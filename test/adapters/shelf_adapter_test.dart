import 'dart:async';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:oauth21/oauth21.dart';
import 'package:shelf/shelf.dart' as shelf;
import 'package:test/test.dart';

// Minimal fakes needed for testing shelf_adapter

class FakeCryptoService implements CryptoService {
  @override
  String generateRandomEntropyString([int bits = 256]) {
    return 'fake-entropy-123456';
  }

  @override
  String hashString(String input) {
    return sha256.convert(utf8.encode(input)).toString();
  }

  @override
  String hashAndBase64UrlEncode(String input) {
    final digest = sha256.convert(utf8.encode(input));
    return base64Url.encode(digest.bytes).replaceAll('=', '');
  }

  @override
  bool verifyPasswordHash(String plain, String hashed) {
    return CryptoService.safeEquals(hashString(plain), hashed);
  }
}

class FakeClientRepository implements ClientRepository {
  final Map<String, ClientRegistration> clients = {};

  @override
  Future<ClientRegistration?> findById(String clientId) async {
    return clients[clientId];
  }
}

class FakeAuthCodeRepository implements AuthCodeRepository {
  final Map<String, AuthCode> codes = {};

  @override
  Future<void> save(AuthCode authCode) async {
    codes[authCode.code] = authCode;
  }

  @override
  Future<AuthCode?> findByCode(String code) async {
    return codes[code];
  }

  @override
  Future<bool> tryConsume(String code) async {
    final authCode = codes[code];
    if (authCode == null || authCode.isUsed || authCode.isExpired) {
      return false;
    }
    codes[code] = authCode.copyWith(isUsed: true);
    return true;
  }
}

class FakeTokenRepository implements TokenRepository {
  final Map<String, AccessToken> accessTokens = {};

  @override
  Future<void> saveAccessToken(AccessToken token) async {
    accessTokens[token.tokenHash] = token;
  }

  @override
  Future<void> saveRefreshToken(RefreshToken token) async {}

  @override
  Future<bool> saveIssuedTokens({
    required AccessToken accessToken,
    RefreshToken? refreshToken,
  }) async {
    accessTokens[accessToken.tokenHash] = accessToken;
    return true;
  }

  @override
  Future<bool> rotateRefreshToken({
    required String oldTokenHash,
    required AccessToken newAccessToken,
    required RefreshToken newRefreshToken,
    Duration graceWindow = const Duration(seconds: 30),
  }) async {
    return true;
  }

  @override
  Future<void> revokeByAuthorizationCode(String authorizationCode) async {}

  @override
  Future<AccessToken?> findAccessTokenByHash(String hashedValue) async {
    return accessTokens[hashedValue];
  }

  @override
  Future<RefreshToken?> findRefreshTokenByHash(String hashedValue) async {
    return null;
  }

  @override
  Future<void> revokeRefreshTokenByHash(String hashedValue) async {}

  @override
  Future<void> revokeAllTokensForClientAndUser(
    String clientId,
    String? userId,
  ) async {}
}

void main() {
  group('shelf_adapter', () {
    late FakeCryptoService cryptoService;
    late FakeClientRepository clientRepo;
    late FakeAuthCodeRepository authCodeRepo;
    late FakeTokenRepository tokenRepo;

    late AuthorizeRequestValidator authValidator;
    late TokenRequestHandler tokenHandler;

    late ClientRegistration confidentialClient;

    setUp(() {
      cryptoService = FakeCryptoService();
      clientRepo = FakeClientRepository();
      authCodeRepo = FakeAuthCodeRepository();
      tokenRepo = FakeTokenRepository();

      authValidator = AuthorizeRequestValidator(clientRepo);
      tokenHandler = TokenRequestHandler(
        clientRepository: clientRepo,
        authCodeRepository: authCodeRepo,
        tokenRepository: tokenRepo,
        cryptoService: cryptoService,
      );

      confidentialClient = ClientRegistration(
        clientId: 'client-123',
        clientType: ClientType.confidential,
        clientSecretHash: cryptoService.hashString('secret-123'),
        redirectUris: {Uri.parse('https://example.com/cb')},
        allowedScopes: {'read', 'write'},
        allowedGrantTypes: {
          'authorization_code',
          'client_credentials',
          'refresh_token',
        },
      );
      clientRepo.clients[confidentialClient.clientId] = confidentialClient;
    });

    group('handleAuthorizeRequest', () {
      test('should call onConsentRequired on valid request', () async {
        final req = shelf.Request(
          'GET',
          Uri.parse(
            'https://auth.example.com/authorize?'
            'response_type=code&'
            'client_id=client-123&'
            'redirect_uri=https%3A%2F%2Fexample.com%2Fcb&'
            'code_challenge='
            'xyz-challenge-string-1234567890-challenge-extra-long&'
            'code_challenge_method=S256&'
            'state=state123',
          ),
        );

        var consentCalled = false;
        final res = await handleAuthorizeRequest(
          req,
          validator: authValidator,
          issuer: 'https://auth.example.com',
          onConsentRequired: (request, result) {
            consentCalled = true;
            expect(result.client.clientId, equals('client-123'));
            return Future.value(shelf.Response.ok('consent needed'));
          },
        );

        expect(consentCalled, isTrue);
        expect(res.statusCode, equals(200));
        expect(await res.readAsString(), equals('consent needed'));
      });

      test(
        'should return 405 Method Not Allowed on non-GET request (#12)',
        () async {
          final req = shelf.Request(
            'POST',
            Uri.parse('https://auth.example.com/authorize'),
          );

          final res = await handleAuthorizeRequest(
            req,
            validator: authValidator,
            issuer: 'https://auth.example.com',
            onConsentRequired: (request, result) {
              fail('Should not be called');
            },
          );

          expect(res.statusCode, equals(405));
          expect(res.headers['allow'], equals('GET'));
          expect(res.headers['cache-control'], equals('no-store'));
        },
      );

      test('should return 400 JSON on non-redirectable error', () async {
        final req = shelf.Request(
          'GET',
          Uri.parse(
            'https://auth.example.com/authorize?'
            'response_type=code&'
            'client_id=unknown-client', // unregistered client
          ),
        );

        final res = await handleAuthorizeRequest(
          req,
          validator: authValidator,
          issuer: 'https://auth.example.com',
          onConsentRequired: (request, result) {
            fail('Should not be called');
          },
        );

        expect(res.statusCode, equals(400));
        expect(res.headers['content-type'], contains('application/json'));
        final body =
            jsonDecode(await res.readAsString()) as Map<String, dynamic>;
        expect(body['error'], equals('invalid_client'));
      });

      test(
        'should return 303 redirect with mandatory iss on redirectable error '
        '(#12)',
        () async {
          final req = shelf.Request(
            'GET',
            Uri.parse(
              'https://auth.example.com/authorize?'
              'response_type=code&'
              'client_id=client-123&'
              'redirect_uri=https%3A%2F%2Fexample.com%2Fcb&'
              // missing code_challenge (redirectable error)
              'state=state123',
            ),
          );

          final res = await handleAuthorizeRequest(
            req,
            validator: authValidator,
            issuer: 'https://auth.example.com',
            onConsentRequired: (request, result) {
              fail('Should not be called');
            },
          );

          expect(res.statusCode, equals(303));
          final location = res.headers['location'];
          expect(location, isNotNull);
          final redirectUri = Uri.parse(location!);
          expect(
            redirectUri.queryParameters['error'],
            equals('invalid_request'),
          );
          expect(
            redirectUri.queryParameters['error_description'],
            contains('code_challenge'),
          );
          expect(redirectUri.queryParameters['state'], equals('state123'));
          expect(
            redirectUri.queryParameters['iss'],
            equals('https://auth.example.com'),
          );
        },
      );
    });

    group('redirectWithAuthorizationCode & redirectWithAuthorizationError', () {
      test('should build 303 redirect with code, state, and iss', () {
        final res = redirectWithAuthorizationCode(
          redirectUri: Uri.parse('https://example.com/cb?existing=1'),
          code: 'auth-code-123',
          state: 'state-xyz',
          issuer: 'https://auth.example.com',
        );

        expect(res.statusCode, equals(303));
        final location = res.headers['location'];
        expect(location, isNotNull);

        final parsed = Uri.parse(location!);
        expect(parsed.scheme, equals('https'));
        expect(parsed.host, equals('example.com'));
        expect(parsed.path, equals('/cb'));
        expect(parsed.queryParameters['existing'], equals('1'));
        expect(parsed.queryParameters['code'], equals('auth-code-123'));
        expect(parsed.queryParameters['state'], equals('state-xyz'));
        expect(
          parsed.queryParameters['iss'],
          equals('https://auth.example.com'),
        );
      });

      test('should omit state when state is null in '
          'redirectWithAuthorizationCode (#5)', () {
        final res = redirectWithAuthorizationCode(
          redirectUri: Uri.parse('https://example.com/cb'),
          code: 'auth-code-123',
          issuer: 'https://auth.example.com',
        );

        final parsed = Uri.parse(res.headers['location']!);
        expect(parsed.queryParameters['code'], equals('auth-code-123'));
        expect(parsed.queryParameters.containsKey('state'), isFalse);
        expect(
          parsed.queryParameters['iss'],
          equals('https://auth.example.com'),
        );
      });

      test('should build 303 error redirect with mandatory iss in '
          'redirectWithAuthorizationError (#12)', () {
        final res = redirectWithAuthorizationError(
          redirectUri: Uri.parse('https://example.com/cb'),
          error: 'access_denied',
          errorDescription: 'User denied access.',
          issuer: 'https://auth.example.com',
        );

        expect(res.statusCode, equals(303));
        final parsed = Uri.parse(res.headers['location']!);
        expect(parsed.queryParameters['error'], equals('access_denied'));
        expect(
          parsed.queryParameters['error_description'],
          equals('User denied access.'),
        );
        expect(parsed.queryParameters.containsKey('state'), isFalse);
        expect(
          parsed.queryParameters['iss'],
          equals('https://auth.example.com'),
        );
      });
    });

    group('handleTokenRequest', () {
      test(
        'should reject request when isHttps is omitted (defaults to false)',
        () async {
          final req = shelf.Request(
            'POST',
            Uri.parse('https://auth.example.com/token'),
            headers: {'content-type': 'application/x-www-form-urlencoded'},
            body:
                'grant_type=client_credentials&client_id=client-123'
                '&client_secret=secret-123',
          );

          final res = await handleTokenRequest(req, handler: tokenHandler);
          expect(res.statusCode, equals(400));
          expect(res.headers['cache-control'], equals('no-store'));
          expect(res.headers['pragma'], equals('no-cache'));
        },
      );

      test('should reject non-POST request with no-store headers', () async {
        final req = shelf.Request(
          'GET',
          Uri.parse('https://auth.example.com/token'),
        );

        final res = await handleTokenRequest(
          req,
          handler: tokenHandler,
          isHttps: true,
        );

        expect(res.statusCode, equals(400));
        expect(res.headers['cache-control'], equals('no-store'));
        expect(res.headers['pragma'], equals('no-cache'));
        final body =
            jsonDecode(await res.readAsString()) as Map<String, dynamic>;
        expect(body['error'], equals('invalid_request'));
      });

      test('should reject non-urlencoded Content-Type', () async {
        final req = shelf.Request(
          'POST',
          Uri.parse('https://auth.example.com/token'),
          headers: {'content-type': 'application/json'},
          body: jsonEncode({'grant_type': 'client_credentials'}),
        );

        final res = await handleTokenRequest(
          req,
          handler: tokenHandler,
          isHttps: true,
        );

        expect(res.statusCode, equals(400));
        expect(res.headers['cache-control'], equals('no-store'));
        expect(res.headers['pragma'], equals('no-cache'));
        final body =
            jsonDecode(await res.readAsString()) as Map<String, dynamic>;
        expect(body['error'], equals('invalid_request'));
      });

      test('should successfully execute client credentials exchange', () async {
        final req = shelf.Request(
          'POST',
          Uri.parse('https://auth.example.com/token'),
          headers: {'content-type': 'application/x-www-form-urlencoded'},
          body:
              'grant_type=client_credentials&'
              'client_id=client-123&'
              'client_secret=secret-123&'
              'scope=read',
        );

        final res = await handleTokenRequest(
          req,
          handler: tokenHandler,
          isHttps: true,
        );

        expect(res.statusCode, equals(200));
        expect(res.headers['cache-control'], equals('no-store'));
        expect(res.headers['pragma'], equals('no-cache'));

        final body =
            jsonDecode(await res.readAsString()) as Map<String, dynamic>;
        expect(body['access_token'], equals('fake-entropy-123456'));
        expect(body['token_type'], equals('Bearer'));
        expect(body['expires_in'], equals(3600));
        expect(body['scope'], equals('read'));
      });

      test('should propagate token handler errors correctly', () async {
        final req = shelf.Request(
          'POST',
          Uri.parse('https://auth.example.com/token'),
          headers: {'content-type': 'application/x-www-form-urlencoded'},
          body:
              'grant_type=client_credentials&'
              'client_id=client-123&'
              'client_secret=wrong-secret',
        );

        final res = await handleTokenRequest(
          req,
          handler: tokenHandler,
          isHttps: true,
        );

        expect(res.statusCode, equals(401));
        final body =
            jsonDecode(await res.readAsString()) as Map<String, dynamic>;
        expect(body['error'], equals('invalid_client'));
      });

      test('should reject token request body containing parameter '
          'pollution / duplicate keys with no-store headers', () async {
        final req = shelf.Request(
          'POST',
          Uri.parse('https://auth.example.com/token'),
          headers: {'content-type': 'application/x-www-form-urlencoded'},
          body:
              'grant_type=client_credentials&client_id=client-123&'
              'grant_type=authorization_code',
        );

        final res = await handleTokenRequest(
          req,
          handler: tokenHandler,
          isHttps: true,
        );
        expect(res.statusCode, equals(400));
        expect(res.headers['cache-control'], equals('no-store'));
        expect(res.headers['pragma'], equals('no-cache'));

        final json =
            jsonDecode(await res.readAsString()) as Map<String, dynamic>;
        expect(json['error'], equals('invalid_request'));
        expect(json['error_description'], contains('Duplicate parameters'));
      });

      test('should reject token request if payload size exceeds safe '
          'memory boundaries', () async {
        final hugeJunkPayload =
            'grant_type=client_credentials&data=${'A' * 15000}';
        final req = shelf.Request(
          'POST',
          Uri.parse('https://auth.example.com/token'),
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            'content-length': hugeJunkPayload.length.toString(),
          },
          body: hugeJunkPayload,
        );

        final res = await handleTokenRequest(
          req,
          handler: tokenHandler,
          isHttps: true,
        );
        expect(res.statusCode, equals(400));
        expect(res.headers['cache-control'], equals('no-store'));
        expect(res.headers['pragma'], equals('no-cache'));

        final json =
            jsonDecode(await res.readAsString()) as Map<String, dynamic>;
        expect(json['error'], equals('invalid_request'));
        expect(json['error_description'], contains('Payload too large'));
      });

      test('should abort chunked stream payload mid-stream if size exceeds '
          '10,240 bytes', () async {
        var thirdChunkRead = false;
        Stream<List<int>> chunkedStream() async* {
          yield List<int>.filled(6000, 65);
          yield List<int>.filled(6000, 65); // Exceeds 10,240 bytes here
          thirdChunkRead = true;
          yield List<int>.filled(6000, 65);
        }

        final req = shelf.Request(
          'POST',
          Uri.parse('https://auth.example.com/token'),
          headers: {'content-type': 'application/x-www-form-urlencoded'},
          body: chunkedStream(),
        );

        final res = await handleTokenRequest(
          req,
          handler: tokenHandler,
          isHttps: true,
        );
        expect(res.statusCode, equals(400));
        expect(thirdChunkRead, isFalse);
        expect(res.headers['cache-control'], equals('no-store'));
        expect(res.headers['pragma'], equals('no-cache'));

        final json =
            jsonDecode(await res.readAsString()) as Map<String, dynamic>;
        expect(json['error'], equals('invalid_request'));
        expect(json['error_description'], contains('Payload too large'));
      });

      test('should reject malformed Content-Length, invalid UTF-8 bytes, and '
          'malformed percent-encoding without throwing 500', () async {
        final badContentLengthReq = shelf.Request(
          'POST',
          Uri.parse('https://auth.example.com/token'),
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            'content-length': '-5',
          },
          body: 'grant_type=client_credentials',
        );
        final resBadLen = await handleTokenRequest(
          badContentLengthReq,
          handler: tokenHandler,
          isHttps: true,
        );
        expect(resBadLen.statusCode, equals(400));

        final invalidUtf8Req = shelf.Request(
          'POST',
          Uri.parse('https://auth.example.com/token'),
          headers: {'content-type': 'application/x-www-form-urlencoded'},
          body: Stream.value(<int>[0xFF, 0xFE, 0xFD]),
        );
        final resInvalidUtf8 = await handleTokenRequest(
          invalidUtf8Req,
          handler: tokenHandler,
          isHttps: true,
        );
        expect(resInvalidUtf8.statusCode, equals(400));

        final badPercentReq = shelf.Request(
          'POST',
          Uri.parse('https://auth.example.com/token'),
          headers: {'content-type': 'application/x-www-form-urlencoded'},
          body: 'grant_type=%ZZ&client_id=client-123',
        );
        final resBadPercent = await handleTokenRequest(
          badPercentReq,
          handler: tokenHandler,
          isHttps: true,
        );
        expect(resBadPercent.statusCode, equals(400));
      });

      test('should handle url-encoded parameter without equals sign', () async {
        final req = shelf.Request(
          'POST',
          Uri.parse('https://auth.example.com/token'),
          headers: {'content-type': 'application/x-www-form-urlencoded'},
          body: 'grant_type=client_credentials&client_id=client-123&nopair',
        );

        final res = await handleTokenRequest(
          req,
          handler: tokenHandler,
          isHttps: true,
        );
        expect(res.statusCode, isNot(equals(500)));
      });
    });

    group('bearerAuthenticationMiddleware (#9)', () {
      late BearerTokenValidator bearerValidator;
      const rawToken = 'valid-bearer-token-123';

      setUp(() async {
        bearerValidator = BearerTokenValidator(
          tokenRepository: tokenRepo,
          cryptoService: cryptoService,
          realm: 'resource.example.com',
        );
        await tokenRepo.saveAccessToken(
          AccessToken(
            tokenHash: cryptoService.hashString(rawToken),
            clientId: 'client-123',
            userId: 'user-789',
            scope: 'read write',
            expiresAt: DateTime.now().add(const Duration(hours: 1)),
          ),
        );
      });

      test('should attach AccessToken to request context and preserve request '
          'body stream for downstream POST handlers', () async {
        final handler = const shelf.Pipeline()
            .addMiddleware(
              bearerAuthenticationMiddleware(
                validator: bearerValidator,
                requiredScopes: {'read'},
                isHttps: true,
              ),
            )
            .addHandler((req) async {
              final token = getAccessTokenFromContext(req);
              final payload = await req.readAsString();
              return shelf.Response.ok(
                jsonEncode({
                  'user': token?.userId,
                  'client': token?.clientId,
                  'payload': payload,
                }),
              );
            });

        final req = shelf.Request(
          'POST',
          Uri.parse('https://resource.example.com/items'),
          headers: {'Authorization': 'Bearer $rawToken'},
          body: '{"name":"widget"}',
        );

        final res = await handler(req);
        expect(res.statusCode, equals(200));
        final body =
            jsonDecode(await res.readAsString()) as Map<String, dynamic>;
        expect(body['user'], equals('user-789'));
        expect(body['client'], equals('client-123'));
        expect(body['payload'], equals('{"name":"widget"}'));
      });

      test(
        'should ignore ?access_token=... in URI query parameters and return '
        '401 with bare WWW-Authenticate when Authorization header is absent',
        () async {
          final handler = const shelf.Pipeline()
              .addMiddleware(
                bearerAuthenticationMiddleware(
                  validator: bearerValidator,
                  isHttps: true,
                ),
              )
              .addHandler((_) => shelf.Response.ok('secret'));

          final req = shelf.Request(
            'GET',
            Uri.parse(
              'https://resource.example.com/items?access_token=$rawToken',
            ),
          );

          final res = await handler(req);
          expect(res.statusCode, equals(401));
          expect(
            res.headers['www-authenticate'],
            equals('Bearer realm="resource.example.com"'),
          );
          expect(await res.readAsString(), isEmpty);
        },
      );

      test('should return 403 insufficient_scope with JSON error body when '
          'requiredScopes are not met', () async {
        final handler = const shelf.Pipeline()
            .addMiddleware(
              bearerAuthenticationMiddleware(
                validator: bearerValidator,
                requiredScopes: {'admin'},
                isHttps: true,
              ),
            )
            .addHandler((_) => shelf.Response.ok('secret'));

        final req = shelf.Request(
          'GET',
          Uri.parse('https://resource.example.com/admin'),
          headers: {'Authorization': 'Bearer $rawToken'},
        );

        final res = await handler(req);
        expect(res.statusCode, equals(403));
        expect(
          res.headers['www-authenticate'],
          contains('error="insufficient_scope"'),
        );
        final body =
            jsonDecode(await res.readAsString()) as Map<String, dynamic>;
        expect(body['error'], equals('insufficient_scope'));
      });
    });
  });
}
