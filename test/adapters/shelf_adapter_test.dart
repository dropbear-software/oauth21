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
  Future<void> markAsUsed(String code) async {
    final authCode = codes[code];
    if (authCode != null) {
      codes[code] = authCode.copyWith(isUsed: true);
    }
  }

  @override
  Future<void> revokeTokensForCode(String code) async {}
}

class FakeTokenRepository implements TokenRepository {
  @override
  Future<void> saveAccessToken(AccessToken token) async {}

  @override
  Future<void> saveRefreshToken(RefreshToken token) async {}

  @override
  Future<AccessToken?> findAccessTokenByHash(String hashedValue) async {
    return null;
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
          onConsentRequired: (request, result) {
            consentCalled = true;
            expect(result.isValid, isTrue);
            expect(result.client?.clientId, equals('client-123'));
            return Future.value(shelf.Response.ok('consent needed'));
          },
        );

        expect(consentCalled, isTrue);
        expect(res.statusCode, equals(200));
        expect(await res.readAsString(), equals('consent needed'));
      });

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

      test('should return 303 redirect on redirectable error', () async {
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
          onConsentRequired: (request, result) {
            fail('Should not be called');
          },
        );

        expect(res.statusCode, equals(303));
        final location = res.headers['location'];
        expect(location, isNotNull);
        final redirectUri = Uri.parse(location!);
        expect(redirectUri.queryParameters['error'], equals('invalid_request'));
        expect(
          redirectUri.queryParameters['error_description'],
          contains('code_challenge'),
        );
        expect(redirectUri.queryParameters['state'], equals('state123'));
      });
    });

    group('redirectWithAuthorizationCode', () {
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
    });

    group('handleTokenRequest', () {
      test('should reject non-POST request', () async {
        final req = shelf.Request(
          'GET',
          Uri.parse('https://auth.example.com/token'),
        );

        final res = await handleTokenRequest(req, handler: tokenHandler);

        expect(res.statusCode, equals(400));
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

        final res = await handleTokenRequest(req, handler: tokenHandler);

        expect(res.statusCode, equals(400));
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

        final res = await handleTokenRequest(req, handler: tokenHandler);

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

        final res = await handleTokenRequest(req, handler: tokenHandler);

        expect(res.statusCode, equals(401));
        final body =
            jsonDecode(await res.readAsString()) as Map<String, dynamic>;
        expect(body['error'], equals('invalid_client'));
      });

      test('should reject token request body containing parameter '
          'pollution / duplicate keys', () async {
        final req = shelf.Request(
          'POST',
          Uri.parse('https://auth.example.com/token'),
          headers: {'content-type': 'application/x-www-form-urlencoded'},
          body:
              'grant_type=client_credentials&client_id=client-123&'
              'grant_type=authorization_code',
        );

        final res = await handleTokenRequest(req, handler: tokenHandler);
        expect(res.statusCode, equals(400));

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

        final res = await handleTokenRequest(req, handler: tokenHandler);
        expect(res.statusCode, equals(400));

        final json =
            jsonDecode(await res.readAsString()) as Map<String, dynamic>;
        expect(json['error'], equals('invalid_request'));
        expect(json['error_description'], contains('Payload too large'));
      });

      test(
        'should reject stream payload if size exceeds safe limits',
        () async {
          final hugeJunkPayload =
              'grant_type=client_credentials&data=${'A' * 15000}';
          final req = shelf.Request(
            'POST',
            Uri.parse('https://auth.example.com/token'),
            headers: {'content-type': 'application/x-www-form-urlencoded'},
            body: Stream.value(utf8.encode(hugeJunkPayload)),
          );

          final res = await handleTokenRequest(req, handler: tokenHandler);
          expect(res.statusCode, equals(400));

          final json =
              jsonDecode(await res.readAsString()) as Map<String, dynamic>;
          expect(json['error'], equals('invalid_request'));
          expect(json['error_description'], contains('Payload too large'));
        },
      );

      test('should handle url-encoded parameter without equals sign', () async {
        final req = shelf.Request(
          'POST',
          Uri.parse('https://auth.example.com/token'),
          headers: {'content-type': 'application/x-www-form-urlencoded'},
          body: 'grant_type=client_credentials&client_id=client-123&nopair',
        );

        final res = await handleTokenRequest(req, handler: tokenHandler);
        expect(res.statusCode, isNot(equals(500)));
      });
    });
  });
}
