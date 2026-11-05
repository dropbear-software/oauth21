import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:oauth21/oauth21.dart';
import 'package:test/test.dart';

class _FakeCryptoService implements CryptoService {
  @override
  String generateRandomEntropyString([int bits = 256]) => 'entropy';

  @override
  String hashString(String input) =>
      sha256.convert(utf8.encode(input)).toString();

  @override
  String hashAndBase64UrlEncode(String input) =>
      base64Url.encode(sha256.convert(utf8.encode(input)).bytes);

  @override
  bool verifyPasswordHash(String plain, String hashed) =>
      CryptoService.safeEquals(hashString(plain), hashed);
}

class _FakeTokenRepository implements TokenRepository {
  final Map<String, AccessToken> accessTokens = {};

  @override
  Future<AccessToken?> findAccessTokenByHash(String hashedValue) async =>
      accessTokens[hashedValue];

  @override
  Future<void> saveAccessToken(AccessToken token) async {
    accessTokens[token.tokenHash] = token;
  }

  @override
  Future<RefreshToken?> findRefreshTokenByHash(String hashedValue) async =>
      null;

  @override
  Future<void> revokeAllTokensForClientAndUser(
    String clientId,
    String? userId,
  ) async {}

  @override
  Future<void> revokeByAuthorizationCode(String authorizationCode) async {}

  @override
  Future<void> revokeRefreshTokenByHash(String hashedValue) async {}

  @override
  Future<bool> rotateRefreshToken({
    required String oldTokenHash,
    required AccessToken newAccessToken,
    required RefreshToken newRefreshToken,
    Duration graceWindow = const Duration(seconds: 30),
  }) async => false;

  @override
  Future<bool> saveIssuedTokens({
    required AccessToken accessToken,
    RefreshToken? refreshToken,
  }) async => true;

  @override
  Future<void> saveRefreshToken(RefreshToken token) async {}
}

void main() {
  group('BearerTokenValidator (#9)', () {
    late _FakeCryptoService crypto;
    late _FakeTokenRepository tokenRepo;
    late BearerTokenValidator validator;
    const validRawToken = 'valid-token-68_abc.123~xyz+/=';

    setUp(() async {
      crypto = _FakeCryptoService();
      tokenRepo = _FakeTokenRepository();
      validator = BearerTokenValidator(
        tokenRepository: tokenRepo,
        cryptoService: crypto,
      );

      await tokenRepo.saveAccessToken(
        AccessToken(
          tokenHash: crypto.hashString(validRawToken),
          clientId: 'client-1',
          userId: 'user-1',
          scope: 'read write',
          expiresAt: DateTime.now().add(const Duration(hours: 1)),
        ),
      );
    });

    test('should reject non-HTTPS requests with 400 invalid_request', () async {
      final res = await validator.validate(
        authorizationHeader: 'Bearer $validRawToken',
      );
      expect(res, isA<BearerTokenInvalid>());
      final invalid = res as BearerTokenInvalid;
      expect(invalid.statusCode, equals(400));
      expect(invalid.errorCode, equals('invalid_request'));
    });

    test(
      'should return 401 with bare WWW-Authenticate: Bearer and no error code '
      'when Authorization header is missing, empty, or non-Bearer '
      '(Section 5.3.1)',
      () async {
        for (final header in [null, '', '   ', 'Basic dXNlcjpwYXNz']) {
          final res = await validator.validate(
            authorizationHeader: header,
            isHttps: true,
          );
          expect(res, isA<BearerTokenInvalid>());
          final invalid = res as BearerTokenInvalid;
          expect(invalid.statusCode, equals(401));
          expect(invalid.errorCode, isNull);
          expect(invalid.headers['WWW-Authenticate'], equals('Bearer'));
        }
      },
    );

    test('should include custom realm in WWW-Authenticate header and validate '
        'realm NQSCHAR ABNF', () async {
      final realmValidator = BearerTokenValidator(
        tokenRepository: tokenRepo,
        cryptoService: crypto,
        realm: 'api.example.com',
      );
      final res = await realmValidator.validate(isHttps: true);
      expect(res, isA<BearerTokenInvalid>());
      final invalid = res as BearerTokenInvalid;
      expect(invalid.statusCode, equals(401));
      expect(
        invalid.headers['WWW-Authenticate'],
        equals('Bearer realm="api.example.com"'),
      );

      expect(
        () => BearerTokenValidator(
          tokenRepository: tokenRepo,
          cryptoService: crypto,
          realm: 'bad"realm',
        ),
        throwsArgumentError,
      );
    });

    test(
      'should reject multiple Authorization headers with 400 invalid_request',
      () async {
        final res = await validator.validate(
          authorizationHeaders: [
            'Bearer $validRawToken',
            'Bearer $validRawToken',
          ],
          isHttps: true,
        );
        expect(res, isA<BearerTokenInvalid>());
        final invalid = res as BearerTokenInvalid;
        expect(invalid.statusCode, equals(400));
        expect(invalid.errorCode, equals('invalid_request'));
        expect(
          invalid.headers['WWW-Authenticate'],
          contains('error="invalid_request"'),
        );
      },
    );

    test(
      'should return 401 invalid_token on empty or malformed token68 syntax',
      () async {
        for (final badHeader in [
          'Bearer',
          'Bearer   ',
          'Bearer bad token with spaces',
          'Bearer bad"quote',
        ]) {
          final res = await validator.validate(
            authorizationHeader: badHeader,
            isHttps: true,
          );
          expect(res, isA<BearerTokenInvalid>());
          final invalid = res as BearerTokenInvalid;
          expect(invalid.statusCode, equals(401));
          expect(invalid.errorCode, equals('invalid_token'));
          expect(
            invalid.headers['WWW-Authenticate'],
            contains('error="invalid_token"'),
          );
        }
      },
    );

    test(
      'should return 401 invalid_token for unknown, expired, or revoked tokens',
      () async {
        final resUnknown = await validator.validate(
          authorizationHeader: 'Bearer unknown-token',
          isHttps: true,
        );
        expect(resUnknown, isA<BearerTokenInvalid>());
        final invalidUnknown = resUnknown as BearerTokenInvalid;
        expect(invalidUnknown.statusCode, equals(401));
        expect(invalidUnknown.errorCode, equals('invalid_token'));

        await tokenRepo.saveAccessToken(
          AccessToken(
            tokenHash: crypto.hashString('expired-token'),
            clientId: 'client-1',
            expiresAt: DateTime.now().subtract(const Duration(minutes: 1)),
          ),
        );
        final resExpired = await validator.validate(
          authorizationHeader: 'Bearer expired-token',
          isHttps: true,
        );
        expect(resExpired, isA<BearerTokenInvalid>());
        final invalidExpired = resExpired as BearerTokenInvalid;
        expect(invalidExpired.statusCode, equals(401));
        expect(invalidExpired.errorCode, equals('invalid_token'));

        await tokenRepo.saveAccessToken(
          AccessToken(
            tokenHash: crypto.hashString('revoked-token'),
            clientId: 'client-1',
            expiresAt: DateTime.now().add(const Duration(minutes: 10)),
            isRevoked: true,
          ),
        );
        final resRevoked = await validator.validate(
          authorizationHeader: 'Bearer revoked-token',
          isHttps: true,
        );
        expect(resRevoked, isA<BearerTokenInvalid>());
        final invalidRevoked = resRevoked as BearerTokenInvalid;
        expect(invalidRevoked.statusCode, equals(401));
        expect(invalidRevoked.errorCode, equals('invalid_token'));
      },
    );

    test('should return 403 insufficient_scope when requiredScopes are not '
        'satisfied', () async {
      final res = await validator.validate(
        authorizationHeader: 'Bearer $validRawToken',
        requiredScopes: {'read', 'admin'},
        isHttps: true,
      );
      expect(res, isA<BearerTokenInvalid>());
      final invalid = res as BearerTokenInvalid;
      expect(invalid.statusCode, equals(403));
      expect(invalid.errorCode, equals('insufficient_scope'));
      expect(
        invalid.headers['WWW-Authenticate'],
        contains('error="insufficient_scope"'),
      );
      expect(
        invalid.headers['WWW-Authenticate'],
        contains('scope="read admin"'),
      );
    });

    test('should succeed with 200 and return AccessToken when token and scopes '
        'are valid (case-insensitive bearer prefix)', () async {
      final res = await validator.validate(
        authorizationHeader: 'bearer $validRawToken',
        requiredScopes: {'read', 'write'},
        isHttps: true,
      );
      expect(res, isA<BearerTokenValid>());
      final valid = res as BearerTokenValid;
      expect(valid.accessToken.clientId, equals('client-1'));
      expect(valid.accessToken.userId, equals('user-1'));
    });
  });
}
