import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:oauth21/oauth21.dart';
import 'package:test/test.dart';

class FakeCryptoService implements CryptoService {
  @override
  String generateRandomEntropyString([int bits = 256]) {
    return 'random-entropy-string-1234567890';
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
  bool revokeCalled = false;
  String? revokedCode;

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
  Future<void> revokeTokensForCode(String code) async {
    revokeCalled = true;
    revokedCode = code;
  }
}

class FakeTokenRepository implements TokenRepository {
  final Map<String, AccessToken> accessTokens = {};
  final Map<String, RefreshToken> refreshTokens = {};
  bool revokeAllCalled = false;
  String? revokedClientId;
  String? revokedUserId;

  @override
  Future<void> saveAccessToken(AccessToken token) async {
    accessTokens[token.tokenHash] = token;
  }

  @override
  Future<void> saveRefreshToken(RefreshToken token) async {
    refreshTokens[token.tokenHash] = token;
  }

  @override
  Future<AccessToken?> findAccessTokenByHash(String hashedValue) async {
    return accessTokens[hashedValue];
  }

  @override
  Future<RefreshToken?> findRefreshTokenByHash(String hashedValue) async {
    return refreshTokens[hashedValue];
  }

  @override
  Future<void> revokeRefreshTokenByHash(String hashedValue) async {
    final token = refreshTokens[hashedValue];
    if (token != null) {
      refreshTokens[hashedValue] = token.copyWith(
        isRevoked: true,
        revokedAt: DateTime.now(),
      );
    }
  }

  @override
  Future<void> revokeAllTokensForClientAndUser(
    String clientId,
    String? userId,
  ) async {
    revokeAllCalled = true;
    revokedClientId = clientId;
    revokedUserId = userId;

    accessTokens.updateAll((hash, t) {
      if (t.clientId == clientId && t.userId == userId) {
        return t.copyWith(isRevoked: true);
      }
      return t;
    });

    refreshTokens.updateAll((hash, t) {
      if (t.clientId == clientId && t.userId == userId) {
        return t.copyWith(isRevoked: true);
      }
      return t;
    });
  }
}

void main() {
  group('TokenRequestHandler', () {
    late FakeCryptoService cryptoService;
    late FakeClientRepository clientRepo;
    late FakeAuthCodeRepository authCodeRepo;
    late FakeTokenRepository tokenRepo;
    late TokenRequestHandler handler;

    late ClientRegistration confidentialClient;
    late ClientRegistration publicClient;

    setUp(() {
      cryptoService = FakeCryptoService();
      clientRepo = FakeClientRepository();
      authCodeRepo = FakeAuthCodeRepository();
      tokenRepo = FakeTokenRepository();

      handler = TokenRequestHandler(
        clientRepository: clientRepo,
        authCodeRepository: authCodeRepo,
        tokenRepository: tokenRepo,
        cryptoService: cryptoService,
      );

      confidentialClient = ClientRegistration(
        clientId: 'client-confidential',
        clientType: ClientType.confidential,
        clientSecretHash: cryptoService.hashString('secret123'),
        redirectUris: {Uri.parse('https://example.com/cb')},
        allowedScopes: {'read', 'write'},
        allowedGrantTypes: {
          'authorization_code',
          'client_credentials',
          'refresh_token',
        },
      );

      publicClient = ClientRegistration(
        clientId: 'client-public',
        clientType: ClientType.public,
        redirectUris: {Uri.parse('https://example.com/cb')},
        allowedScopes: {'read'},
        allowedGrantTypes: {'authorization_code', 'refresh_token'},
      );

      clientRepo.clients[confidentialClient.clientId] = confidentialClient;
      clientRepo.clients[publicClient.clientId] = publicClient;
    });

    group('Transport Security & Authentication', () {
      test('should reject non-HTTPS request', () async {
        final res = await handler.handle({
          'grant_type': 'client_credentials',
        }, isHttps: false);
        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('invalid_request'));
      });

      test('should authenticate via Basic Auth header', () async {
        final authHeader =
            'Basic ${base64.encode(utf8.encode('client-confidential:secret123'))}';
        final res = await handler.handle({
          'grant_type': 'client_credentials',
        }, authorizationHeader: authHeader);
        expect(res.statusCode, equals(200));
      });

      test('should fail on malformed Basic Auth header', () async {
        final res = await handler.handle({
          'grant_type': 'client_credentials',
        }, authorizationHeader: 'Basic invalid-base64');
        expect(res.statusCode, equals(401));
        expect(res.body['error'], equals('invalid_client'));
      });

      test('should authenticate via request body credentials', () async {
        final res = await handler.handle({
          'grant_type': 'client_credentials',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
        });
        expect(res.statusCode, equals(200));
      });

      test('should reject multiple authentication methods', () async {
        final authHeader =
            'Basic ${base64.encode(utf8.encode('client-confidential:secret123'))}';
        final res = await handler.handle({
          'grant_type': 'client_credentials',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
        }, authorizationHeader: authHeader);
        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('invalid_request'));
      });

      test('should reject request missing client_id', () async {
        final res = await handler.handle({'grant_type': 'client_credentials'});
        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('invalid_request'));
      });

      test('should reject non-existent client', () async {
        final res = await handler.handle({
          'grant_type': 'client_credentials',
          'client_id': 'client-unknown',
          'client_secret': 'secret',
        });
        expect(res.statusCode, equals(401));
        expect(res.body['error'], equals('invalid_client'));
      });

      test('should reject missing secret for confidential client', () async {
        final res = await handler.handle({
          'grant_type': 'client_credentials',
          'client_id': 'client-confidential',
        });
        expect(res.statusCode, equals(401));
        expect(res.body['error'], equals('invalid_client'));
      });

      test('should reject invalid secret for confidential client', () async {
        final res = await handler.handle({
          'grant_type': 'client_credentials',
          'client_id': 'client-confidential',
          'client_secret': 'wrong-secret',
        });
        expect(res.statusCode, equals(401));
        expect(res.body['error'], equals('invalid_client'));
      });

      test('should reject public client providing a secret', () async {
        final res = await handler.handle({
          'grant_type': 'authorization_code',
          'client_id': 'client-public',
          'client_secret': 'secret',
        });
        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('invalid_request'));
      });

      test('should reject missing grant_type parameter', () async {
        final res = await handler.handle({'client_id': 'client-public'});
        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('invalid_request'));
      });

      test('should reject disallowed grant type', () async {
        final res = await handler.handle({
          'grant_type': 'client_credentials',
          'client_id': 'client-public',
        });
        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('unauthorized_client'));
      });
    });

    group('Authorization Code Grant', () {
      late AuthCode activeCode;
      late String verifier;

      setUp(() async {
        verifier = 'verifier-string-1234567890-verifier-string-1234567890';
        final challenge = cryptoService.hashAndBase64UrlEncode(verifier);

        activeCode = AuthCode(
          code: 'valid-auth-code',
          clientId: 'client-confidential',
          redirectUri: Uri.parse('https://example.com/cb'),
          userId: 'user-123',
          codeChallenge: challenge,
          codeChallengeMethod: 'S256',
          expiresAt: DateTime.now().add(const Duration(minutes: 5)),
          scope: 'read write',
        );
        await authCodeRepo.save(activeCode);
      });

      test('should issue tokens on valid code and verifier', () async {
        final res = await handler.handle({
          'grant_type': 'authorization_code',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'code': 'valid-auth-code',
          'code_verifier': verifier,
          'redirect_uri': 'https://example.com/cb',
        });

        expect(res.statusCode, equals(200));
        expect(res.body['access_token'], isNotNull);
        expect(res.body['refresh_token'], isNotNull);
        expect(res.body['token_type'], equals('Bearer'));
        expect(res.body['expires_in'], equals(3600));

        final updatedCode = await authCodeRepo.findByCode('valid-auth-code');
        expect(updatedCode?.isUsed, isTrue);
      });

      test('should validate with code_challenge_method plain', () async {
        final plainCode = AuthCode(
          code: 'plain-auth-code',
          clientId: 'client-confidential',
          redirectUri: Uri.parse('https://example.com/cb'),
          userId: 'user-123',
          codeChallenge: verifier,
          codeChallengeMethod: 'plain',
          expiresAt: DateTime.now().add(const Duration(minutes: 5)),
        );
        await authCodeRepo.save(plainCode);

        final res = await handler.handle({
          'grant_type': 'authorization_code',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'code': 'plain-auth-code',
          'code_verifier': verifier,
          'redirect_uri': 'https://example.com/cb',
        });

        expect(res.statusCode, equals(200));
      });

      test('should reject request missing code', () async {
        final res = await handler.handle({
          'grant_type': 'authorization_code',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'code_verifier': verifier,
        });
        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('invalid_request'));
      });

      test('should reject request missing code_verifier', () async {
        final res = await handler.handle({
          'grant_type': 'authorization_code',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'code': 'valid-auth-code',
        });
        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('invalid_request'));
      });

      test('should reject non-existent authorization code', () async {
        final res = await handler.handle({
          'grant_type': 'authorization_code',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'code': 'unknown-code',
          'code_verifier': verifier,
        });
        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('invalid_grant'));
      });

      test(
        'should reject authorization code bound to different client',
        () async {
          final res = await handler.handle({
            'grant_type': 'authorization_code',
            'client_id': 'client-public',
            'code': 'valid-auth-code',
            'code_verifier': verifier,
          });
          expect(res.statusCode, equals(400));
          expect(res.body['error'], equals('invalid_grant'));
        },
      );

      test('should reject request with mismatched redirect_uri', () async {
        final res = await handler.handle({
          'grant_type': 'authorization_code',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'code': 'valid-auth-code',
          'code_verifier': verifier,
          'redirect_uri': 'https://example.com/different',
        });
        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('invalid_grant'));
      });

      test('should reject invalid PKCE verifier', () async {
        final res = await handler.handle({
          'grant_type': 'authorization_code',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'code': 'valid-auth-code',
          'code_verifier': 'wrong-verifier',
        });
        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('invalid_grant'));
      });

      test('should reject expired authorization code', () async {
        final expiredCode = AuthCode(
          code: 'expired-auth-code',
          clientId: 'client-confidential',
          redirectUri: Uri.parse('https://example.com/cb'),
          userId: 'user-123',
          codeChallenge: 'challenge',
          codeChallengeMethod: 'plain',
          expiresAt: DateTime.now().subtract(const Duration(minutes: 5)),
        );
        await authCodeRepo.save(expiredCode);

        final res = await handler.handle({
          'grant_type': 'authorization_code',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'code': 'expired-auth-code',
          'code_verifier': 'challenge',
        });
        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('invalid_grant'));
      });

      test('should reject token request if redirect_uri is omitted but was '
          'bound to the authorization code', () async {
        final res = await handler.handle({
          'grant_type': 'authorization_code',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'code': 'valid-auth-code',
          'code_verifier': verifier,
        });

        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('invalid_grant'));
      });

      test('should detect code reuse and trigger family revocation', () async {
        // Use code first time
        final res1 = await handler.handle({
          'grant_type': 'authorization_code',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'code': 'valid-auth-code',
          'code_verifier': verifier,
          'redirect_uri': 'https://example.com/cb',
        });
        expect(res1.statusCode, equals(200));

        // Use code second time (replay attack)
        final res2 = await handler.handle({
          'grant_type': 'authorization_code',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'code': 'valid-auth-code',
          'code_verifier': verifier,
          'redirect_uri': 'https://example.com/cb',
        });

        expect(res2.statusCode, equals(400));
        expect(res2.body['error'], equals('invalid_grant'));
        expect(authCodeRepo.revokeCalled, isTrue);
        expect(authCodeRepo.revokedCode, equals('valid-auth-code'));
      });

      test(
        'should detect code reuse and trigger family revocation even if expired',
        () async {
          final expiredUsedCode = AuthCode(
            code: 'expired-used-auth-code',
            clientId: 'client-confidential',
            redirectUri: Uri.parse('https://example.com/cb'),
            userId: 'user-123',
            codeChallenge: 'challenge',
            codeChallengeMethod: 'plain',
            expiresAt: DateTime.now().subtract(const Duration(minutes: 5)),
            isUsed: true,
          );
          await authCodeRepo.save(expiredUsedCode);

          final res = await handler.handle({
            'grant_type': 'authorization_code',
            'client_id': 'client-confidential',
            'client_secret': 'secret123',
            'code': 'expired-used-auth-code',
            'code_verifier': 'challenge',
            'redirect_uri': 'https://example.com/cb',
          });

          expect(res.statusCode, equals(400));
          expect(res.body['error'], equals('invalid_grant'));
          expect(authCodeRepo.revokeCalled, isTrue);
          expect(authCodeRepo.revokedCode, equals('expired-used-auth-code'));
        },
      );
    });

    group('Client Credentials Grant', () {
      test('should successfully issue client-scoped access token', () async {
        final res = await handler.handle({
          'grant_type': 'client_credentials',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'scope': 'read',
        });
        expect(res.statusCode, equals(200));
        expect(res.body['access_token'], isNotNull);
        expect(
          res.body['refresh_token'],
          isNull,
        ); // Client credentials does not return refresh token
        expect(res.body['scope'], equals('read'));
      });

      test(
        'should reject client credentials requested scope if not allowed',
        () async {
          final res = await handler.handle({
            'grant_type': 'client_credentials',
            'client_id': 'client-confidential',
            'client_secret': 'secret123',
            'scope': 'read admin',
          });
          expect(res.statusCode, equals(400));
          expect(res.body['error'], equals('invalid_scope'));
        },
      );
    });

    group('Refresh Token Grant', () {
      late RefreshToken activeToken;
      late String rawTokenVal;

      setUp(() async {
        rawTokenVal = 'refresh-token-val-12345';
        final hash = cryptoService.hashString(rawTokenVal);

        activeToken = RefreshToken(
          tokenHash: hash,
          clientId: 'client-confidential',
          expiresAt: DateTime.now().add(const Duration(days: 30)),
          userId: 'user-456',
          scope: 'read write',
        );
        await tokenRepo.saveRefreshToken(activeToken);
      });

      test('should rotate refresh token and return new tokens', () async {
        final res = await handler.handle({
          'grant_type': 'refresh_token',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'refresh_token': rawTokenVal,
        });

        expect(res.statusCode, equals(200));
        expect(res.body['access_token'], isNotNull);
        expect(res.body['refresh_token'], isNotNull);
        expect(res.body['refresh_token'], isNot(equals(rawTokenVal)));

        final oldHash = cryptoService.hashString(rawTokenVal);
        final oldToken = await tokenRepo.findRefreshTokenByHash(oldHash);
        expect(oldToken?.isRevoked, isTrue);
      });

      test('should reject request missing refresh_token', () async {
        final res = await handler.handle({
          'grant_type': 'refresh_token',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
        });
        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('invalid_request'));
      });

      test('should reject invalid refresh token', () async {
        final res = await handler.handle({
          'grant_type': 'refresh_token',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'refresh_token': 'wrong-refresh-token',
        });
        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('invalid_grant'));
      });

      test(
        'should reject refresh token belonging to different client',
        () async {
          final res = await handler.handle({
            'grant_type': 'refresh_token',
            'client_id': 'client-public',
            'refresh_token': rawTokenVal,
          });
          expect(res.statusCode, equals(400));
          expect(res.body['error'], equals('invalid_grant'));
        },
      );

      test('should reject expired refresh token', () async {
        final expiredHash = cryptoService.hashString('expired-token');
        final expiredToken = RefreshToken(
          tokenHash: expiredHash,
          clientId: 'client-confidential',
          expiresAt: DateTime.now().subtract(const Duration(days: 1)),
          userId: 'user-456',
        );
        await tokenRepo.saveRefreshToken(expiredToken);

        final res = await handler.handle({
          'grant_type': 'refresh_token',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'refresh_token': 'expired-token',
        });
        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('invalid_grant'));
      });

      test(
        'should reject refresh token requesting scope exceeding original',
        () async {
          final res = await handler.handle({
            'grant_type': 'refresh_token',
            'client_id': 'client-confidential',
            'client_secret': 'secret123',
            'refresh_token': rawTokenVal,
            'scope': 'read admin',
          });
          expect(res.statusCode, equals(400));
          expect(res.body['error'], equals('invalid_scope'));
        },
      );

      test(
        'should detect refresh token replay and revoke active family',
        () async {
          // Revoke the refresh token first and simulate it was revoked 31 seconds ago
          final hash = cryptoService.hashString(rawTokenVal);
          final token = await tokenRepo.findRefreshTokenByHash(hash);
          if (token != null) {
            final olderRevokedToken = token.copyWith(
              isRevoked: true,
              revokedAt: DateTime.now().subtract(const Duration(seconds: 31)),
            );
            await tokenRepo.saveRefreshToken(olderRevokedToken);
          }

          final res = await handler.handle({
            'grant_type': 'refresh_token',
            'client_id': 'client-confidential',
            'client_secret': 'secret123',
            'refresh_token': rawTokenVal,
          });

          expect(res.statusCode, equals(400));
          expect(res.body['error'], equals('invalid_grant'));
          expect(tokenRepo.revokeAllCalled, isTrue);
          expect(tokenRepo.revokedClientId, equals('client-confidential'));
          expect(tokenRepo.revokedUserId, equals('user-456'));
        },
      );

      test('should allow refresh token rotation retry within 30-second grace '
          'window exactly once', () async {
        final hash = cryptoService.hashString(rawTokenVal);
        await tokenRepo.revokeRefreshTokenByHash(hash);

        // First retry (within grace window) should succeed
        final res1 = await handler.handle({
          'grant_type': 'refresh_token',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'refresh_token': rawTokenVal,
        });

        expect(res1.statusCode, equals(200));
        expect(res1.body['access_token'], isNotNull);
        expect(res1.body['refresh_token'], isNotNull);

        // Verify that the token is marked as used in grace window
        final updatedToken = await tokenRepo.findRefreshTokenByHash(hash);
        expect(updatedToken?.usedInGraceWindow, isTrue);

        // Reset spy flag
        tokenRepo.revokeAllCalled = false;

        // Second retry should trigger cascading revocation
        final res2 = await handler.handle({
          'grant_type': 'refresh_token',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'refresh_token': rawTokenVal,
        });

        expect(res2.statusCode, equals(400));
        expect(res2.body['error'], equals('invalid_grant'));
        expect(tokenRepo.revokeAllCalled, isTrue);
      });

      test('should reject refresh token rotation retry if outside 30-second '
          'grace window', () async {
        final hash = cryptoService.hashString(rawTokenVal);
        final token = await tokenRepo.findRefreshTokenByHash(hash);
        if (token != null) {
          final olderRevokedToken = token.copyWith(
            isRevoked: true,
            revokedAt: DateTime.now().subtract(const Duration(seconds: 31)),
          );
          await tokenRepo.saveRefreshToken(olderRevokedToken);
        }

        tokenRepo.revokeAllCalled = false;

        final res = await handler.handle({
          'grant_type': 'refresh_token',
          'client_id': 'client-confidential',
          'client_secret': 'secret123',
          'refresh_token': rawTokenVal,
        });

        expect(res.statusCode, equals(400));
        expect(res.body['error'], equals('invalid_grant'));
        expect(tokenRepo.revokeAllCalled, isTrue);
      });
    });

    test('should protect against timing attacks by validating that '
        'cryptoService uses constant-time matching', () {
      expect(CryptoService.safeEquals('abc', 'abc'), isTrue);
      expect(CryptoService.safeEquals('abc', 'xyz'), isFalse);
      expect(CryptoService.safeEquals('abc', 'abcd'), isFalse);
    });
  });
}
