import 'package:oauth21/oauth21.dart';
import 'package:test/test.dart';

void main() {
  group('Server Entities', () {
    group('ClientRegistration', () {
      test('should instantiate with correct values and defaults', () {
        final client = ClientRegistration(
          clientId: 'client-123',
          clientType: ClientType.confidential,
          clientSecretHash: 'hashed-secret',
          redirectUris: {Uri.parse('https://example.com/cb')},
          allowedScopes: {'read', 'write'},
        );

        expect(client.clientId, equals('client-123'));
        expect(client.clientType, equals(ClientType.confidential));
        expect(client.clientSecretHash, equals('hashed-secret'));
        expect(
          client.redirectUris,
          contains(Uri.parse('https://example.com/cb')),
        );
        expect(client.allowedScopes, contains('read'));
        expect(client.allowedScopes, contains('write'));
        expect(client.allowedGrantTypes, contains('authorization_code'));
      });

      test(
        'should reject relative URIs inside the redirectUris registration set',
        () {
          expect(
            () => ClientRegistration(
              clientId: 'client-123',
              clientType: ClientType.confidential,
              clientSecretHash: 'hash',
              redirectUris: {
                Uri.parse('/relative-callback'),
                Uri.parse('https://example.com/cb'),
              },
              allowedScopes: {'read'},
            ),
            throwsArgumentError,
          );
        },
      );

      test(
        'should reject URIs containing fragment inside redirectUris set',
        () {
          expect(
            () => ClientRegistration(
              clientId: 'client-123',
              clientType: ClientType.confidential,
              clientSecretHash: 'hash',
              redirectUris: {Uri.parse('https://example.com/cb#token')},
              allowedScopes: {'read'},
            ),
            throwsArgumentError,
          );
        },
      );

      test('should reject dangerous and malformed redirect URI schemes while '
          'accepting valid HTTPS, loopback HTTP, and reverse-domain '
          'private-use schemes', () {
        for (final badUri in [
          'javascript:alert(1)',
          'data:text/html,hi',
          'file:///etc/passwd',
          'http://example.com/cb',
          'https://user:pass@example.com/cb',
          'myapp:/cb',
          'app.:/cb',
          'com..app:/cb',
        ]) {
          expect(
            () => ClientRegistration(
              clientId: 'client-123',
              clientType: ClientType.confidential,
              clientSecretHash: 'hash',
              redirectUris: {Uri.parse(badUri)},
              allowedScopes: {'read'},
            ),
            throwsArgumentError,
            reason: 'Expected $badUri to be rejected',
          );
        }

        final validClient = ClientRegistration(
          clientId: 'client-123',
          clientType: ClientType.public,
          redirectUris: {
            Uri.parse('https://example.com/cb'),
            Uri.parse('http://localhost:8080/cb'),
            Uri.parse('http://127.0.0.1:8080/cb'),
            Uri.parse('http://[::1]:8080/cb'),
            Uri.parse('com.example.app:/cb'),
          },
          allowedScopes: {'read'},
        );
        expect(validClient.redirectUris.length, equals(5));
      });

      test(
        'should enforce strict immutability on configuration collections',
        () {
          final client = ClientRegistration(
            clientId: 'client-123',
            clientType: ClientType.confidential,
            clientSecretHash: 'hash',
            redirectUris: {Uri.parse('https://example.com/cb')},
            allowedScopes: {'read'},
          );

          expect(
            () => client.allowedScopes.add('write'),
            throwsUnsupportedError,
          );
          expect(
            () => client.redirectUris.add(Uri.parse('https://attack.com')),
            throwsUnsupportedError,
          );
          expect(
            () => client.allowedGrantTypes.add('implicit'),
            throwsUnsupportedError,
          );
        },
      );

      test('should reject clientId containing invalid non-VSCHAR control '
          'characters', () {
        expect(
          () => ClientRegistration(
            clientId: 'client\nid', // Contains a newline character
            clientType: ClientType.confidential,
            clientSecretHash: 'hash',
            redirectUris: {Uri.parse('https://example.com/cb')},
            allowedScopes: {'read'},
          ),
          throwsArgumentError,
        );
      });

      test(
        'should reject allowedScopes containing individual tokens that violate '
        'ABNF character rules',
        () {
          expect(
            () => ClientRegistration(
              clientId: 'client-123',
              clientType: ClientType.confidential,
              clientSecretHash: 'hash',
              redirectUris: {Uri.parse('https://example.com/cb')},
              allowedScopes: {'read', 'write"scope'}, // Illegal double quote
            ),
            throwsArgumentError,
          );

          expect(
            () => ClientRegistration(
              clientId: 'client-123',
              clientType: ClientType.confidential,
              clientSecretHash: 'hash',
              redirectUris: {Uri.parse('https://example.com/cb')},
              allowedScopes: {'read', r'read\write'}, // Illegal backslash
            ),
            throwsArgumentError,
          );
        },
      );

      test('should reject empty or pure whitespace clientId strings', () {
        expect(
          () => ClientRegistration(
            clientId: '   ', // Spaces only
            clientType: ClientType.confidential,
            clientSecretHash: 'hash',
            redirectUris: {Uri.parse('https://example.com/cb')},
            allowedScopes: {'read'},
          ),
          throwsArgumentError,
        );
      });

      test('should reject untrimmed clientId strings', () {
        expect(
          () => ClientRegistration(
            clientId: 'client-123 ', // Trailing space
            clientType: ClientType.confidential,
            clientSecretHash: 'hash',
            redirectUris: {Uri.parse('https://example.com/cb')},
            allowedScopes: {'read'},
          ),
          throwsArgumentError,
        );
        expect(
          () => ClientRegistration(
            clientId: ' client-123', // Leading space
            clientType: ClientType.confidential,
            clientSecretHash: 'hash',
            redirectUris: {Uri.parse('https://example.com/cb')},
            allowedScopes: {'read'},
          ),
          throwsArgumentError,
        );
      });

      test(
        'should accept valid grant-name and absolute URI allowedGrantTypes and '
        'reject malformed grant types (Appendix A.10 & Section 6.3)',
        () {
          final validClient = ClientRegistration(
            clientId: 'client-123',
            clientType: ClientType.confidential,
            clientSecretHash: 'hash',
            redirectUris: {Uri.parse('https://example.com/cb')},
            allowedGrantTypes: {
              'authorization_code',
              'refresh_token',
              'urn:ietf:params:oauth:grant-type:jwt-bearer',
              'https://example.com/grants/custom',
            },
          );
          expect(validClient.allowedGrantTypes.length, equals(4));

          for (final badGrant in [
            '',
            r'bad!grant$type',
            'relative/path/grant',
            'https://example.com/grant#fragment',
            'https://example.com/grant with space',
          ]) {
            expect(
              () => ClientRegistration(
                clientId: 'client-123',
                clientType: ClientType.confidential,
                clientSecretHash: 'hash',
                redirectUris: {Uri.parse('https://example.com/cb')},
                allowedGrantTypes: {badGrant},
              ),
              throwsArgumentError,
              reason: 'Expected grantType "$badGrant" to be rejected',
            );
          }
        },
      );
    });

    group('AuthCode', () {
      final now = DateTime.now();
      final future = now.add(const Duration(minutes: 10));
      final past = now.subtract(const Duration(minutes: 10));
      final validChallenge = 'A' * 43;

      test('should check isExpired correctly', () {
        final activeCode = AuthCode(
          code: 'code-1',
          clientId: 'client-1',
          redirectUri: Uri.parse('https://example.com/cb'),
          userId: 'user-1',
          codeChallenge: validChallenge,
          codeChallengeMethod: 'S256',
          expiresAt: future,
        );

        final expiredCode = AuthCode(
          code: 'code-2',
          clientId: 'client-2',
          redirectUri: Uri.parse('https://example.com/cb'),
          userId: 'user-2',
          codeChallenge: validChallenge,
          codeChallengeMethod: 'S256',
          expiresAt: past,
        );

        expect(activeCode.isExpired, isFalse);
        expect(expiredCode.isExpired, isTrue);
      });

      test('should reject auth code if the code string contains invalid '
          'non-VSCHAR characters', () {
        expect(
          () => AuthCode(
            code: 'malformed\ncode', // Newline injection
            clientId: 'client-1',
            redirectUri: Uri.parse('https://example.com/cb'),
            userId: 'user-1',
            codeChallenge: validChallenge,
            codeChallengeMethod: 'S256',
            expiresAt: future,
          ),
          throwsArgumentError,
        );
      });

      test('should reject empty or pure whitespace auth code strings', () {
        expect(
          () => AuthCode(
            code: '   ', // Spaces only
            clientId: 'client-1',
            redirectUri: Uri.parse('https://example.com/cb'),
            userId: 'user-1',
            codeChallenge: validChallenge,
            codeChallengeMethod: 'S256',
            expiresAt: future,
          ),
          throwsArgumentError,
        );
      });

      test('should reject untrimmed code strings', () {
        expect(
          () => AuthCode(
            code: 'code-1 ', // Trailing space
            clientId: 'client-1',
            redirectUri: Uri.parse('https://example.com/cb'),
            userId: 'user-1',
            codeChallenge: validChallenge,
            codeChallengeMethod: 'S256',
            expiresAt: future,
          ),
          throwsArgumentError,
        );
      });

      test('should reject empty, untrimmed, or invalid clientId strings', () {
        expect(
          () => AuthCode(
            code: 'valid-code-123',
            clientId: '   ', // Whitespace
            redirectUri: Uri.parse('https://example.com/cb'),
            userId: 'user-1',
            codeChallenge: validChallenge,
            codeChallengeMethod: 'S256',
            expiresAt: future,
          ),
          throwsArgumentError,
        );
        expect(
          () => AuthCode(
            code: 'valid-code-123',
            clientId: 'client-1 ', // Trailing space
            redirectUri: Uri.parse('https://example.com/cb'),
            userId: 'user-1',
            codeChallenge: validChallenge,
            codeChallengeMethod: 'S256',
            expiresAt: future,
          ),
          throwsArgumentError,
        );
        expect(
          () => AuthCode(
            code: 'valid-code-123',
            clientId: 'client\nid', // Invalid characters
            redirectUri: Uri.parse('https://example.com/cb'),
            userId: 'user-1',
            codeChallenge: validChallenge,
            codeChallengeMethod: 'S256',
            expiresAt: future,
          ),
          throwsArgumentError,
        );
      });

      test('should reject invalid userId, codeChallenge, or scope', () {
        expect(
          () => AuthCode(
            code: 'valid-code-123',
            clientId: 'client-1',
            redirectUri: Uri.parse('https://example.com/cb'),
            userId: '   ',
            codeChallenge: validChallenge,
            codeChallengeMethod: 'S256',
            expiresAt: future,
          ),
          throwsArgumentError,
        );

        expect(
          () => AuthCode(
            code: 'valid-code-123',
            clientId: 'client-1',
            redirectUri: Uri.parse('https://example.com/cb'),
            userId: 'user-1',
            codeChallenge: 'too-short',
            codeChallengeMethod: 'S256',
            expiresAt: future,
          ),
          throwsArgumentError,
        );

        expect(
          () => AuthCode(
            code: 'valid-code-123',
            clientId: 'client-1',
            redirectUri: Uri.parse('https://example.com/cb'),
            userId: 'user-1',
            codeChallenge: validChallenge,
            codeChallengeMethod: 'S256',
            scope: 'read  write',
            expiresAt: future,
          ),
          throwsArgumentError,
        );
      });

      test('should reject unsupported codeChallengeMethod values', () {
        expect(
          () => AuthCode(
            code: 'valid-code-123',
            clientId: 'client-1',
            redirectUri: Uri.parse('https://example.com/cb'),
            userId: 'user-1',
            codeChallenge: validChallenge,
            codeChallengeMethod: 'MD5', // Unsupported signature method
            expiresAt: future,
          ),
          throwsArgumentError,
        );
        expect(
          () => AuthCode(
            code: 'valid-code-123',
            clientId: 'client-1',
            redirectUri: Uri.parse('https://example.com/cb'),
            userId: 'user-1',
            codeChallenge: validChallenge,
            codeChallengeMethod: 'plain', // Removed in OAuth 2.1
            expiresAt: future,
          ),
          throwsArgumentError,
        );
      });

      test('should copyWith correctly', () {
        final original = AuthCode(
          code: 'code-1',
          clientId: 'client-1',
          redirectUri: Uri.parse('https://example.com/cb'),
          userId: 'user-1',
          codeChallenge: validChallenge,
          codeChallengeMethod: 'S256',
          scope: 'read write',
          expiresAt: future,
        );

        final modified = original.copyWith(isUsed: true);

        expect(modified.code, equals('code-1'));
        expect(modified.isUsed, isTrue);

        final unchanged = original.copyWith();
        expect(unchanged.code, equals(original.code));
        expect(unchanged.clientId, equals(original.clientId));
        expect(unchanged.redirectUri, equals(original.redirectUri));
        expect(unchanged.userId, equals(original.userId));
        expect(unchanged.scope, equals(original.scope));
        expect(unchanged.codeChallenge, equals(original.codeChallenge));
        expect(
          unchanged.codeChallengeMethod,
          equals(original.codeChallengeMethod),
        );
        expect(unchanged.expiresAt, equals(original.expiresAt));
        expect(unchanged.isUsed, equals(original.isUsed));
      });

      test(
        'should evaluate overall lifecycle validity combined with usage flags',
        () {
          final original = AuthCode(
            code: 'code-1',
            clientId: 'client-1',
            redirectUri: Uri.parse('https://example.com/cb'),
            userId: 'user-1',
            codeChallenge: validChallenge,
            codeChallengeMethod: 'S256',
            expiresAt: future,
          );

          expect(original.isValid, isTrue);

          final usedCode = original.copyWith(isUsed: true);
          expect(usedCode.isValid, isFalse);

          final expiredCode = original.copyWith(expiresAt: past);
          expect(expiredCode.isValid, isFalse);
        },
      );
    });

    group('AccessToken', () {
      final now = DateTime.now();
      final future = now.add(const Duration(hours: 1));
      final past = now.subtract(const Duration(hours: 1));

      test('should check isExpired correctly', () {
        final activeToken = AccessToken(
          tokenHash: 'hash-1',
          clientId: 'client-1',
          expiresAt: future,
        );

        final expiredToken = AccessToken(
          tokenHash: 'hash-2',
          clientId: 'client-2',
          expiresAt: past,
        );

        expect(activeToken.isExpired, isFalse);
        expect(expiredToken.isExpired, isTrue);
      });

      test('should copyWith correctly', () {
        final original = AccessToken(
          tokenHash: 'hash-1',
          clientId: 'client-1',
          expiresAt: future,
          authorizationCode: 'code-123',
        );

        final modified = original.copyWith(isRevoked: true);

        expect(modified.tokenHash, equals('hash-1'));
        expect(modified.isRevoked, isTrue);
        expect(modified.authorizationCode, equals('code-123'));

        final unchanged = original.copyWith();
        expect(unchanged.tokenHash, equals(original.tokenHash));
        expect(unchanged.clientId, equals(original.clientId));
        expect(unchanged.userId, equals(original.userId));
        expect(unchanged.scope, equals(original.scope));
        expect(unchanged.expiresAt, equals(original.expiresAt));
        expect(unchanged.isRevoked, equals(original.isRevoked));
        expect(unchanged.authorizationCode, equals(original.authorizationCode));
      });

      test(
        'should evaluate overall lifecycle validity combined with revocation '
        'flags',
        () {
          final original = AccessToken(
            tokenHash: 'hash-1',
            clientId: 'client-1',
            expiresAt: future,
          );

          expect(original.isValid, isTrue);

          final revokedToken = original.copyWith(isRevoked: true);
          expect(revokedToken.isValid, isFalse);

          final expiredToken = original.copyWith(expiresAt: past);
          expect(expiredToken.isValid, isFalse);
        },
      );
    });

    group('RefreshToken', () {
      final now = DateTime.now();
      final future = now.add(const Duration(days: 30));
      final past = now.subtract(const Duration(days: 30));

      test('should check isExpired correctly', () {
        final activeToken = RefreshToken(
          tokenHash: 'hash-1',
          clientId: 'client-1',
          expiresAt: future,
        );

        final expiredToken = RefreshToken(
          tokenHash: 'hash-2',
          clientId: 'client-2',
          expiresAt: past,
        );

        expect(activeToken.isExpired, isFalse);
        expect(expiredToken.isExpired, isTrue);
      });

      test('should copyWith correctly', () {
        final original = RefreshToken(
          tokenHash: 'hash-1',
          clientId: 'client-1',
          expiresAt: future,
          authorizationCode: 'code-123',
        );

        final modified = original.copyWith(isRevoked: true);

        expect(modified.tokenHash, equals('hash-1'));
        expect(modified.isRevoked, isTrue);
        expect(modified.authorizationCode, equals('code-123'));

        final unchanged = original.copyWith();
        expect(unchanged.tokenHash, equals(original.tokenHash));
        expect(unchanged.clientId, equals(original.clientId));
        expect(unchanged.userId, equals(original.userId));
        expect(unchanged.scope, equals(original.scope));
        expect(unchanged.expiresAt, equals(original.expiresAt));
        expect(unchanged.isRevoked, equals(original.isRevoked));
        expect(unchanged.revokedAt, equals(original.revokedAt));
        expect(unchanged.usedInGraceWindow, equals(original.usedInGraceWindow));
        expect(unchanged.authorizationCode, equals(original.authorizationCode));
      });

      test('should support grace window properties', () {
        final now = DateTime.now();
        final token = RefreshToken(
          tokenHash: 'hash-1',
          clientId: 'client-1',
          expiresAt: future,
          revokedAt: now,
          usedInGraceWindow: true,
        );
        expect(token.revokedAt, equals(now));
        expect(token.usedInGraceWindow, isTrue);

        final modified = token.copyWith(usedInGraceWindow: false);
        expect(modified.usedInGraceWindow, isFalse);
        expect(modified.revokedAt, equals(now));
      });

      test(
        'should evaluate overall lifecycle validity combined with revocation '
        'flags',
        () {
          final original = RefreshToken(
            tokenHash: 'hash-1',
            clientId: 'client-1',
            expiresAt: future,
          );

          expect(original.isValid, isTrue);

          final revokedToken = original.copyWith(isRevoked: true);
          expect(revokedToken.isValid, isFalse);

          final expiredToken = original.copyWith(expiresAt: past);
          expect(expiredToken.isValid, isFalse);
        },
      );
    });
  });
}
