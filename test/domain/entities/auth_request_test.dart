import 'package:oauth21/src/domain/entities/auth_request.dart';
import 'package:oauth21/src/domain/value_objects/code_challenge.dart';
import 'package:oauth21/src/domain/value_objects/code_verifier.dart';
import 'package:test/test.dart';

void main() {
  group('AuthRequest', () {
    final codeVerifier = CodeVerifier('A' * 50);
    final codeChallenge = CodeChallenge.s256(codeVerifier);
    final redirectUri = Uri.parse('https://client.example.com/callback');
    const clientId = 'test-client-id';
    const authEndpoint = 'https://auth.example.com/authorize';
    const stateToken = 'xyz-state-token';

    test('should construct and serialize a valid authorize request URI', () {
      final request = AuthRequest(
        authorizationEndpoint: authEndpoint,
        clientId: clientId,
        redirectUri: redirectUri,
        state: stateToken,
        codeChallenge: codeChallenge,
        scope: 'read write',
      );

      final uri = request.toUri();
      expect(uri.scheme, equals('https'));
      expect(uri.host, equals('auth.example.com'));
      expect(uri.path, equals('/authorize'));
      expect(uri.queryParameters['response_type'], equals('code'));
      expect(uri.queryParameters['client_id'], equals(clientId));
      expect(
        uri.queryParameters['redirect_uri'],
        equals(redirectUri.toString()),
      );
      expect(uri.queryParameters['state'], equals(stateToken));
      expect(
        uri.queryParameters['code_challenge'],
        equals(codeChallenge.value),
      );
      expect(uri.queryParameters['code_challenge_method'], equals('S256'));
      expect(uri.queryParameters['scope'], equals('read write'));
      expect(uri.query, contains('scope=read+write'));
    });

    test('should reject redirect URI containing fragment', () {
      final invalidRedirect = Uri.parse(
        'https://client.example.com/callback#token=123',
      );
      expect(
        () => AuthRequest(
          authorizationEndpoint: authEndpoint,
          clientId: clientId,
          redirectUri: invalidRedirect,
          state: stateToken,
          codeChallenge: codeChallenge,
        ),
        throwsArgumentError,
      );
    });

    test('should reject relative redirect URI', () {
      final relativeRedirect = Uri.parse('/callback');
      expect(
        () => AuthRequest(
          authorizationEndpoint: authEndpoint,
          clientId: clientId,
          redirectUri: relativeRedirect,
          state: stateToken,
          codeChallenge: codeChallenge,
        ),
        throwsArgumentError,
      );
    });

    test(
      'should reject custom parameters that collide with standard parameters',
      () {
        expect(
          () => AuthRequest(
            authorizationEndpoint: authEndpoint,
            clientId: clientId,
            redirectUri: redirectUri,
            state: stateToken,
            codeChallenge: codeChallenge,
            customParameters: {'response_type': 'token'}, // Insecure/colliding
          ),
          throwsArgumentError,
        );

        expect(
          () => AuthRequest(
            authorizationEndpoint: authEndpoint,
            clientId: clientId,
            redirectUri: redirectUri,
            state: stateToken,
            codeChallenge: codeChallenge,
            customParameters: {'code_challenge': 'override'},
          ),
          throwsArgumentError,
        );
      },
    );

    test(
      'should preserve existing query parameters on authorization endpoint if no collision',
      () {
        final request = AuthRequest(
          authorizationEndpoint: '$authEndpoint?tenant=1234',
          clientId: clientId,
          redirectUri: redirectUri,
          state: stateToken,
          codeChallenge: codeChallenge,
        );

        final uri = request.toUri();
        expect(uri.queryParameters['tenant'], equals('1234'));
        expect(uri.queryParameters['client_id'], equals(clientId));
      },
    );

    test(
      'should reject if existing endpoint parameters duplicate/pollute each other',
      () {
        expect(
          () => AuthRequest(
            authorizationEndpoint: '$authEndpoint?tenant=1234&tenant=5678',
            clientId: clientId,
            redirectUri: redirectUri,
            state: stateToken,
            codeChallenge: codeChallenge,
          ),
          throwsArgumentError,
        );
      },
    );

    test(
      'should reject if existing endpoint parameters collide with standard parameters',
      () {
        expect(
          () => AuthRequest(
            authorizationEndpoint: '$authEndpoint?client_id=pre-existing',
            clientId: clientId,
            redirectUri: redirectUri,
            state: stateToken,
            codeChallenge: codeChallenge,
          ),
          throwsArgumentError,
        );
      },
    );

    test(
      'should reject if existing endpoint contains standard parameter response_type',
      () {
        expect(
          () => AuthRequest(
            authorizationEndpoint: '$authEndpoint?response_type=code',
            clientId: clientId,
            redirectUri: redirectUri,
            state: stateToken,
            codeChallenge: codeChallenge,
          ),
          throwsArgumentError,
        );
      },
    );

    test(
      'should reject if custom parameters collide with existing endpoint parameters',
      () {
        expect(
          () => AuthRequest(
            authorizationEndpoint: '$authEndpoint?tenant=1234',
            clientId: clientId,
            redirectUri: redirectUri,
            state: stateToken,
            codeChallenge: codeChallenge,
            customParameters: {'tenant': 'collision'},
          ),
          throwsArgumentError,
        );
      },
    );

    group('TLS rules & loopback exception', () {
      test('should reject non-https authorizationEndpoint', () {
        expect(
          () => AuthRequest(
            authorizationEndpoint: 'http://auth.example.com/authorize',
            clientId: clientId,
            redirectUri: redirectUri,
            state: stateToken,
            codeChallenge: codeChallenge,
          ),
          throwsArgumentError,
        );
      });

      test('should reject non-https redirectUri for non-loopback hosts', () {
        expect(
          () => AuthRequest(
            authorizationEndpoint: authEndpoint,
            clientId: clientId,
            redirectUri: Uri.parse('http://client.example.com/callback'),
            state: stateToken,
            codeChallenge: codeChallenge,
          ),
          throwsArgumentError,
        );
      });

      test('should allow http scheme for IPv4 loopback address', () {
        expect(
          () => AuthRequest(
            authorizationEndpoint: authEndpoint,
            clientId: clientId,
            redirectUri: Uri.parse('http://127.0.0.1:8080/callback'),
            state: stateToken,
            codeChallenge: codeChallenge,
          ),
          returnsNormally,
        );
      });

      test('should allow http scheme for IPv6 loopback address', () {
        expect(
          () => AuthRequest(
            authorizationEndpoint: authEndpoint,
            clientId: clientId,
            redirectUri: Uri.parse('http://[::1]:8080/callback'),
            state: stateToken,
            codeChallenge: codeChallenge,
          ),
          returnsNormally,
        );
      });

      test('should allow http scheme for localhost loopback host', () {
        expect(
          () => AuthRequest(
            authorizationEndpoint: authEndpoint,
            clientId: clientId,
            redirectUri: Uri.parse('http://localhost:3000/callback'),
            state: stateToken,
            codeChallenge: codeChallenge,
          ),
          returnsNormally,
        );
      });

      test(
        'should allow valid private-use URI schemes for native application redirection',
        () {
          expect(
            () => AuthRequest(
              authorizationEndpoint: authEndpoint,
              clientId: clientId,
              redirectUri: Uri.parse('com.example.app:/oauth2redirect'),
              state: stateToken,
              codeChallenge: codeChallenge,
            ),
            returnsNormally,
          );
        },
      );

      test(
        'should reject private-use URI schemes that do not contain a period character',
        () {
          expect(
            () => AuthRequest(
              authorizationEndpoint: authEndpoint,
              clientId: clientId,
              redirectUri: Uri.parse('myapp:/oauth2redirect'),
              state: stateToken,
              codeChallenge: codeChallenge,
            ),
            throwsArgumentError,
          );
        },
      );

      test(
        'should reject http scheme for fake loopback domains or incorrect subdomains',
        () {
          expect(
            () => AuthRequest(
              authorizationEndpoint: authEndpoint,
              clientId: clientId,
              redirectUri: Uri.parse(
                'http://localhost.attacker.com:3000/callback',
              ),
              state: stateToken,
              codeChallenge: codeChallenge,
            ),
            throwsArgumentError,
          );

          expect(
            () => AuthRequest(
              authorizationEndpoint: authEndpoint,
              clientId: clientId,
              redirectUri: Uri.parse('http://127.0.0.2:8080/callback'),
              state: stateToken,
              codeChallenge: codeChallenge,
            ),
            throwsArgumentError,
          );
        },
      );
    });

    group('VSCHAR Syntax Enforcement', () {
      test(
        'should reject state parameter containing invalid non-VSCHAR control characters',
        () {
          expect(
            () => AuthRequest(
              authorizationEndpoint: authEndpoint,
              clientId: clientId,
              redirectUri: redirectUri,
              state: 'invalid\nstate', // Contains a newline character
              codeChallenge: codeChallenge,
            ),
            throwsArgumentError,
          );
        },
      );

      test('should reject client_id containing non-ASCII characters', () {
        expect(
          () => AuthRequest(
            authorizationEndpoint: authEndpoint,
            clientId: '🚀-client', // Contains an emoji
            redirectUri: redirectUri,
            state: stateToken,
            codeChallenge: codeChallenge,
          ),
          throwsArgumentError,
        );
      });
    });

    group('Omitted parameter handling', () {
      test(
        'should completely omit parameters with empty values from serialized query',
        () {
          final request = AuthRequest(
            authorizationEndpoint: authEndpoint,
            clientId: clientId,
            redirectUri: redirectUri,
            state: stateToken,
            codeChallenge: codeChallenge,
            scope: '', // empty value
            customParameters: {
              'foo': '', // empty custom parameter value
              'bar': 'baz',
            },
          );

          final uri = request.toUri();
          expect(uri.queryParameters.containsKey('scope'), isFalse);
          expect(uri.queryParameters.containsKey('foo'), isFalse);
          expect(uri.queryParameters['bar'], equals('baz'));
          expect(uri.query, isNot(contains('scope=')));
          expect(uri.query, isNot(contains('foo=')));
        },
      );

      test(
        'should completely omit parameters consisting entirely of whitespace',
        () {
          final request = AuthRequest(
            authorizationEndpoint: authEndpoint,
            clientId: clientId,
            redirectUri: redirectUri,
            state: stateToken,
            codeChallenge: codeChallenge,
            scope: '   ', // Pure whitespace
          );

          final uri = request.toUri();
          expect(uri.queryParameters.containsKey('scope'), isFalse);
          expect(uri.query, isNot(contains('scope=')));
        },
      );
    });

    group('Scope syntax character enforcement', () {
      test(
        'should reject scope string containing invalid double quote characters',
        () {
          expect(
            () => AuthRequest(
              authorizationEndpoint: authEndpoint,
              clientId: clientId,
              redirectUri: redirectUri,
              state: stateToken,
              codeChallenge: codeChallenge,
              scope: 'read "write"',
            ),
            throwsArgumentError,
          );
        },
      );

      test(
        'should reject scope string containing invalid backslash characters',
        () {
          expect(
            () => AuthRequest(
              authorizationEndpoint: authEndpoint,
              clientId: clientId,
              redirectUri: redirectUri,
              state: stateToken,
              codeChallenge: codeChallenge,
              scope: r'read\write',
            ),
            throwsArgumentError,
          );
        },
      );

      test(
        'should reject scope string containing consecutive space delimiters',
        () {
          expect(
            () => AuthRequest(
              authorizationEndpoint: authEndpoint,
              clientId: clientId,
              redirectUri: redirectUri,
              state: stateToken,
              codeChallenge: codeChallenge,
              scope: 'read  write',
            ),
            throwsArgumentError,
          );
        },
      );

      test('should accept scope string with valid ABNF characters', () {
        expect(
          () => AuthRequest(
            authorizationEndpoint: authEndpoint,
            clientId: clientId,
            redirectUri: redirectUri,
            state: stateToken,
            codeChallenge: codeChallenge,
            scope: 'read! #write [ok] ~test',
          ),
          returnsNormally,
        );
      });

      test(
        'should reject scope string containing leading or trailing space characters',
        () {
          expect(
            () => AuthRequest(
              authorizationEndpoint: authEndpoint,
              clientId: clientId,
              redirectUri: redirectUri,
              state: stateToken,
              codeChallenge: codeChallenge,
              scope: ' read write', // Leading space
            ),
            throwsArgumentError,
          );

          expect(
            () => AuthRequest(
              authorizationEndpoint: authEndpoint,
              clientId: clientId,
              redirectUri: redirectUri,
              state: stateToken,
              codeChallenge: codeChallenge,
              scope: 'read write ', // Trailing space
            ),
            throwsArgumentError,
          );
        },
      );
    });
  });
}
