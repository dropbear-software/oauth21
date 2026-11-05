import 'dart:async';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:oauth21/src/domain/entities/token_result.dart';
import 'package:oauth21/src/domain/oauth_client.dart';
import 'package:oauth21/src/domain/ports/oauth_http_client.dart';
import 'package:oauth21/src/domain/ports/oauth_req_parser.dart';
import 'package:oauth21/src/domain/value_objects/code_challenge.dart';
import 'package:oauth21/src/domain/value_objects/code_verifier.dart';
import 'package:test/test.dart';

class MockOAuthHttpClient implements OAuthHttpClient {
  final Future<OAuthHttpResponse> Function(
    Uri url,
    Map<String, String> headers,
    Map<String, String> body,
  )
  onPost;

  MockOAuthHttpClient(this.onPost);

  @override
  Future<OAuthHttpResponse> post(
    Uri url, {
    required Map<String, String> body,
    Map<String, String> headers = const {},
  }) {
    return onPost(url, headers, body);
  }
}

void main() {
  group('OAuthClient', () {
    const authEndpoint = 'https://auth.example.com/authorize';
    const tokenEndpoint = 'https://auth.example.com/token';
    const clientId = 'client-123';
    const stateToken = 'state-xyz';

    group('constructor validation', () {
      final dummyHttp = MockOAuthHttpClient(
        (u, h, b) async =>
            const OAuthHttpResponse(statusCode: 200, body: '', headers: {}),
      );

      test('should reject invalid clientId, clientSecret, endpoints, or '
          'expectedIssuer', () {
        expect(
          () => OAuthClient(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            clientId: '   ',
            httpClient: dummyHttp,
          ),
          throwsArgumentError,
        );

        expect(
          () => OAuthClient(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            clientId: clientId,
            clientSecret: '',
            httpClient: dummyHttp,
          ),
          throwsArgumentError,
        );

        expect(
          () => OAuthClient(
            authorizationEndpoint: 'http://auth.example.com/authorize',
            tokenEndpoint: tokenEndpoint,
            clientId: clientId,
            httpClient: dummyHttp,
          ),
          throwsArgumentError,
        );

        expect(
          () => OAuthClient(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: 'http://auth.example.com/token',
            clientId: clientId,
            httpClient: dummyHttp,
          ),
          throwsArgumentError,
        );

        expect(
          () => OAuthClient(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            clientId: clientId,
            expectedIssuer: 'https://auth.example.com?query=1',
            httpClient: dummyHttp,
          ),
          throwsArgumentError,
        );
      });
    });

    group('createAuthorizationRequest', () {
      test('should build a valid AuthRequest with correct parameters', () {
        final client = OAuthClient(
          authorizationEndpoint: authEndpoint,
          tokenEndpoint: tokenEndpoint,
          clientId: clientId,
          httpClient: MockOAuthHttpClient(
            (u, h, b) async =>
                const OAuthHttpResponse(statusCode: 200, body: '', headers: {}),
          ),
        );
        final verifier = CodeVerifier.generate();
        final challenge = CodeChallenge.s256(verifier);
        final request = client.createAuthorizationRequest(
          redirectUri: Uri.parse('https://client.example.com/callback'),
          state: stateToken,
          codeChallenge: challenge,
          scope: 'read write',
        );

        expect(request.authorizationEndpoint, equals(authEndpoint));
        expect(request.clientId, equals(clientId));
        expect(
          request.redirectUri,
          equals(Uri.parse('https://client.example.com/callback')),
        );
        expect(request.state, equals(stateToken));
        expect(request.codeChallenge, equals(challenge));
        expect(request.scope, equals('read write'));
      });

      test('should build a valid AuthRequest when state and redirectUri are '
          'omitted (#5, Section 2.3.2)', () {
        final client = OAuthClient(
          authorizationEndpoint: authEndpoint,
          tokenEndpoint: tokenEndpoint,
          clientId: clientId,
          httpClient: MockOAuthHttpClient(
            (u, h, b) async =>
                const OAuthHttpResponse(statusCode: 200, body: '', headers: {}),
          ),
        );
        final verifier = CodeVerifier.generate();
        final challenge = CodeChallenge.s256(verifier);
        final request = client.createAuthorizationRequest(
          codeChallenge: challenge,
        );

        expect(request.state, isNull);
        expect(request.redirectUri, isNull);
        expect(request.toUri().queryParameters.containsKey('state'), isFalse);
        expect(
          request.toUri().queryParameters.containsKey('redirect_uri'),
          isFalse,
        );
      });
    });

    group('validateCallback', () {
      final clientNoIssuer = OAuthClient(
        authorizationEndpoint: authEndpoint,
        tokenEndpoint: tokenEndpoint,
        clientId: clientId,
        httpClient: MockOAuthHttpClient(
          (u, h, b) async =>
              const OAuthHttpResponse(statusCode: 200, body: '', headers: {}),
        ),
      );

      final clientWithIssuer = OAuthClient(
        authorizationEndpoint: authEndpoint,
        tokenEndpoint: tokenEndpoint,
        clientId: clientId,
        httpClient: MockOAuthHttpClient(
          (u, h, b) async =>
              const OAuthHttpResponse(statusCode: 200, body: '', headers: {}),
        ),
        expectedIssuer: 'https://auth.example.com',
      );

      test('should pass state verification when states match '
          'character-for-character', () {
        final params = OAuthRedirectParameters(
          code: 'code123',
          state: stateToken,
        );
        expect(
          () => clientNoIssuer.validateCallback(
            params,
            expectedState: stateToken,
          ),
          returnsNormally,
        );
      });

      test('should fail CSRF verification when states do not match', () {
        final params = OAuthRedirectParameters(
          code: 'code123',
          state: 'state-attack',
        );
        expect(
          () => clientNoIssuer.validateCallback(
            params,
            expectedState: stateToken,
          ),
          throwsStateError,
        );
      });

      test('should fail CSRF verification when state is missing', () {
        final params = OAuthRedirectParameters(code: 'code123');
        expect(
          () => clientNoIssuer.validateCallback(
            params,
            expectedState: stateToken,
          ),
          throwsStateError,
        );
      });

      test('should succeed when expectedState is omitted and callback has no '
          'state, and reject unsolicited state (#5)', () {
        const paramsWithoutState = OAuthRedirectParameters(code: 'code123');
        expect(
          () => clientNoIssuer.validateCallback(paramsWithoutState),
          returnsNormally,
        );

        const paramsWithUnsolicitedState = OAuthRedirectParameters(
          code: 'code123',
          state: 'unsolicited-state',
        );
        expect(
          () => clientNoIssuer.validateCallback(paramsWithUnsolicitedState),
          throwsStateError,
        );
      });

      test(
        'should pass issuer verification when iss matches expectedIssuer',
        () {
          final params = OAuthRedirectParameters(
            code: 'code123',
            state: stateToken,
            iss: 'https://auth.example.com',
          );
          expect(
            () => clientWithIssuer.validateCallback(
              params,
              expectedState: stateToken,
            ),
            returnsNormally,
          );
        },
      );

      test('should fail issuer verification when iss matches but has different '
          'casing/characters', () {
        final params = OAuthRedirectParameters(
          code: 'code123',
          state: stateToken,
          iss: 'https://auth.example.com/other',
        );
        expect(
          () => clientWithIssuer.validateCallback(
            params,
            expectedState: stateToken,
          ),
          throwsStateError,
        );
      });

      test(
        'should fail issuer verification when expectedIssuer is set but iss is '
        'missing',
        () {
          final params = OAuthRedirectParameters(
            code: 'code123',
            state: stateToken,
          );
          expect(
            () => clientWithIssuer.validateCallback(
              params,
              expectedState: stateToken,
            ),
            throwsStateError,
          );
        },
      );
    });

    group('exchangeCode', () {
      final codeVerifier = CodeVerifier('A' * 50);

      test(
        'should exchange code successfully without redirect_uri by default',
        () async {
          final httpClient = MockOAuthHttpClient((url, headers, body) async {
            expect(url.toString(), equals(tokenEndpoint));
            expect(body['grant_type'], equals('authorization_code'));
            expect(body['code'], equals('auth-code'));
            expect(body['code_verifier'], equals(codeVerifier.value));
            expect(body['client_id'], equals(clientId));
            expect(body.containsKey('redirect_uri'), isFalse);
            expect(headers.containsKey('Authorization'), isFalse);

            return const OAuthHttpResponse(
              statusCode: 200,
              body: '{"access_token": "token123", "token_type": "Bearer"}',
              headers: {'Cache-Control': 'no-store'},
            );
          });

          final client = OAuthClient(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            clientId: clientId,
            httpClient: httpClient,
          );

          final result = await client.exchangeCode(
            code: 'auth-code',
            codeVerifier: codeVerifier,
          );
          expect(result, isA<TokenSuccess>());
          expect((result as TokenSuccess).accessToken, equals('token123'));
        },
      );

      test('should send redirect_uri if explicitly passed', () async {
        final redirectUri = Uri.parse('https://client.example.com/callback');
        final httpClient = MockOAuthHttpClient((url, headers, body) async {
          expect(body['redirect_uri'], equals(redirectUri.toString()));
          return const OAuthHttpResponse(
            statusCode: 200,
            body: '{"access_token": "token123", "token_type": "Bearer"}',
            headers: {'Cache-Control': 'no-store'},
          );
        });

        final client = OAuthClient(
          authorizationEndpoint: authEndpoint,
          tokenEndpoint: tokenEndpoint,
          clientId: clientId,
          httpClient: httpClient,
        );

        final result = await client.exchangeCode(
          code: 'auth-code',
          codeVerifier: codeVerifier,
          redirectUri: redirectUri,
        );
        expect(result, isA<TokenSuccess>());
      });

      test('should default to client_secret_post when clientSecret is provided '
          '(Section 2.4.1)', () async {
        final httpClient = MockOAuthHttpClient((url, headers, body) async {
          expect(headers.containsKey('Authorization'), isFalse);
          expect(body['client_id'], equals(clientId));
          expect(body['client_secret'], equals('secret-456'));
          return const OAuthHttpResponse(
            statusCode: 200,
            body: '{"access_token": "token123", "token_type": "Bearer"}',
            headers: {'Cache-Control': 'no-store'},
          );
        });

        final client = OAuthClient(
          authorizationEndpoint: authEndpoint,
          tokenEndpoint: tokenEndpoint,
          clientId: clientId,
          clientSecret: 'secret-456',
          httpClient: httpClient,
        );

        final result = await client.exchangeCode(
          code: 'auth-code',
          codeVerifier: codeVerifier,
        );
        expect(result, isA<TokenSuccess>());
      });

      test('should include Basic authentication header and omit body client_id '
          'when ClientAuthMethod.clientSecretBasic is configured', () async {
        final httpClient = MockOAuthHttpClient((url, headers, body) async {
          expect(
            headers['Authorization'],
            equals('Basic Y2xpZW50LTEyMzpzZWNyZXQtNDU2'),
          );
          expect(body.containsKey('client_id'), isFalse);
          expect(body.containsKey('client_secret'), isFalse);
          return const OAuthHttpResponse(
            statusCode: 200,
            body: '{"access_token": "token123", "token_type": "Bearer"}',
            headers: {'Cache-Control': 'no-store'},
          );
        });

        final client = OAuthClient(
          authorizationEndpoint: authEndpoint,
          tokenEndpoint: tokenEndpoint,
          clientId: clientId,
          clientSecret: 'secret-456',
          authMethod: ClientAuthMethod.clientSecretBasic,
          httpClient: httpClient,
        );

        final result = await client.exchangeCode(
          code: 'auth-code',
          codeVerifier: codeVerifier,
        );
        expect(result, isA<TokenSuccess>());
      });

      test('should strictly form-encode client ID and secret separately before '
          'generating Basic auth token', () async {
        final httpClient = MockOAuthHttpClient((url, headers, body) async {
          // client ID: 'client:id' -> 'client%3Aid'
          // client secret: 'sec&ret' -> 'sec%26ret'
          // Joined: 'client%3Aid:sec%26ret' -> Base64 encoded
          expect(
            headers['Authorization'],
            equals('Basic Y2xpZW50JTNBaWQ6c2VjJTI2cmV0'),
          );
          expect(body.containsKey('client_id'), isFalse);
          return const OAuthHttpResponse(
            statusCode: 200,
            body: '{"access_token":"t1","token_type":"Bearer"}',
            headers: {'Cache-Control': 'no-store'},
          );
        });

        final client = OAuthClient(
          authorizationEndpoint: authEndpoint,
          tokenEndpoint: tokenEndpoint,
          clientId: 'client:id',
          clientSecret: 'sec&ret',
          authMethod: ClientAuthMethod.clientSecretBasic,
          httpClient: httpClient,
        );

        await client.exchangeCode(
          code: 'auth-code',
          codeVerifier: codeVerifier,
        );
      });

      test(
        'should reject mismatched HTTP status codes in exchangeCode response '
        '(#7)',
        () {
          final httpClient = MockOAuthHttpClient((url, headers, body) async {
            return const OAuthHttpResponse(
              statusCode: 200,
              body: '{"error": "invalid_grant"}',
              headers: {'Cache-Control': 'no-store'},
            );
          });

          final client = OAuthClient(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            clientId: clientId,
            httpClient: httpClient,
          );

          expect(
            () => client.exchangeCode(
              code: 'auth-code',
              codeVerifier: codeVerifier,
            ),
            throwsFormatException,
          );
        },
      );
    });

    group('exchangeRefreshToken & exchangeClientCredentials (#7)', () {
      test('exchangeRefreshToken should send optional scope and validate '
          'refreshToken and scope ABNF', () async {
        final httpClient = MockOAuthHttpClient((url, headers, body) async {
          expect(body['grant_type'], equals('refresh_token'));
          expect(body['refresh_token'], equals('valid-refresh-token'));
          expect(body['scope'], equals('read'));
          return const OAuthHttpResponse(
            statusCode: 200,
            body: '{"access_token": "t1", "token_type": "Bearer"}',
            headers: {'Cache-Control': 'no-store'},
          );
        });

        final client = OAuthClient(
          authorizationEndpoint: authEndpoint,
          tokenEndpoint: tokenEndpoint,
          clientId: clientId,
          httpClient: httpClient,
        );

        final res = await client.exchangeRefreshToken(
          'valid-refresh-token',
          scope: 'read',
        );
        expect(res, isA<TokenSuccess>());

        expect(() => client.exchangeRefreshToken(''), throwsArgumentError);
        expect(
          () => client.exchangeRefreshToken('bad\ntoken'),
          throwsArgumentError,
        );
        expect(
          () => client.exchangeRefreshToken(
            'valid-refresh-token',
            scope: 'read  write',
          ),
          throwsArgumentError,
        );
      });

      test(
        'exchangeClientCredentials should authenticate via clientSecretPost by '
        'default or clientSecretBasic when configured, support optional scope, '
        'and throw StateError for public clients',
        () async {
          final postHttpClient = MockOAuthHttpClient((
            url,
            headers,
            body,
          ) async {
            expect(body['grant_type'], equals('client_credentials'));
            expect(body['client_id'], equals(clientId));
            expect(body['client_secret'], equals('secret-456'));
            expect(body['scope'], equals('read write'));
            expect(headers.containsKey('Authorization'), isFalse);
            return const OAuthHttpResponse(
              statusCode: 200,
              body: '{"access_token": "cc-token", "token_type": "Bearer"}',
              headers: {'Cache-Control': 'no-store'},
            );
          });

          final confidentialPostClient = OAuthClient(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            clientId: clientId,
            clientSecret: 'secret-456',
            httpClient: postHttpClient,
          );

          final resPost = await confidentialPostClient
              .exchangeClientCredentials(scope: 'read write');
          expect(resPost, isA<TokenSuccess>());

          final basicHttpClient = MockOAuthHttpClient((
            url,
            headers,
            body,
          ) async {
            expect(body['grant_type'], equals('client_credentials'));
            expect(body.containsKey('client_id'), isFalse);
            expect(body.containsKey('client_secret'), isFalse);
            expect(headers['Authorization'], startsWith('Basic '));
            return const OAuthHttpResponse(
              statusCode: 200,
              body: '{"access_token": "cc-token", "token_type": "Bearer"}',
              headers: {'Cache-Control': 'no-store'},
            );
          });

          final confidentialBasicClient = OAuthClient(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            clientId: clientId,
            clientSecret: 'secret-456',
            authMethod: ClientAuthMethod.clientSecretBasic,
            httpClient: basicHttpClient,
          );

          final resBasic = await confidentialBasicClient
              .exchangeClientCredentials();
          expect(resBasic, isA<TokenSuccess>());

          expect(
            () => confidentialPostClient.exchangeClientCredentials(
              scope: 'invalid"scope',
            ),
            throwsArgumentError,
          );

          final publicClient = OAuthClient(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            clientId: clientId,
            httpClient: postHttpClient,
          );
          expect(publicClient.exchangeClientCredentials, throwsStateError);
        },
      );
    });
  });

  group('OAuthAuthenticatedClient', () {
    const token = 'my-access-token-123';

    test('should append Bearer authorization header to request', () async {
      final mockInner = MockClient((request) async {
        expect(request.headers['Authorization'], equals('Bearer $token'));
        expect(request.followRedirects, isFalse);
        return http.Response('OK', 200);
      });

      final authClient = OAuthAuthenticatedClient(mockInner, token);
      final response = await authClient.get(
        Uri.parse('https://api.example.com/user'),
      );
      expect(response.statusCode, equals(200));
    });

    test(
      'should reject remote cleartext HTTP, spoofed localhost, userinfo, and '
      'fragment URLs while permitting loopback HTTP and disabling '
      'followRedirects',
      () async {
        final mockInner = MockClient((request) async {
          expect(request.followRedirects, isFalse);
          return http.Response('OK', 200);
        });
        final authClient = OAuthAuthenticatedClient(mockInner, token);

        for (final badUrl in [
          'http://api.example.com/resource',
          'http://localhost.evil.com/resource',
          'https://user:pass@api.example.com/resource',
          'https://api.example.com/resource#frag',
        ]) {
          expect(
            () => authClient.get(Uri.parse(badUrl)),
            throwsArgumentError,
            reason: 'Expected $badUrl to be rejected',
          );
        }

        for (final validUrl in [
          'https://api.example.com/resource',
          'http://localhost:8080/resource',
          'http://127.0.0.1:8080/resource',
          'http://[::1]:8080/resource',
        ]) {
          final res = await authClient.get(Uri.parse(validUrl));
          expect(res.statusCode, equals(200));
        }
      },
    );

    test(
      'should dynamically append the correct token type scheme prefix to the '
      'authorization header',
      () async {
        final mockInner = MockClient((request) async {
          expect(
            request.headers['Authorization'],
            equals('DPoP dynamic-token-123'),
          );
          return http.Response('OK', 200);
        });

        // Pass 'DPoP' as the explicit token type configuration
        final authClient = OAuthAuthenticatedClient(
          mockInner,
          'dynamic-token-123',
          tokenType: 'DPoP',
        );
        final response = await authClient.get(
          Uri.parse('https://api.example.com/user'),
        );
        expect(response.statusCode, equals(200));
      },
    );

    test(
      'should reject request if the access token is in a query parameter',
      () {
        final mockInner = MockClient((request) async {
          return http.Response('OK', 200);
        });

        final authClient = OAuthAuthenticatedClient(mockInner, token);

        // Attempting to send access token in query string should throw
        // StateError immediately.
        expect(
          () => authClient.get(
            Uri.parse('https://api.example.com/user?access_token=$token'),
          ),
          throwsStateError,
        );

        expect(
          () => authClient.get(
            Uri.parse('https://api.example.com/user?token=$token'),
          ),
          throwsStateError,
        );
      },
    );

    test('should reject request if the sensitive token value is leaked inside '
        'any query parameter value', () {
      final mockInner = MockClient((request) async => http.Response('OK', 200));
      final authClient = OAuthAuthenticatedClient(
        mockInner,
        'secret-token-val',
      );

      expect(
        () => authClient.get(
          Uri.parse(
            'https://api.example.com/user?custom_key=secret-token-val',
          ), // Custom parameter leaking value
        ),
        throwsStateError,
      );
    });
  });
}
