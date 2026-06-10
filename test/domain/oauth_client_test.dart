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

      test(
        'should pass state verification when states match character-for-character',
        () {
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
        },
      );

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

      test(
        'should fail issuer verification when iss matches but has different casing/characters',
        () {
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
        },
      );

      test(
        'should fail issuer verification when expectedIssuer is set but iss is missing',
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

      test('should send redirect_uri fallback if explicitly passed', () async {
        final fallbackUri = Uri.parse('https://client.example.com/callback');
        final httpClient = MockOAuthHttpClient((url, headers, body) async {
          expect(body['redirect_uri'], equals(fallbackUri.toString()));
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
          redirectUriFallback: fallbackUri,
        );
        expect(result, isA<TokenSuccess>());
      });

      test(
        'should include Basic authentication header if clientSecret is provided',
        () async {
          final httpClient = MockOAuthHttpClient((url, headers, body) async {
            expect(
              headers['Authorization'],
              equals('Basic Y2xpZW50LTEyMzpzZWNyZXQtNDU2'),
            );
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
        },
      );

      test(
        'should strictly form-encode client ID and secret separately before generating Basic auth token',
        () async {
          final httpClient = MockOAuthHttpClient((url, headers, body) async {
            // client ID: 'client:id' -> 'client%3Aid'
            // client secret: 'sec&ret' -> 'sec%26ret'
            // Joined: 'client%3Aid:sec%26ret' -> Base64 encoded
            expect(
              headers['Authorization'],
              equals('Basic Y2xpZW50JTNBaWQ6c2VjJTI2cmV0'),
            );
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
            httpClient: httpClient,
          );

          await client.exchangeCode(
            code: 'auth-code',
            codeVerifier: codeVerifier,
          );
        },
      );
    });
  });

  group('OAuthAuthenticatedClient', () {
    const token = 'my-access-token-123';

    test('should append Bearer authorization header to request', () async {
      final mockInner = MockClient((request) async {
        expect(request.headers['Authorization'], equals('Bearer $token'));
        return http.Response('OK', 200);
      });

      final authClient = OAuthAuthenticatedClient(mockInner, token);
      final response = await authClient.get(
        Uri.parse('https://api.example.com/user'),
      );
      expect(response.statusCode, equals(200));
    });

    test(
      'should dynamically append the correct token type scheme prefix to the authorization header',
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

    test('should reject request if the access token is in a query parameter', () {
      final mockInner = MockClient((request) async {
        return http.Response('OK', 200);
      });

      final authClient = OAuthAuthenticatedClient(mockInner, token);

      // Attempting to send access token in query string should throw StateError immediately
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
    });

    test(
      'should reject request if the sensitive token value is leaked inside any query parameter value',
      () {
        final mockInner = MockClient(
          (request) async => http.Response('OK', 200),
        );
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
      },
    );
  });
}
