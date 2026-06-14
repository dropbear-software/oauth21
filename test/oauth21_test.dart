import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:oauth21/oauth21.dart';
import 'package:test/test.dart';

void main() {
  group('OAuth 2.1 Complete Flow Integration Test', () {
    const authEndpoint = 'https://auth.example.com/authorize';
    const tokenEndpoint = 'https://auth.example.com/token';
    const clientId = 'my-client-id';
    const clientSecret = 'my-client-secret';
    const state = 'xyz-random-state-token';
    const redirectUri = 'https://client.example.com/callback';

    test(
      'executes authorization request, callback validation, code exchange, and authenticated API call',
      () async {
        // 1. Generate PKCE values
        final verifier = CodeVerifier.generate();
        final challenge = CodeChallenge.s256(verifier);

        // 2. Compose authorization request
        final authRequest = AuthRequest(
          authorizationEndpoint: authEndpoint,
          clientId: clientId,
          redirectUri: Uri.parse(redirectUri),
          state: state,
          codeChallenge: challenge,
          scope: 'read write',
        );

        final authUri = authRequest.toUri();
        expect(authUri.queryParameters['response_type'], equals('code'));
        expect(
          authUri.queryParameters['code_challenge_method'],
          equals('S256'),
        );
        expect(authUri.queryParameters['redirect_uri'], equals(redirectUri));

        // 3. Mock incoming callback redirect from authorization server
        const authCode = 'splat-auth-code-123';
        final callbackUri = Uri.parse(
          '$redirectUri?code=$authCode&state=$state&iss=https%3A%2F%2Fauth.example.com',
        );

        // Setup parser and parse redirect URL
        const parser = DefaultRequestParser();
        final parsedParams = parser.parseRedirect(callbackUri);

        // 4. Initialize OAuthClient
        final mockHttpClient = HttpAdapter(
          MockClient((request) async {
            // Verify back-channel request properties
            expect(request.url.toString(), equals(tokenEndpoint));
            expect(request.method, equals('POST'));
            // Basic auth should be sent
            expect(
              request.headers['Authorization'],
              equals('Basic bXktY2xpZW50LWlkOm15LWNsaWVudC1zZWNyZXQ='),
            );
            expect(
              request.headers['Content-Type'],
              equals('application/x-www-form-urlencoded'),
            );

            // Body parameters
            final bodyParams = request.bodyFields;
            expect(bodyParams['grant_type'], equals('authorization_code'));
            expect(bodyParams['code'], equals(authCode));
            expect(bodyParams['code_verifier'], equals(verifier.value));
            expect(bodyParams['client_id'], equals(clientId));
            // Redirect URI must be present in token request if bound to authorization code
            expect(bodyParams['redirect_uri'], equals(redirectUri));

            return http.Response(
              '{"access_token": "secret-access-token-999", "token_type": "Bearer", "expires_in": 3600}',
              200,
              headers: {'Cache-Control': 'no-store'},
            );
          }),
        );

        final oauthClient = OAuthClient(
          authorizationEndpoint: authEndpoint,
          tokenEndpoint: tokenEndpoint,
          clientId: clientId,
          clientSecret: clientSecret,
          expectedIssuer: 'https://auth.example.com',
          httpClient: mockHttpClient,
        );

        // Validate CSRF state and issuer mix-up mitigation
        expect(
          () =>
              oauthClient.validateCallback(parsedParams, expectedState: state),
          returnsNormally,
        );

        // 5. Exchange auth code for tokens
        final tokenResult = await oauthClient.exchangeCode(
          code: parsedParams.code!,
          codeVerifier: verifier,
          redirectUri: Uri.parse(redirectUri),
        );

        expect(tokenResult, isA<TokenSuccess>());
        final tokenSuccess = tokenResult as TokenSuccess;
        expect(tokenSuccess.accessToken, equals('secret-access-token-999'));
        expect(tokenSuccess.tokenType, equals('Bearer'));

        // 6. Use token to make resource server API calls
        final mockResourceClient = MockClient((request) async {
          // Authorization header must use Bearer scheme case-insensitively
          expect(
            request.headers['Authorization'],
            equals('Bearer secret-access-token-999'),
          );
          return http.Response('{"status": "success"}', 200);
        });

        final authenticatedClient = OAuthAuthenticatedClient(
          mockResourceClient,
          tokenSuccess.accessToken,
        );

        final apiResponse = await authenticatedClient.get(
          Uri.parse('https://api.example.com/data'),
        );
        expect(apiResponse.statusCode, equals(200));
        expect(apiResponse.body, contains('success'));

        // 7. Security check: make sure token is rejected if passed as a query parameter
        expect(
          () => authenticatedClient.get(
            Uri.parse(
              'https://api.example.com/data?access_token=secret-access-token-999',
            ),
          ),
          throwsStateError,
        );
      },
    );

    test('exchanges refresh token for new access token', () async {
      final mockHttpClient = HttpAdapter(
        MockClient((request) async {
          expect(request.url.toString(), equals(tokenEndpoint));
          expect(request.method, equals('POST'));
          expect(
            request.headers['Authorization'],
            equals('Basic bXktY2xpZW50LWlkOm15LWNsaWVudC1zZWNyZXQ='),
          );

          final bodyParams = request.bodyFields;
          expect(bodyParams['grant_type'], equals('refresh_token'));
          expect(bodyParams['refresh_token'], equals('old-refresh-token-123'));
          expect(bodyParams['client_id'], equals(clientId));

          return http.Response(
            '{"access_token": "new-access-token", "token_type": "Bearer", '
            '"expires_in": 3600, "refresh_token": "new-refresh-token"}',
            200,
            headers: {'Cache-Control': 'no-store'},
          );
        }),
      );

      final oauthClient = OAuthClient(
        authorizationEndpoint: authEndpoint,
        tokenEndpoint: tokenEndpoint,
        clientId: clientId,
        clientSecret: clientSecret,
        httpClient: mockHttpClient,
      );

      final result = await oauthClient.exchangeRefreshToken(
        'old-refresh-token-123',
      );
      expect(result, isA<TokenSuccess>());
      final success = result as TokenSuccess;
      expect(success.accessToken, equals('new-access-token'));
      expect(success.refreshToken, equals('new-refresh-token'));
    });
  });
}
