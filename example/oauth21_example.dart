// Example scripts use print to demonstrate usage in the console.
// ignore_for_file: avoid_print

import 'package:http/http.dart' as http;
import 'package:oauth21/oauth21.dart';

void main() async {
  // 1. Initialize the OAuth 2.1 Client
  final httpClient = http.Client();
  final oauthClient = OAuthClient(
    authorizationEndpoint: 'https://auth.example.com/authorize',
    tokenEndpoint: 'https://auth.example.com/token',
    clientId: 'my-client-id',
    httpClient: HttpAdapter(httpClient),
    expectedIssuer: 'https://auth.example.com',
  );

  // 2. Generate PKCE Verifier and Challenge
  final codeVerifier = CodeVerifier.generate();
  final codeChallenge = CodeChallenge.s256(codeVerifier);

  // 3. Compose Authorization Request URL
  final authRequest = oauthClient.createAuthorizationRequest(
    redirectUri: Uri.parse('https://client.example.com/callback'),
    state: 'random-secure-state-token',
    codeChallenge: codeChallenge,
    scope: 'read write',
  );

  final authorizationUrl = authRequest.toUri();
  // Redirect the user agent to `authorizationUrl`...
  print('Direct the user to: $authorizationUrl');

  // 4. Handle redirect callback
  // In your web server/callback controller:
  final callbackUri = Uri.parse(
    'https://client.example.com/callback?code=auth-code-value&state=random-secure-state-token&iss=https%3A%2F%2Fauth.example.com',
  );

  const parser = DefaultRequestParser();
  final redirectParams = parser.parseRedirect(callbackUri);

  try {
    // Validate CSRF state and server identity
    oauthClient.validateCallback(
      redirectParams,
      expectedState: 'random-secure-state-token',
    );

    // 5. Exchange code for access token
    if (redirectParams.code != null) {
      final tokenResult = await oauthClient.exchangeCode(
        code: redirectParams.code!,
        codeVerifier: codeVerifier,
      );

      switch (tokenResult) {
        case TokenSuccess(:final accessToken):
          print('Successfully authenticated! Token retrieved.');

          // 6. Make authenticated API request
          final authenticatedClient = OAuthAuthenticatedClient(
            httpClient,
            accessToken,
          );
          final response = await authenticatedClient.get(
            Uri.parse('https://api.example.com/profile'),
          );
          print('API Response status: ${response.statusCode}');
        case TokenError(:final error, :final errorDescription):
          print('Token exchange failed: $error - $errorDescription');
      }
    }
  } on Object catch (e) {
    print('Callback validation failed: $e');
  } finally {
    httpClient.close();
  }
}
