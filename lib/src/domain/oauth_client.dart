import 'dart:convert';

import 'package:http/http.dart' as http;

import 'entities/auth_request.dart';
import 'entities/token_result.dart';
import 'ports/oauth_http_client.dart';
import 'ports/oauth_req_parser.dart';
import 'value_objects/code_challenge.dart';
import 'value_objects/code_verifier.dart';

/// Orchestrates the front-channel and back-channel OAuth 2.1 client flow.
class OAuthClient {
  /// The authorization server's authorization endpoint.
  final String authorizationEndpoint;

  /// The authorization server's token endpoint.
  final String tokenEndpoint;

  /// The client's unique identifier.
  final String clientId;

  /// The client's secret, if using client authentication (optional).
  final String? clientSecret;

  /// The HTTP client port used to communicate with the authorization server.
  final OAuthHttpClient httpClient;

  /// The request parser port used to process redirect callbacks.
  final OAuthRequestParser requestParser;

  /// The expected issuer identifier used to prevent server mix-up attacks (optional).
  final String? expectedIssuer;

  /// Creates a new [OAuthClient] instance.
  const OAuthClient({
    required this.authorizationEndpoint,
    required this.tokenEndpoint,
    required this.clientId,
    required this.httpClient,
    this.requestParser = const DefaultRequestParser(),
    this.clientSecret,
    this.expectedIssuer,
  });

  /// Composes a secure front-channel [AuthRequest] for authorization code grant.
  AuthRequest createAuthorizationRequest({
    required Uri redirectUri,
    required String state,
    required CodeChallenge codeChallenge,
    String? scope,
    Map<String, String> customParameters = const {},
  }) {
    return AuthRequest(
      authorizationEndpoint: authorizationEndpoint,
      clientId: clientId,
      redirectUri: redirectUri,
      state: state,
      codeChallenge: codeChallenge,
      scope: scope,
      customParameters: customParameters,
    );
  }

  /// Validates the incoming redirect callback parameters.
  ///
  /// - Enforces character-for-character state matching to prevent CSRF.
  /// - Validates the `iss` parameter if [expectedIssuer] is defined, preventing server mix-up attacks.
  ///
  /// Throws [StateError] if validation fails.
  void validateCallback(
    OAuthRedirectParameters params, {
    required String expectedState,
  }) {
    // 1. Verify CSRF state token
    if (params.state == null) {
      throw StateError(
        'CSRF validation failed: callback did not contain a state parameter.',
      );
    }
    if (params.state != expectedState) {
      throw StateError(
        'CSRF validation failed: incoming state "${params.state}" '
        'does not match expected state "$expectedState".',
      );
    }

    // 2. Mitigate Mix-Up attacks using the iss parameter
    if (expectedIssuer != null) {
      if (params.iss == null) {
        throw StateError(
          'Security violation: expected issuer "$expectedIssuer" in redirect callback, '
          'but the "iss" parameter was missing.',
        );
      }
      if (params.iss != expectedIssuer) {
        throw StateError(
          'Issuer mismatch: expected issuer "$expectedIssuer", but got "${params.iss}". '
          'Aborting redirect callback processing to prevent server mix-up attack.',
        );
      }
    }
  }

  /// Exchanges the authorization [code] for access tokens via back-channel POST.
  ///
  /// - Omits `redirect_uri` by default as PKCE makes it redundant.
  /// - Accepts [redirectUriFallback] for backwards compatibility with legacy OAuth 2.0 servers.
  Future<TokenResult> exchangeCode({
    required String code,
    required CodeVerifier codeVerifier,
    Uri? redirectUriFallback,
  }) async {
    final body = {
      'grant_type': 'authorization_code',
      'code': code,
      'code_verifier': codeVerifier.value,
      'client_id': clientId,
    };

    if (redirectUriFallback != null) {
      body['redirect_uri'] = redirectUriFallback.toString();
    }

    final headers = <String, String>{};
    if (clientSecret != null) {
      final encodedClientId = Uri.encodeQueryComponent(clientId);
      final encodedClientSecret = Uri.encodeQueryComponent(clientSecret!);
      final credentials = base64.encode(
        utf8.encode('$encodedClientId:$encodedClientSecret'),
      );
      headers['Authorization'] = 'Basic $credentials';
    }

    final response = await httpClient.post(
      Uri.parse(tokenEndpoint),
      headers: headers,
      body: body,
    );

    return TokenResult.fromResponse(
      body: response.body,
      headers: response.headers,
    );
  }
}

/// An HTTP client wrapper that automatically appends the Bearer token to requests
/// and enforces OAuth 2.1 resource access security constraints.
class OAuthAuthenticatedClient extends http.BaseClient {
  final http.Client _inner;
  final String _accessToken;

  /// The token type scheme prefix to use in the Authorization header (e.g., Bearer, DPoP).
  final String tokenType;

  /// Creates a new [OAuthAuthenticatedClient] wrapping the [_inner] HTTP client.
  OAuthAuthenticatedClient(
    this._inner,
    this._accessToken, {
    this.tokenType = 'Bearer',
  });

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    // 1. Enforce query string prohibitions:
    // "Under no circumstances may an access token be appended to a query parameter string.
    // If a URL format contains a token query string, the library must reject the resource request execution loop."
    final url = request.url;
    for (final values in url.queryParametersAll.values) {
      for (final val in values) {
        if (val.contains(_accessToken)) {
          throw StateError(
            'Security violation: Access token must never be appended to a query parameter string. '
            'Resource request execution loop rejected.',
          );
        }
      }
    }

    // 2. Enforce Bearer / Token Type Format:
    // Pass tokens strictly via the HTTP Authorization request header utilizing the correct scheme.
    request.headers['Authorization'] = '$tokenType $_accessToken';

    return _inner.send(request);
  }
}
