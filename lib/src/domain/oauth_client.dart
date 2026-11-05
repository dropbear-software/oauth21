import 'dart:convert';

import 'package:http/http.dart' as http;

import 'abnf_validators.dart';
import 'entities/auth_request.dart';
import 'entities/token_result.dart';
import 'ports/oauth_http_client.dart';
import 'ports/oauth_req_parser.dart';
import 'redirect_uri_policy.dart';
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

  /// The expected issuer identifier used to prevent server mix-up attacks
  /// (optional).
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

  /// Composes a secure front-channel [AuthRequest] for the authorization code
  /// grant.
  AuthRequest createAuthorizationRequest({
    required Uri redirectUri,
    required CodeChallenge codeChallenge,
    String? state,
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
  /// - Enforces character-for-character state matching to prevent CSRF when
  ///   [expectedState] is provided, or rejects unsolicited `state` parameters
  ///   when [expectedState] is omitted.
  /// - Validates the `iss` parameter if [expectedIssuer] is defined, preventing
  ///   server mix-up attacks.
  ///
  /// Throws [StateError] if validation fails.
  void validateCallback(
    OAuthRedirectParameters params, {
    String? expectedState,
  }) {
    // 1. Verify CSRF state token
    if (expectedState != null) {
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
    } else if (params.state != null) {
      throw StateError(
        'CSRF validation failed: unexpected state "${params.state}" received '
        'when no state was sent in the authorization request.',
      );
    }

    // 2. Mitigate Mix-Up attacks using the iss parameter
    if (expectedIssuer != null) {
      if (params.iss == null) {
        throw StateError(
          'Security violation: expected issuer "$expectedIssuer" in redirect '
          'callback, but the "iss" parameter was missing.',
        );
      }
      if (params.iss != expectedIssuer) {
        throw StateError(
          'Issuer mismatch: expected issuer "$expectedIssuer", but got '
          '"${params.iss}". Aborting redirect callback processing to prevent '
          'server mix-up attack.',
        );
      }
    }
  }

  Map<String, String> _buildTokenRequestHeaders() {
    final headers = <String, String>{};
    if (clientSecret != null) {
      final encodedClientId = Uri.encodeQueryComponent(clientId);
      final encodedClientSecret = Uri.encodeQueryComponent(clientSecret!);
      final credentials = base64.encode(
        utf8.encode('$encodedClientId:$encodedClientSecret'),
      );
      headers['Authorization'] = 'Basic $credentials';
    }
    return headers;
  }

  /// Exchanges the authorization [code] for access tokens via back-channel
  /// POST.
  ///
  /// - Accepts [redirectUri] if one was bound to the authorization code.
  Future<TokenResult> exchangeCode({
    required String code,
    required CodeVerifier codeVerifier,
    Uri? redirectUri,
  }) {
    final body = {
      'grant_type': 'authorization_code',
      'code': code,
      'code_verifier': codeVerifier.value,
      'client_id': clientId,
    };

    if (redirectUri != null) {
      body['redirect_uri'] = redirectUri.toString();
    }

    return _sendTokenRequest(body);
  }

  /// Exchanges a [refreshToken] for a new set of tokens via back-channel POST.
  ///
  /// Optionally accepts a narrowed [scope] string (OAuth 2.1 Section 4.3.1).
  Future<TokenResult> exchangeRefreshToken(
    String refreshToken, {
    String? scope,
  }) {
    if (!isValidVscharParam(refreshToken)) {
      throw ArgumentError.value(
        refreshToken,
        'refreshToken',
        'refresh_token must be a non-empty VSCHAR string.',
      );
    }

    final body = {
      'grant_type': 'refresh_token',
      'refresh_token': refreshToken,
      'client_id': clientId,
    };

    return _sendTokenRequest(body, scope: scope);
  }

  /// Requests an access token using the Client Credentials grant (OAuth 2.1
  /// Section 4.2).
  ///
  /// Requires a confidential client configured with a non-empty [clientSecret].
  Future<TokenResult> exchangeClientCredentials({String? scope}) {
    if (clientSecret == null || clientSecret!.isEmpty) {
      throw StateError(
        'Client credentials grant requires a confidential client with a '
        'non-empty clientSecret.',
      );
    }

    final body = <String, String>{'grant_type': 'client_credentials'};

    return _sendTokenRequest(body, scope: scope);
  }

  Future<TokenResult> _sendTokenRequest(
    Map<String, String> body, {
    String? scope,
  }) async {
    if (scope != null) {
      if (!isValidScopeString(scope)) {
        throw ArgumentError.value(
          scope,
          'scope',
          'scope must be a space-delimited list of valid NQCHAR scope tokens.',
        );
      }
      body['scope'] = scope;
    }

    final response = await httpClient.post(
      Uri.parse(tokenEndpoint),
      headers: _buildTokenRequestHeaders(),
      body: body,
    );

    return TokenResult.fromResponse(
      body: response.body,
      headers: response.headers,
      statusCode: response.statusCode,
    );
  }
}

/// An HTTP client wrapper that automatically appends the Bearer token to
/// requests and enforces OAuth 2.1 resource access security constraints.
///
/// Only HTTPS URIs (or loopback HTTP URIs for `localhost`, `127.0.0.1`, `::1`,
/// and `[::1]`) are permitted. In addition, `request.followRedirects` is
/// unconditionally set to `false` on every request so that wrapped HTTP clients
/// never follow a `3xx` redirect to a cleartext or third-party URI with the
/// `Authorization` header attached.
class OAuthAuthenticatedClient extends http.BaseClient {
  final http.Client _inner;
  final String _accessToken;

  /// The token type scheme prefix to use in the Authorization header (e.g.,
  /// `Bearer`, `DPoP`).
  final String tokenType;

  /// Creates a new [OAuthAuthenticatedClient] wrapping [_inner].
  OAuthAuthenticatedClient(
    this._inner,
    this._accessToken, {
    this.tokenType = 'Bearer',
  });

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    final url = request.url;

    // 1. Enforce transport security (HTTPS or loopback HTTP only, valid host,
    // no userinfo/fragment)
    if (!isAllowedHttpEndpointUri(url)) {
      throw ArgumentError.value(
        url,
        'request.url',
        'OAuthAuthenticatedClient only sends bearer tokens over HTTPS, or HTTP '
            'to a loopback host (localhost, 127.0.0.1, [::1]), with a valid '
            'authority and no userinfo or fragment.',
      );
    }

    // 2. Enforce query string prohibitions:
    // "Under no circumstances may an access token be appended to a query
    // parameter string. If a URL format contains a token query string, the
    // library must reject the resource request execution loop."
    for (final values in url.queryParametersAll.values) {
      for (final val in values) {
        if (val.contains(_accessToken)) {
          throw StateError(
            'Security violation: Access token must never be appended to a '
            'query parameter string. '
            'Resource request execution loop rejected.',
          );
        }
      }
    }

    // 3. Prevent automatic redirect following to avoid leaking bearer tokens
    // across redirect hops
    request.followRedirects = false;

    // 4. Enforce Bearer / Token Type Format:
    // Pass tokens strictly via the HTTP Authorization request header utilizing
    // the correct scheme.
    request.headers['Authorization'] = '$tokenType $_accessToken';

    return _inner.send(request);
  }
}
