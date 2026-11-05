import 'package:meta/meta.dart';
import '../abnf_validators.dart';
import '../redirect_uri_policy.dart';
import '../value_objects/code_challenge.dart';

/// Represents a front-channel OAuth 2.1 authorization request.
///
/// This class compiles and validates parameters for the authorization URL.
/// It enforces OAuth 2.1 rules, including:
/// - Only authorization code flow is permitted (`response_type=code` is
///   enforced; implicit `response_type=token` and password grant are blocked).
/// - The redirect URI must not contain a fragment component (`#`).
/// - Parameter pollution is neutralized: duplicate parameter keys in the base
///   endpoint, custom parameters, or standard parameters are strictly rejected.
@immutable
class AuthRequest {
  /// The authorization server's endpoint.
  final String authorizationEndpoint;

  /// The client identifier.
  final String clientId;

  /// The client's optional redirection URI (may be omitted when the client has
  /// a single registered redirect URI per OAuth 2.1 Section 2.3.2).
  final Uri? redirectUri;

  /// The optional state parameter used to prevent CSRF.
  final String? state;

  /// The PKCE code challenge.
  final CodeChallenge codeChallenge;

  /// The optional scope.
  final String? scope;

  /// Additional custom query parameters.
  final Map<String, String> customParameters;

  /// Creates and validates an [AuthRequest].
  ///
  /// Throws [ArgumentError] if:
  /// - The [redirectUri] is provided and violates the OAuth 2.1 redirect URI
  ///   security policy (e.g. has a fragment component `#`).
  /// - [clientId], [state], [scope], or [customParameters] violate Appendix A
  ///   ABNF syntax.
  /// - There are duplicate parameter keys or collisions between standard
  ///   parameters, existing parameters in the [authorizationEndpoint], and
  ///   [customParameters].
  AuthRequest({
    required this.authorizationEndpoint,
    required this.clientId,
    required this.codeChallenge,
    this.redirectUri,
    this.state,
    this.scope,
    this.customParameters = const {},
  }) {
    // 1. Validate redirect URI against OAuth 2.1 redirect URI security policy
    if (redirectUri != null && !isAllowedRedirectUri(redirectUri!)) {
      throw ArgumentError.value(
        redirectUri,
        'redirectUri',
        'redirectUri must use https, loopback http, or a reverse-domain '
            'private-use scheme, and must not contain fragments or userinfo.',
      );
    }

    // 2. Enforce TLS and authority requirements on authorizationEndpoint
    final endpointUri = Uri.tryParse(authorizationEndpoint);
    if (endpointUri == null ||
        !isAllowedHttpEndpointUri(endpointUri, allowLoopbackHttp: false)) {
      throw ArgumentError.value(
        authorizationEndpoint,
        'authorizationEndpoint',
        'Security violation: authorizationEndpoint must be a valid https URI '
            'with a host and no fragment or userinfo. '
            'Got: "$authorizationEndpoint".',
      );
    }

    // 3. Enforce scope ABNF syntax: 1*( %x21 / %x23-5B / %x5D-7E )
    if (scope != null && !isValidScopeString(scope!)) {
      throw ArgumentError.value(
        scope,
        'scope',
        'Malformed scope: scope tokens must be non-empty and only contain '
            'characters in ranges %x21, %x23-5B, and %x5D-7E.',
      );
    }

    // 4. Enforce 1*VSCHAR syntax on client_id and state (ABNF range %x20-7E)
    if (!isValidVscharParam(clientId)) {
      throw ArgumentError.value(
        clientId,
        'clientId',
        'client_id must be non-empty, trimmed, and contain only printable '
            'ASCII characters (VSCHAR).',
      );
    }
    if (state != null && !isValidVscharParam(state!)) {
      throw ArgumentError.value(
        state,
        'state',
        'state must be non-empty, trimmed, and contain only printable '
            'ASCII characters (VSCHAR).',
      );
    }

    // Parse endpoint URI to analyze existing query parameters

    // Define standard keys to prevent custom parameter collisions
    final standardKeys = {
      'response_type',
      'client_id',
      'redirect_uri',
      'scope',
      'state',
      'code_challenge',
      'code_challenge_method',
    };

    // Track all keys seen to check for duplicate keys / parameter pollution
    final allKeys = <String>{};

    // 5. Analyze existing endpoint parameters
    endpointUri.queryParametersAll.forEach((key, values) {
      if (values.length > 1) {
        throw ArgumentError(
          'Parameter pollution detected: query parameter "$key" is defined '
          'multiple times in the authorizationEndpoint.',
        );
      }
      if (standardKeys.contains(key)) {
        throw ArgumentError(
          'Parameter collision: authorizationEndpoint contains standard '
          'OAuth 2.1 parameter "$key" which must be set via the constructor '
          'arguments.',
        );
      }
      allKeys.add(key);
    });

    // 6. Analyze standard parameters to be added
    final standardKeysToAdd = [
      'response_type',
      'client_id',
      if (redirectUri != null) 'redirect_uri',
      if (state != null) 'state',
      'code_challenge',
      'code_challenge_method',
      if (scope != null) 'scope',
    ];

    allKeys.addAll(standardKeysToAdd);

    // 7. Analyze custom parameters (Appendix A.16 param-name & 1*VSCHAR)
    customParameters.forEach((key, value) {
      if (!paramNameAbnfRegex.hasMatch(key)) {
        throw ArgumentError.value(
          key,
          'customParameters',
          'Custom parameter key "$key" violates Appendix A.16 param-name ABNF.',
        );
      }
      if (!isValidVscharParam(value)) {
        throw ArgumentError.value(
          value,
          'customParameters[$key]',
          'Custom parameter value for "$key" must be a non-empty, trimmed '
              'VSCHAR string.',
        );
      }
      if (standardKeys.contains(key)) {
        throw ArgumentError(
          'Custom parameter "$key" collides with a standard OAuth 2.1 '
          'parameter.',
        );
      }
      if (!allKeys.add(key)) {
        throw ArgumentError(
          'Parameter collision: custom parameter "$key" is already defined '
          'in the authorizationEndpoint.',
        );
      }
    });
  }

  /// Composes the final, absolute authorization request URI.
  Uri toUri() {
    final endpointUri = Uri.parse(authorizationEndpoint);

    // Start with existing parameters in the endpoint
    final queryParams = Map<String, String>.from(endpointUri.queryParameters);

    // Add standard parameters
    queryParams['response_type'] = 'code';
    queryParams['client_id'] = clientId;
    if (redirectUri != null) {
      queryParams['redirect_uri'] = redirectUri.toString();
    }
    if (state != null) {
      queryParams['state'] = state!;
    }
    queryParams['code_challenge'] = codeChallenge.value;
    queryParams['code_challenge_method'] = codeChallenge.method;

    if (scope != null) {
      queryParams['scope'] = scope!;
    }

    // Add custom parameters
    queryParams.addAll(customParameters);

    // Serialize query parameters manually to guarantee order/format.
    final queryBuffer = StringBuffer();

    queryParams.forEach((key, value) {
      if (queryBuffer.isNotEmpty) {
        queryBuffer.write('&');
      }
      queryBuffer.write(
        '${Uri.encodeQueryComponent(key)}=${Uri.encodeQueryComponent(value)}',
      );
    });

    return endpointUri.replace(query: queryBuffer.toString());
  }
}
