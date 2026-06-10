import 'package:meta/meta.dart';
import '../value_objects/code_challenge.dart';

/// Represents a front-channel OAuth 2.1 authorization request.
///
/// This class compiles and validates parameters for the authorization URL.
/// It enforces OAuth 2.1 rules, including:
/// - Only authorization code flow is permitted (`response_type=code` is enforced;
///   implicit `response_type=token` and password grant are blocked).
/// - The redirect URI must not contain a fragment component (`#`).
/// - Parameter pollution is neutralized: duplicate parameter keys in the base endpoint,
///   custom parameters, or standard parameters are strictly rejected.
@immutable
class AuthRequest {
  /// The authorization server's endpoint.
  final String authorizationEndpoint;

  /// The client identifier.
  final String clientId;

  /// The client's redirection URI.
  final Uri redirectUri;

  /// The state parameter used to prevent CSRF.
  final String state;

  /// The PKCE code challenge.
  final CodeChallenge codeChallenge;

  /// The optional scope.
  final String? scope;

  /// Additional custom query parameters.
  final Map<String, String> customParameters;

  /// Creates and validates an [AuthRequest].
  ///
  /// Throws [ArgumentError] if:
  /// - The [redirectUri] has a fragment component (`#`).
  /// - There are duplicate parameter keys or collisions between standard parameters,
  ///   existing parameters in the [authorizationEndpoint], and [customParameters].
  AuthRequest({
    required this.authorizationEndpoint,
    required this.clientId,
    required this.redirectUri,
    required this.state,
    required this.codeChallenge,
    this.scope,
    this.customParameters = const {},
  }) {
    // 1. Validate redirect URI is absolute and does not contain a fragment
    if (!redirectUri.isAbsolute) {
      throw ArgumentError('Redirect URI must be an absolute URI.');
    }
    if (redirectUri.hasFragment) {
      throw ArgumentError(
        'Redirect URI must not contain a fragment component (#).',
      );
    }

    // 2. Enforce TLS requirements
    final endpointUri = Uri.parse(authorizationEndpoint);
    if (endpointUri.scheme != 'https') {
      throw ArgumentError(
        'Security violation: authorizationEndpoint must use the secure "https" scheme. Got: "$authorizationEndpoint".',
      );
    }

    final redirectScheme = redirectUri.scheme.toLowerCase();
    if (redirectScheme == 'http') {
      final host = redirectUri.host;
      final isLoopback =
          host == '127.0.0.1' || host == '::1' || host == 'localhost';
      if (!isLoopback) {
        throw ArgumentError(
          'Security violation: redirectUri must use the secure "https" scheme except for loopback interface redirect URIs. Got: "$redirectUri".',
        );
      }
    } else if (redirectScheme != 'https') {
      if (!redirectScheme.contains('.')) {
        throw ArgumentError(
          'Security violation: Private-use redirect URI scheme must contain a period character (.) '
          'to enforce reverse domain name naming conventions. Got scheme: "${redirectUri.scheme}".',
        );
      }
    }

    // 3. Enforce scope ABNF syntax: 1*( %x21 / %x23-5B / %x5D-7E )
    if (scope != null && scope!.trim().isNotEmpty) {
      final tokens = scope!.split(' ');
      final tokenRegex = RegExp(r'^[\x21\x23-\x5B\x5D-\x7E]+$');
      for (final token in tokens) {
        if (token.isEmpty) {
          throw ArgumentError(
            'Malformed scope: contains consecutive or leading/trailing space delimiters.',
          );
        }
        if (!tokenRegex.hasMatch(token)) {
          throw ArgumentError(
            'Malformed scope token "$token". Scope tokens must only contain characters in ranges %x21, %x23-5B, and %x5D-7E.',
          );
        }
      }
    }

    // 4. Enforce VSCHAR syntax on client_id and state (ABNF range %x20-7E)
    final vscharRegex = RegExp(r'^[\x20-\x7E]*$');
    final vscharRequiredRegex = RegExp(r'^[\x20-\x7E]+$');

    if (!vscharRegex.hasMatch(clientId)) {
      throw ArgumentError(
        'client_id contains invalid characters. Must contain only printable ASCII characters (VSCHAR).',
      );
    }
    if (!vscharRequiredRegex.hasMatch(state)) {
      throw ArgumentError(
        'state contains invalid characters or is empty. Must contain only printable ASCII characters (VSCHAR).',
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

    // 2. Analyze existing endpoint parameters
    endpointUri.queryParametersAll.forEach((key, values) {
      if (values.length > 1) {
        throw ArgumentError(
          'Parameter pollution detected: query parameter "$key" is defined '
          'multiple times in the authorizationEndpoint.',
        );
      }
      if (standardKeys.contains(key)) {
        throw ArgumentError(
          'Parameter collision: authorizationEndpoint contains standard OAuth 2.1 '
          'parameter "$key" which must be set via the constructor arguments.',
        );
      }
      allKeys.add(key);
    });

    // 3. Analyze standard parameters to be added
    final standardKeysToAdd = [
      'response_type',
      'client_id',
      'redirect_uri',
      'state',
      'code_challenge',
      'code_challenge_method',
      if (scope != null && scope!.isNotEmpty) 'scope',
    ];

    for (final key in standardKeysToAdd) {
      if (!allKeys.add(key)) {
        throw ArgumentError('Duplicate query parameter "$key" detected.');
      }
    }

    // 4. Analyze custom parameters
    customParameters.forEach((key, value) {
      if (standardKeys.contains(key)) {
        throw ArgumentError(
          'Custom parameter "$key" collides with a standard OAuth 2.1 parameter.',
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
    queryParams['redirect_uri'] = redirectUri.toString();
    queryParams['state'] = state;
    queryParams['code_challenge'] = codeChallenge.value;
    queryParams['code_challenge_method'] = codeChallenge.method;

    if (scope != null && scope!.isNotEmpty) {
      queryParams['scope'] = scope!;
    }

    // Add custom parameters
    queryParams.addAll(customParameters);

    // Omit parameters that do not have a value (empty or whitespace-only values)
    queryParams.removeWhere((key, value) => value.trim().isEmpty);

    // Serialize query parameters manually to guarantee order/format,
    // and perform one last sanity check for duplicates.
    final queryBuffer = StringBuffer();
    final keysSeen = <String>{};

    queryParams.forEach((key, value) {
      if (!keysSeen.add(key)) {
        throw StateError(
          'Duplicate parameter key detected during serialization: $key',
        );
      }
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
