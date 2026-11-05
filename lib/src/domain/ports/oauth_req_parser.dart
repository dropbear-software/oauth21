import '../abnf_validators.dart';
import '../redirect_uri_policy.dart';

/// Represents parsed callback redirect parameters from the authorization
/// server.
class OAuthRedirectParameters {
  /// The authorization code issued by the server, if successful.
  final String? code;

  /// The state parameter returned by the server, which must match the original
  /// state.
  final String? state;

  /// The issuer identifier returned by the server, used to prevent mix-up
  /// attacks.
  final String? iss;

  /// The error code returned by the server, if the authorization failed.
  final String? error;

  /// The error description returned by the server, if the authorization failed.
  final String? errorDescription;

  /// The error URI returned by the server, if the authorization failed.
  final String? errorUri;

  /// Creates a new [OAuthRedirectParameters] instance.
  const OAuthRedirectParameters({
    this.code,
    this.state,
    this.iss,
    this.error,
    this.errorDescription,
    this.errorUri,
  });
}

/// Framework-agnostic interface for parsing OAuth 2.1 redirect callback
/// requests.
abstract interface class OAuthRequestParser {
  /// Parses the redirect request URI into standard parameters.
  ///
  /// Should throw [ArgumentError] if parameter pollution is detected.
  OAuthRedirectParameters parseRedirect(Uri redirectUrl);
}

/// Default implementation of [OAuthRequestParser] that parses standard [Uri]
/// query parameters.
class DefaultRequestParser implements OAuthRequestParser {
  /// Creates a new [DefaultRequestParser] instance.
  const DefaultRequestParser();

  @override
  OAuthRedirectParameters parseRedirect(Uri redirectUrl) {
    final queryParams = redirectUrl.queryParametersAll;

    // Neutralize parameter pollution: reject if any query parameter appears
    // more than once.
    queryParams.forEach((key, values) {
      if (values.length > 1) {
        throw ArgumentError(
          'Security violation: Parameter pollution detected. '
          'Query parameter "$key" occurs multiple times in the callback URL.',
        );
      }
    });

    final params = redirectUrl.queryParameters;

    // Treat empty parameters as omitted (null)
    String? getParam(String key) {
      final value = params[key];
      return (value == null || value.isEmpty) ? null : value;
    }

    final code = getParam('code');
    final state = getParam('state');
    final iss = getParam('iss');
    final error = getParam('error');
    final errorDescription = getParam('error_description');
    final errorUri = getParam('error_uri');

    // Reject structural dead-ends (neither code nor error present)
    if (code == null && error == null) {
      throw ArgumentError(
        'Security violation: callback redirect contains neither "code" nor '
        '"error" parameters.',
      );
    }

    // Reject ambiguous callbacks containing both code and error
    if (code != null && error != null) {
      throw ArgumentError(
        'Security violation: callback redirect cannot contain both "code" and '
        '"error" parameters.',
      );
    }

    if (code != null && !vscharRequiredRegex.hasMatch(code)) {
      throw FormatException(
        'Security violation: "code" parameter contains characters violating '
        'ABNF VSCHAR syntax.',
      );
    }

    if (state != null && !vscharRequiredRegex.hasMatch(state)) {
      throw FormatException(
        'Security violation: "state" parameter contains characters violating '
        'ABNF VSCHAR syntax.',
      );
    }

    if (iss != null && !isValidIssuerUri(iss, allowLoopbackHttp: true)) {
      throw FormatException(
        'Security violation: "iss" parameter must be a valid issuer URL '
        'with no query or fragment components.',
      );
    }

    if (error != null && !nqscharRequiredRegex.hasMatch(error)) {
      throw FormatException(
        'Security violation: "error" parameter contains characters violating '
        'ABNF NQSCHAR syntax.',
      );
    }

    if (errorDescription != null &&
        !nqscharRequiredRegex.hasMatch(errorDescription)) {
      throw FormatException(
        'Security violation: "error_description" parameter contains '
        'characters violating ABNF NQSCHAR syntax.',
      );
    }

    if (errorUri != null && !isValidErrorUri(errorUri)) {
      throw FormatException(
        'Security violation: "error_uri" parameter violates ABNF NQCHAR or '
        'URI syntax.',
      );
    }

    return OAuthRedirectParameters(
      code: code,
      state: state,
      iss: iss,
      error: error,
      errorDescription: errorDescription,
      errorUri: errorUri,
    );
  }
}
