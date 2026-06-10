/// Represents parsed callback redirect parameters from the authorization server.
class OAuthRedirectParameters {
  /// The authorization code issued by the server, if successful.
  final String? code;

  /// The state parameter returned by the server, which must match the original state.
  final String? state;

  /// The issuer identifier returned by the server, used to prevent mix-up attacks.
  final String? iss;

  /// The error code returned by the server, if the authorization failed.
  final String? error;

  /// The error description returned by the server, if the authorization failed.
  final String? errorDescription;

  /// Creates a new [OAuthRedirectParameters] instance.
  const OAuthRedirectParameters({
    this.code,
    this.state,
    this.iss,
    this.error,
    this.errorDescription,
  });
}

/// Framework-agnostic interface for parsing OAuth 2.1 redirect callback requests.
abstract interface class OAuthRequestParser {
  /// Parses the redirect request URI into standard parameters.
  ///
  /// Should throw [ArgumentError] if parameter pollution is detected.
  OAuthRedirectParameters parseRedirect(Uri redirectUrl);
}

/// Default implementation of [OAuthRequestParser] that parses standard [Uri] query parameters.
class DefaultRequestParser implements OAuthRequestParser {
  /// Creates a new [DefaultRequestParser] instance.
  const DefaultRequestParser();

  @override
  OAuthRedirectParameters parseRedirect(Uri redirectUrl) {
    final queryParams = redirectUrl.queryParametersAll;

    // Neutralize parameter pollution: reject if any query parameter appears more than once.
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

    // Reject structural dead-ends (neither code nor error present)
    if (code == null && error == null) {
      throw ArgumentError(
        'Security violation: callback redirect contains neither "code" nor "error" parameters.',
      );
    }

    // ABNF character validation:
    // VSCHAR = %x20-7E
    final vscharRequiredRegex = RegExp(r'^[\x20-\x7E]+$');
    // NQSCHAR = %x20-21 / %x23-5B / %x5D-7E
    final nqscharRegex = RegExp(r'^[\x20-\x21\x23-\x5B\x5D-\x7E]+$');

    if (code != null && !vscharRequiredRegex.hasMatch(code)) {
      throw FormatException(
        'Security violation: "code" parameter contains characters violating ABNF VSCHAR syntax.',
      );
    }

    if (state != null && !vscharRequiredRegex.hasMatch(state)) {
      throw FormatException(
        'Security violation: "state" parameter contains characters violating ABNF VSCHAR syntax.',
      );
    }

    if (error != null && !nqscharRegex.hasMatch(error)) {
      throw FormatException(
        'Security violation: "error" parameter contains characters violating ABNF NQSCHAR syntax.',
      );
    }

    if (errorDescription != null && !nqscharRegex.hasMatch(errorDescription)) {
      throw FormatException(
        'Security violation: "error_description" parameter contains characters violating ABNF NQSCHAR syntax.',
      );
    }

    return OAuthRedirectParameters(
      code: code,
      state: state,
      iss: iss,
      error: error,
      errorDescription: errorDescription,
    );
  }
}
