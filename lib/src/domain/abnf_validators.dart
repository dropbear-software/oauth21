/// Internal OAuth 2.1 Appendix A ABNF syntax regular expressions and validation
/// helpers shared across client and server domain components.
library;

/// Matches `1*VSCHAR` (`%x20-7E`): one or more printable ASCII characters.
final RegExp vscharRequiredRegex = RegExp(r'^[\x20-\x7E]+$');

/// Matches `*VSCHAR` (`%x20-7E`): zero or more printable ASCII characters.
final RegExp vscharOptionalRegex = RegExp(r'^[\x20-\x7E]*$');

/// Matches `1*NQCHAR` (`%x21 / %x23-5B / %x5D-7E`): one or more non-quote,
/// non-backslash, non-space printable ASCII characters (used for scope-token
/// and error_uri characters).
final RegExp nqcharRequiredRegex = RegExp(r'^[\x21\x23-\x5B\x5D-\x7E]+$');

/// Matches `1*NQSCHAR` (`%x20-21 / %x23-5B / %x5D-7E`): one or more non-quote,
/// non-backslash printable ASCII characters including space (used for `error`
/// and `error_description`).
final RegExp nqscharRequiredRegex = RegExp(r'^[\x20-\x21\x23-\x5B\x5D-\x7E]+$');

/// Matches OAuth 2.1 Section 4.1.1 / Appendix A.18 `code-verifier` and
/// `code-challenge` ABNF (`43*128unreserved`).
final RegExp codeVerifierAbnfRegex = RegExp(r'^[A-Za-z0-9\-._~]{43,128}$');

/// Matches HTTP Bearer `token68` syntax (`1*( ALPHA / DIGIT / "-" / "." / "_" /
/// "~" / "+" / "/" ) *"="`).
final RegExp token68Regex = RegExp(r'^[A-Za-z0-9\-._~+/]+=*$');

/// Returns `true` if [value] is non-empty, has no leading or trailing
/// whitespace, and matches `1*VSCHAR` (`%x20-7E`).
bool isValidVscharParam(String value) {
  return value.isNotEmpty &&
      value.trim() == value &&
      vscharRequiredRegex.hasMatch(value);
}

/// Returns `true` if [scope] is a valid space-delimited list of `1*NQCHAR`
/// scope tokens with no empty tokens (no leading, trailing, or consecutive
/// spaces).
///
/// When [allowEmpty] is `true`, an empty string `""` is also accepted.
bool isValidScopeString(String scope, {bool allowEmpty = false}) {
  if (scope.isEmpty) {
    return allowEmpty;
  }
  final tokens = scope.split(' ');
  for (final token in tokens) {
    if (token.isEmpty || !nqcharRequiredRegex.hasMatch(token)) {
      return false;
    }
  }
  return true;
}

/// Validates [scope] against `scope = scope-token *( SP scope-token )` and
/// returns the deduplicated set of scope tokens, or `null` if [scope] is
/// malformed.
Set<String>? parseAndDeduplicateScope(String scope) {
  if (!isValidScopeString(scope)) {
    return null;
  }
  return scope.split(' ').toSet();
}

/// Returns `true` if [value] matches `error-uri = 1*NQCHAR` (Appendix A.9) and
/// parses as a valid URI reference with a scheme (`URI-reference`).
bool isValidErrorUri(String value) {
  if (value.isEmpty || !nqcharRequiredRegex.hasMatch(value)) {
    return false;
  }
  final parsed = Uri.tryParse(value);
  return parsed != null && parsed.hasScheme;
}
