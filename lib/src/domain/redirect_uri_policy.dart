/// Internal URI and transport security policy helpers for OAuth 2.1.
///
/// Centralizes loopback host checks, HTTP(S) endpoint validation, and redirect
/// URI validation across client and server domain components.
library;

final RegExp _reverseDomainSchemePattern = RegExp(
  r'^[a-z0-9]+(\.[a-z0-9-]+)+$',
);

/// Returns `true` if [host] is an exact loopback address (`localhost`,
/// `127.0.0.1`, `::1`, or `[::1]`).
bool isLoopbackHost(String host) {
  final normalized = host.toLowerCase();
  return normalized == 'localhost' ||
      normalized == '127.0.0.1' ||
      normalized == '::1' ||
      normalized == '[::1]';
}

/// Returns `true` if [uri] is a valid OAuth 2.1 HTTP(S) endpoint URI.
///
/// Requires:
/// - No URI fragment (`!uri.hasFragment`)
/// - A non-empty authority/host (`uri.hasAuthority && uri.host.isNotEmpty`)
/// - No userinfo credentials (`uri.userInfo.isEmpty`)
/// - `https` scheme, or `http` scheme on a loopback host when
///   [allowLoopbackHttp] is `true`.
bool isAllowedHttpEndpointUri(Uri uri, {bool allowLoopbackHttp = true}) {
  if (uri.hasFragment ||
      !uri.hasAuthority ||
      uri.host.isEmpty ||
      uri.userInfo.isNotEmpty) {
    return false;
  }
  final scheme = uri.scheme.toLowerCase();
  if (scheme == 'https') {
    return true;
  }
  if (allowLoopbackHttp && scheme == 'http' && isLoopbackHost(uri.host)) {
    return true;
  }
  return false;
}

/// Returns `true` if [uri] is an allowed OAuth 2.1 redirect URI.
///
/// Per `draft-ietf-oauth-v2-1-17.txt` Sections 1.5, 7.13, and 8.4.3, allowed
/// redirect URIs must have a scheme, must not contain a fragment or userinfo,
/// and must use one of:
/// - `https` with a non-empty host
/// - `http` with an exact loopback host (`localhost`, `127.0.0.1`, `::1`, `[::1]`)
/// - A reverse-domain private-use URI scheme matching `^[a-z0-9]+(\.[a-z0-9-]+)+$`
bool isAllowedRedirectUri(Uri uri) {
  if (!uri.hasScheme || uri.hasFragment || uri.userInfo.isNotEmpty) {
    return false;
  }
  final scheme = uri.scheme.toLowerCase();
  if (scheme == 'https') {
    return uri.hasAuthority && uri.host.isNotEmpty;
  }
  if (scheme == 'http') {
    return uri.hasAuthority && uri.host.isNotEmpty && isLoopbackHost(uri.host);
  }
  return _reverseDomainSchemePattern.hasMatch(scheme);
}
