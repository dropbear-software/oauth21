/// Internal URI and transport security policy helpers for OAuth 2.1.
///
/// Centralizes loopback host checks, HTTP(S) endpoint validation, and redirect
/// URI validation across client and server domain components.
library;

import 'abnf_validators.dart';

final RegExp _reverseDomainSchemePattern = RegExp(
  r'^[a-z0-9]+(\.[a-z0-9-]+)+$',
);

const Set<String> _reservedAuthorizationResponseKeys = {
  'code',
  'state',
  'iss',
  'error',
  'error_description',
  'error_uri',
};

/// Returns `true` if [host] is an exact loopback address (`localhost`,
/// `127.0.0.1`, `::1`, or `[::1]`).
bool isLoopbackHost(String host) {
  final normalized = host.toLowerCase();
  return normalized == 'localhost' ||
      normalized == '127.0.0.1' ||
      normalized == '::1' ||
      normalized == '[::1]';
}

/// Returns `true` if [uri] uses the `http` scheme on a valid loopback host
/// (`localhost`, `127.0.0.1`, `::1`, or `[::1]`) with no userinfo or fragment.
bool isLoopbackHttpUri(Uri uri) {
  return uri.hasScheme &&
      uri.scheme.toLowerCase() == 'http' &&
      !uri.hasFragment &&
      uri.hasAuthority &&
      uri.host.isNotEmpty &&
      uri.userInfo.isEmpty &&
      isLoopbackHost(uri.host);
}

/// Returns `true` if [value] is a valid OAuth 2.1 Section 4.1.2 / Section
/// 7.15.1 (`RFC 9207`) authorization server issuer URL (`iss`).
///
/// Requires:
/// - `1*VSCHAR` syntax with no leading or trailing whitespace
/// - Valid HTTP(S) endpoint URI (`https` scheme, or loopback `http` when
///   [allowLoopbackHttp] is `true`) with a non-empty host and no userinfo
/// - No query component (`!uri.hasQuery && !value.contains('?')`)
/// - No fragment component (`!uri.hasFragment && !value.contains('#')`)
bool isValidIssuerUri(String value, {bool allowLoopbackHttp = false}) {
  if (!isValidVscharParam(value) ||
      value.contains('?') ||
      value.contains('#')) {
    return false;
  }
  final uri = Uri.tryParse(value);
  return uri != null &&
      !uri.hasQuery &&
      !uri.hasFragment &&
      isAllowedHttpEndpointUri(uri, allowLoopbackHttp: allowLoopbackHttp);
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
/// - `http` with an exact loopback host (`localhost`, `127.0.0.1`, `::1`,
///   `[::1]`)
/// - A reverse-domain private-use URI scheme matching
///   `^[a-z0-9]+(\.[a-z0-9-]+)+$`
bool isAllowedRedirectUri(Uri uri) {
  if (!uri.hasScheme || uri.hasFragment || uri.userInfo.isNotEmpty) {
    return false;
  }
  if (uri.pathSegments.any(
    (segment) =>
        segment == '.' ||
        segment == '..' ||
        segment.split('/').any((part) => part == '.' || part == '..'),
  )) {
    return false;
  }
  if (uri.hasQuery) {
    try {
      final queryParamsAll = uri.queryParametersAll;
      for (final entry in queryParamsAll.entries) {
        if (entry.value.length > 1 ||
            _reservedAuthorizationResponseKeys.contains(entry.key)) {
          return false;
        }
      }
    } on Object catch (_) {
      return false;
    }
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
