import 'dart:async';

/// A simple HTTP client interface for executing out-of-band requests
/// to the OAuth token endpoint.
///
/// This port decouples the core domain from concrete HTTP client implementations,
/// allowing the domain to run in any platform context (shelf, Flutter, CLI, web, etc.).
abstract interface class OAuthHttpClient {
  /// Executes an HTTP POST request to the specified [url] with form-urlencoded data.
  ///
  /// The [headers] must be included in the request.
  /// The [body] represents query/form-urlencoded parameters.
  Future<OAuthHttpResponse> post(
    Uri url, {
    required Map<String, String> body,
    Map<String, String> headers = const {},
  });
}

/// Represents a simplified HTTP response returned by [OAuthHttpClient].
class OAuthHttpResponse {
  /// The response status code.
  final int statusCode;

  /// The response body as a string.
  final String body;

  /// The response headers.
  final Map<String, String> headers;

  /// Creates a new [OAuthHttpResponse] instance.
  const OAuthHttpResponse({
    required this.statusCode,
    required this.body,
    required this.headers,
  });
}
