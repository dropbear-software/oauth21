import 'package:http/http.dart' as http;
import '../domain/ports/oauth_http_client.dart';

/// Implementation of the [OAuthHttpClient] port using `package:http`.
class HttpAdapter implements OAuthHttpClient {
  final http.Client _client;

  /// Creates a new [HttpAdapter] wrapping the provided `package:http` [http.Client].
  HttpAdapter(this._client);

  @override
  Future<OAuthHttpResponse> post(
    Uri url, {
    required Map<String, String> body,
    Map<String, String> headers = const {},
  }) async {
    if (!url.isScheme('https')) {
      throw ArgumentError(
        'Security violation: Token endpoint must use HTTPS channel security. Got "$url".',
      );
    }

    final mergedHeaders = Map<String, String>.from(headers);

    // Automatically set the Content-Type header to form-urlencoded if not specified.
    final hasContentType = mergedHeaders.keys.any(
      (k) => k.toLowerCase() == 'content-type',
    );
    if (!hasContentType) {
      mergedHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
    }

    final response = await _client.post(
      url,
      headers: mergedHeaders,
      body: body,
    );

    return OAuthHttpResponse(
      statusCode: response.statusCode,
      body: response.body,
      headers: response.headers,
    );
  }
}
