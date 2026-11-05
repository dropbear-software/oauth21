import 'package:http/http.dart' as http;
import '../domain/ports/oauth_http_client.dart';
import '../domain/redirect_uri_policy.dart';

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
    // 1. Resolve compliance-safe TLS boundaries (Allow loopback HTTP exceptions)
    if (!isAllowedHttpEndpointUri(url)) {
      throw ArgumentError.value(
        url,
        'url',
        'Security violation: Token endpoint must use HTTPS channel security '
            '(or loopback HTTP) with a valid host and no userinfo or fragment. '
            'Got "$url".',
      );
    }

    // 2. Prevent Case-Sensitive Header Duplication via downcased normalization
    final mergedHeaders = <String, String>{};
    headers.forEach((key, value) {
      mergedHeaders[key.toLowerCase()] = value;
    });

    // Ensure downcased Content-Type is bounded properly
    if (!mergedHeaders.containsKey('content-type')) {
      mergedHeaders['content-type'] = 'application/x-www-form-urlencoded';
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
