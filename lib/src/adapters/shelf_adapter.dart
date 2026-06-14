import 'dart:convert';
import 'package:shelf/shelf.dart' as shelf;
import '../domain/services/authorize_request_validator.dart';
import '../domain/services/token_request_handler.dart';

/// Handles validation of incoming parameters at the authorization endpoint.
///
/// - If the request is invalid and **non-redirectable**, returns a
///   `400 Bad Request` response.
/// - If the request is invalid and **redirectable**, redirects the user-agent
///   using `303 See Other` to the client's redirect URI with the error parameters.
/// - If the request is valid, invokes [onConsentRequired] to delegate
///   user authentication and consent.
Future<shelf.Response> handleAuthorizeRequest(
  shelf.Request request, {
  required AuthorizeRequestValidator validator,
  required Future<shelf.Response> Function(
    shelf.Request request,
    AuthorizeValidationResult result,
  )
  onConsentRequired,
}) async {
  // Collect query parameters supporting multi-value parameters for pollution checks.
  final params = request.requestedUri.queryParametersAll;

  final result = await validator.validate(params);

  if (!result.isValid) {
    if (result.isRedirectable && result.validatedRedirectUri != null) {
      final target = result.validatedRedirectUri!.replace(
        queryParameters: {
          ...result.validatedRedirectUri!.queryParameters,
          'error': result.errorCode!,
          'error_description': result.errorDescription!,
          if (result.state != null) 'state': result.state!,
        },
      );
      return shelf.Response.seeOther(target);
    } else {
      return shelf.Response.badRequest(
        body: jsonEncode({
          'error': result.errorCode,
          'error_description': result.errorDescription,
        }),
        headers: {'Content-Type': 'application/json'},
      );
    }
  }

  return onConsentRequired(request, result);
}

/// Redirects the user-agent back to the client redirect URI with the auth code.
///
/// Employs HTTP status code `303 See Other` and includes the mandatory `iss` parameter.
shelf.Response redirectWithAuthorizationCode({
  required Uri redirectUri,
  required String code,
  required String state,
  required String issuer,
}) {
  final target = redirectUri.replace(
    queryParameters: {
      ...redirectUri.queryParameters,
      'code': code,
      'state': state,
      'iss': issuer,
    },
  );
  return shelf.Response.seeOther(target);
}

/// Handles incoming POST token requests.
///
/// Form-decodes request bodies, extracts client credentials from headers,
/// validates transport security, and returns JSON responses conforming to specs.
Future<shelf.Response> handleTokenRequest(
  shelf.Request request, {
  required TokenRequestHandler handler,
  bool isHttps = true,
}) async {
  if (request.method != 'POST') {
    return shelf.Response.badRequest(
      body: jsonEncode({
        'error': 'invalid_request',
        'error_description': 'HTTP method must be POST.',
      }),
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
      },
    );
  }

  final contentType = request.headers['content-type'] ?? '';
  if (!contentType.contains('application/x-www-form-urlencoded')) {
    return shelf.Response.badRequest(
      body: jsonEncode({
        'error': 'invalid_request',
        'error_description':
            'Content-Type must be application/x-www-form-urlencoded.',
      }),
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
      },
    );
  }

  // 1. Defend against Heap-Space DoS (Max 10 KB allocation threshold)
  final contentLengthHeader = request.headers['content-length'];
  if (contentLengthHeader != null) {
    final length = int.tryParse(contentLengthHeader) ?? 0;
    if (length > 10240) {
      return shelf.Response.badRequest(
        body: jsonEncode({
          'error': 'invalid_request',
          'error_description': 'Payload too large.',
        }),
        headers: {'Content-Type': 'application/json'},
      );
    }
  }

  final bodyStr = await request.readAsString();

  if (bodyStr.length > 10240) {
    return shelf.Response.badRequest(
      body: jsonEncode({
        'error': 'invalid_request',
        'error_description': 'Payload too large.',
      }),
      headers: {'Content-Type': 'application/json'},
    );
  }

  // 2. Intercept Body Parameter Pollution before Map flattening
  final rawPairs = bodyStr.split('&');
  final seenKeys = <String>{};
  for (final pair in rawPairs) {
    if (pair.isEmpty) continue;
    final eqIndex = pair.indexOf('=');
    final key = eqIndex != -1
        ? Uri.decodeQueryComponent(pair.substring(0, eqIndex))
        : Uri.decodeQueryComponent(pair);

    if (!seenKeys.add(key)) {
      return shelf.Response.badRequest(
        body: jsonEncode({
          'error': 'invalid_request',
          'error_description': 'Duplicate parameters are prohibited.',
        }),
        headers: {'Content-Type': 'application/json'},
      );
    }
  }

  final body = Uri.splitQueryString(bodyStr);

  final authorizationHeader =
      request.headers['Authorization'] ?? request.headers['authorization'];

  final serverResponse = await handler.handle(
    body,
    authorizationHeader: authorizationHeader,
    isHttps: isHttps,
  );

  return shelf.Response(
    serverResponse.statusCode,
    body: jsonEncode(serverResponse.body),
    headers: serverResponse.headers,
  );
}
