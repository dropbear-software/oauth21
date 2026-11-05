import 'dart:convert';
import 'dart:typed_data';
import 'package:shelf/shelf.dart' as shelf;
import '../domain/entities/access_token.dart';
import '../domain/services/authorize_request_validator.dart';
import '../domain/services/bearer_token_validator.dart';
import '../domain/services/token_request_handler.dart';

/// Request context key storing the authenticated [AccessToken] attached by
/// [bearerAuthenticationMiddleware].
const String oauthAccessTokenContextKey = 'oauth21.access_token';

/// Retrieves the authenticated [AccessToken] attached to [request] by
/// [bearerAuthenticationMiddleware], or `null` if none is present.
AccessToken? getAccessTokenFromContext(shelf.Request request) =>
    request.context[oauthAccessTokenContextKey] as AccessToken?;

const Map<String, String> _tokenErrorHeaders = {
  'Content-Type': 'application/json;charset=UTF-8',
  'Cache-Control': 'no-store',
  'Pragma': 'no-cache',
};

shelf.Response _tokenBadRequest(String description) {
  return shelf.Response.badRequest(
    body: jsonEncode({
      'error': 'invalid_request',
      'error_description': description,
    }),
    headers: _tokenErrorHeaders,
  );
}

/// Handles validation of incoming parameters at the authorization endpoint.
///
/// - If the HTTP method is not `GET`, returns `405 Method Not Allowed`.
/// - If the request is invalid and **non-redirectable**, returns a
///   `400 Bad Request` response.
/// - If the request is invalid and **redirectable**, redirects the user-agent
///   using `303 See Other` to the client's redirect URI with the error
///   parameters and mandatory `iss` parameter.
/// - If the request is valid, invokes [onConsentRequired] to delegate
///   user authentication and consent.
Future<shelf.Response> handleAuthorizeRequest(
  shelf.Request request, {
  required AuthorizeRequestValidator validator,
  required String issuer,
  required Future<shelf.Response> Function(
    shelf.Request request,
    AuthorizeValidationResult result,
  )
  onConsentRequired,
}) async {
  if (request.method != 'GET') {
    return shelf.Response(
      405,
      body: jsonEncode({
        'error': 'invalid_request',
        'error_description': 'HTTP method must be GET.',
      }),
      headers: {
        'Allow': 'GET',
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
      },
    );
  }

  // Collect query parameters supporting multi-value parameters for pollution checks.
  final params = request.requestedUri.queryParametersAll;

  final result = await validator.validate(params);

  if (!result.isValid) {
    if (result.isRedirectable && result.validatedRedirectUri != null) {
      return redirectWithAuthorizationError(
        redirectUri: result.validatedRedirectUri!,
        error: result.errorCode!,
        issuer: issuer,
        errorDescription: result.errorDescription,
        state: result.state,
      );
    } else {
      return shelf.Response.badRequest(
        body: jsonEncode({
          'error': result.errorCode,
          'error_description': result.errorDescription,
        }),
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          'Pragma': 'no-cache',
        },
      );
    }
  }

  return onConsentRequired(request, result);
}

/// Redirects the user-agent back to the client redirect URI with the auth code.
///
/// Employs HTTP status code `303 See Other` and includes the mandatory `iss`
/// parameter and optional [state] parameter.
shelf.Response redirectWithAuthorizationCode({
  required Uri redirectUri,
  required String code,
  required String issuer,
  String? state,
}) {
  return _redirectSeeOther(
    redirectUri: redirectUri,
    responseParams: {'code': code},
    issuer: issuer,
    state: state,
  );
}

/// Redirects the user-agent back to the client redirect URI with an OAuth 2.1
/// authorization error response.
///
/// Employs HTTP status code `303 See Other` and includes `error`, optional
/// [errorDescription], optional [state], and mandatory [issuer] (`iss`).
shelf.Response redirectWithAuthorizationError({
  required Uri redirectUri,
  required String error,
  required String issuer,
  String? errorDescription,
  String? state,
}) {
  return _redirectSeeOther(
    redirectUri: redirectUri,
    responseParams: {
      'error': error,
      if (errorDescription != null && errorDescription.isNotEmpty)
        'error_description': errorDescription,
    },
    issuer: issuer,
    state: state,
  );
}

shelf.Response _redirectSeeOther({
  required Uri redirectUri,
  required Map<String, String> responseParams,
  required String issuer,
  String? state,
}) {
  final target = redirectUri.replace(
    queryParameters: {
      ...redirectUri.queryParameters,
      ...responseParams,
      if (state != null && state.isNotEmpty) 'state': state,
      'iss': issuer,
    },
  );
  return shelf.Response.seeOther(
    target,
    headers: {'Cache-Control': 'no-store', 'Pragma': 'no-cache'},
  );
}

/// Handles incoming POST token requests.
///
/// Form-decodes request bodies, extracts client credentials from headers,
/// validates transport security, and returns JSON responses conforming to specs.
Future<shelf.Response> handleTokenRequest(
  shelf.Request request, {
  required TokenRequestHandler handler,
  bool isHttps = false,
}) async {
  if (request.method != 'POST') {
    return _tokenBadRequest('HTTP method must be POST.');
  }

  final contentType = request.headers['content-type'] ?? '';
  if (!contentType.contains('application/x-www-form-urlencoded')) {
    return _tokenBadRequest(
      'Content-Type must be application/x-www-form-urlencoded.',
    );
  }

  // 1. Defend against Heap-Space DoS (Max 10 KB allocation threshold)
  const maxBodyBytes = 10240;
  final contentLengthHeader = request.headers['content-length'];
  if (contentLengthHeader != null) {
    final length = int.tryParse(contentLengthHeader.trim());
    if (length == null || length < 0) {
      return _tokenBadRequest('Invalid Content-Length header.');
    }
    if (length > maxBodyBytes) {
      return _tokenBadRequest('Payload too large.');
    }
  }

  final bodyBytes = BytesBuilder(copy: false);
  await for (final chunk in request.read()) {
    if (bodyBytes.length + chunk.length > maxBodyBytes) {
      return _tokenBadRequest('Payload too large.');
    }
    bodyBytes.add(chunk);
  }

  final String bodyStr;
  final Map<String, String> body;
  try {
    bodyStr = utf8.decode(bodyBytes.takeBytes());
    if (RegExp('%(?![0-9a-fA-F]{2})').hasMatch(bodyStr)) {
      return _tokenBadRequest('Malformed request body.');
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
        return _tokenBadRequest('Duplicate parameters are prohibited.');
      }
    }

    body = Uri.splitQueryString(bodyStr);
  } on FormatException catch (_) {
    return _tokenBadRequest('Malformed request body.');
  }

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

/// Shelf middleware that protects resource server endpoints using
/// [BearerTokenValidator] in accordance with OAuth 2.1 Section 5.
///
/// - Validates only the HTTP `Authorization` header (never reading or
///   consuming the request body stream or honoring URI query tokens).
/// - On failure, returns the appropriate `400`, `401`, or `403` response with
///   `WWW-Authenticate` and `Cache-Control: no-store` headers.
/// - On success, attaches the validated [AccessToken] to `request.context`
///   under [oauthAccessTokenContextKey] (retrievable via
///   [getAccessTokenFromContext]) and forwards the request to the inner handler.
shelf.Middleware bearerAuthenticationMiddleware({
  required BearerTokenValidator validator,
  Set<String> requiredScopes = const {},
  bool isHttps = false,
}) {
  return (shelf.Handler innerHandler) {
    return (shelf.Request request) async {
      final result = await validator.validate(
        authorizationHeader: request.headers['authorization'],
        authorizationHeaders: request.headersAll['authorization'],
        requiredScopes: requiredScopes,
        isHttps: isHttps,
      );

      if (!result.isValid) {
        final body = result.errorCode != null
            ? jsonEncode({
                'error': result.errorCode,
                if (result.errorDescription != null)
                  'error_description': result.errorDescription,
              })
            : null;
        return shelf.Response(
          result.statusCode,
          body: body,
          headers: result.headers,
        );
      }

      final updatedRequest = request.change(
        context: {oauthAccessTokenContextKey: result.accessToken!},
      );
      return innerHandler(updatedRequest);
    };
  };
}
