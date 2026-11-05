import 'package:meta/meta.dart';

import '../abnf_validators.dart';
import '../entities/access_token.dart';
import '../ports/crypto_service.dart';
import '../ports/token_repository.dart';

/// Represents the result of validating an incoming Bearer token request at a
/// resource server endpoint (OAuth 2.1 Section 5).
///
/// This is a sealed hierarchy with two outcomes:
/// - [BearerTokenValid]: The bearer token is valid and satisfies the required
///   scopes.
/// - [BearerTokenInvalid]: The request failed authentication or authorization.
@immutable
sealed class BearerValidationResult {
  /// Creates a [BearerValidationResult].
  const BearerValidationResult();
}

/// Represents a successfully validated Bearer token request.
@immutable
final class BearerTokenValid extends BearerValidationResult {
  /// The validated [AccessToken].
  final AccessToken accessToken;

  /// Creates a successful [BearerTokenValid] result for [accessToken].
  const BearerTokenValid(this.accessToken);
}

/// Represents a failed Bearer token validation result.
@immutable
final class BearerTokenInvalid extends BearerValidationResult {
  /// The HTTP error status code (`400`, `401`, or `403`).
  final int statusCode;

  /// HTTP response headers to include on error responses (such as
  /// `WWW-Authenticate`, `Cache-Control`, `Pragma`, and `Content-Type`).
  final Map<String, String> headers;

  /// The OAuth 2.1 bearer error code (`invalid_request`, `invalid_token`, or
  /// `insufficient_scope`), or `null` when the request lacked authentication
  /// credentials (Section 5.3.1).
  final String? errorCode;

  /// Human-readable description of the error, if any.
  final String? errorDescription;

  /// Creates a failed [BearerTokenInvalid] result with the specified HTTP
  /// [statusCode], [headers], and optional [errorCode] / [errorDescription].
  const BearerTokenInvalid({
    required this.statusCode,
    required this.headers,
    this.errorCode,
    this.errorDescription,
  });
}

/// Validates Bearer access tokens presented to resource server endpoints in
/// accordance with OAuth 2.1 Section 5.
class BearerTokenValidator {
  static final RegExp _bearerSchemePrefixRegex = RegExp(
    r'^[Bb][Ee][Aa][Rr][Ee][Rr](?:\s+|$)',
  );

  /// Repository used to look up stored access tokens by hash.
  final TokenRepository tokenRepository;

  /// Cryptographic service used to hash raw bearer tokens before lookup.
  final CryptoService cryptoService;

  /// Optional protection space (`realm`) included in `WWW-Authenticate`
  /// challenge headers.
  final String? realm;

  /// Creates a [BearerTokenValidator].
  ///
  /// Throws [ArgumentError] if [realm] is provided and violates `NQSCHAR` ABNF.
  BearerTokenValidator({
    required this.tokenRepository,
    required this.cryptoService,
    this.realm,
  }) {
    if (realm != null && !nqscharRequiredRegex.hasMatch(realm!)) {
      throw ArgumentError.value(
        realm,
        'realm',
        'realm must be a non-empty string conforming to NQSCHAR ABNF.',
      );
    }
  }

  String _buildWwwAuthenticate({
    String? errorCode,
    String? errorDescription,
    String? scope,
  }) {
    final attributes = <String>[
      if (realm != null) 'realm="$realm"',
      if (errorCode != null) 'error="$errorCode"',
      if (errorDescription != null) 'error_description="$errorDescription"',
      if (scope != null) 'scope="$scope"',
    ];
    if (attributes.isEmpty) {
      return 'Bearer';
    }
    return 'Bearer ${attributes.join(', ')}';
  }

  Map<String, String> _errorHeaders({
    required String wwwAuthenticate,
    required bool hasBody,
  }) {
    return {
      'WWW-Authenticate': wwwAuthenticate,
      if (hasBody) 'Content-Type': 'application/json;charset=UTF-8',
      'Cache-Control': 'no-store',
      'Pragma': 'no-cache',
    };
  }

  BearerTokenInvalid _bearerError({
    required int statusCode,
    required String errorCode,
    required String errorDescription,
    String? scope,
  }) {
    return BearerTokenInvalid(
      statusCode: statusCode,
      errorCode: errorCode,
      errorDescription: errorDescription,
      headers: _errorHeaders(
        wwwAuthenticate: _buildWwwAuthenticate(
          errorCode: errorCode,
          errorDescription: errorDescription,
          scope: scope,
        ),
        hasBody: true,
      ),
    );
  }

  /// Validates an incoming resource request's `Authorization` header(s) and
  /// scope requirements.
  ///
  /// - Requires [isHttps] to be `true`.
  /// - Rejects multiple `Authorization` headers (`400 invalid_request`).
  /// - Returns `401 Unauthorized` with a bare `WWW-Authenticate: Bearer`
  ///   challenge (and no `error` code) when the `Authorization` header is
  ///   missing, empty, or uses a non-`Bearer` authentication scheme (OAuth 2.1
  ///   Section 5.3.1).
  /// - Validates `token68` ABNF syntax, hashes the token with [cryptoService],
  ///   and verifies the stored [AccessToken] is active (`401 invalid_token`).
  /// - Verifies all [requiredScopes] are present on the token
  ///   (`403 insufficient_scope`).
  Future<BearerValidationResult> validate({
    String? authorizationHeader,
    List<String>? authorizationHeaders,
    Set<String> requiredScopes = const {},
    bool isHttps = false,
  }) async {
    for (final scope in requiredScopes) {
      if (!nqcharRequiredRegex.hasMatch(scope)) {
        throw ArgumentError.value(
          scope,
          'requiredScopes',
          'Each required scope token must conform to NQCHAR ABNF.',
        );
      }
    }

    // 1. Enforce transport security (OAuth 2.1 Section 5.1.1 / 1.5)
    if (!isHttps) {
      return const BearerTokenInvalid(
        statusCode: 400,
        errorCode: 'invalid_request',
        errorDescription: 'HTTPS is required for resource server endpoints.',
        headers: {
          'Content-Type': 'application/json;charset=UTF-8',
          'Cache-Control': 'no-store',
          'Pragma': 'no-cache',
        },
      );
    }

    // 2. Reject multiple Authorization headers (OAuth 2.1 Section 5.2 / 5.3.2)
    if (authorizationHeaders != null && authorizationHeaders.length > 1) {
      return _bearerError(
        statusCode: 400,
        errorCode: 'invalid_request',
        errorDescription: 'Multiple Authorization headers are not allowed.',
      );
    }

    final effectiveHeader =
        (authorizationHeaders != null && authorizationHeaders.length == 1)
        ? authorizationHeaders.first
        : authorizationHeader;

    // 3. Missing, empty, or non-Bearer Authorization header -> 401 without error code (Section 5.3.1)
    if (effectiveHeader == null ||
        effectiveHeader.trim().isEmpty ||
        !_bearerSchemePrefixRegex.hasMatch(effectiveHeader.trim())) {
      return BearerTokenInvalid(
        statusCode: 401,
        headers: _errorHeaders(
          wwwAuthenticate: _buildWwwAuthenticate(),
          hasBody: false,
        ),
      );
    }

    // 4. Extract raw token and enforce token68 ABNF (Section 5.1.1)
    final rawToken = effectiveHeader.trim().substring(6).trim();
    if (rawToken.isEmpty || !token68Regex.hasMatch(rawToken)) {
      return _bearerError(
        statusCode: 401,
        errorCode: 'invalid_token',
        errorDescription: 'Malformed bearer token.',
      );
    }

    // 5. Hash and look up access token
    final tokenHash = cryptoService.hashString(rawToken);
    final accessToken = await tokenRepository.findAccessTokenByHash(tokenHash);
    if (accessToken == null || !accessToken.isValid) {
      return _bearerError(
        statusCode: 401,
        errorCode: 'invalid_token',
        errorDescription: 'The access token is invalid, expired, or revoked.',
      );
    }

    // 6. Verify required scopes (Section 5.3.2: 403 insufficient_scope)
    if (requiredScopes.isNotEmpty) {
      final grantedScopes =
          accessToken.scope == null || accessToken.scope!.trim().isEmpty
          ? const <String>{}
          : accessToken.scope!.trim().split(RegExp(r'\s+')).toSet();

      if (!grantedScopes.containsAll(requiredScopes)) {
        return _bearerError(
          statusCode: 403,
          errorCode: 'insufficient_scope',
          errorDescription:
              'The request requires higher privileges than provided by the access token.',
          scope: requiredScopes.join(' '),
        );
      }
    }

    return BearerTokenValid(accessToken);
  }
}
