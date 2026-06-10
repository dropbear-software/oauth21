import 'dart:convert';
import 'package:meta/meta.dart';

/// Represents the result of an OAuth 2.1 token exchange request.
///
/// This is a sealed class that is split into [TokenSuccess] and [TokenError].
@immutable
sealed class TokenResult {
  const TokenResult();

  /// Parses a token endpoint HTTP response.
  ///
  /// Throws [ArgumentError] if the mandatory `Cache-Control: no-store` header is missing.
  /// Throws [FormatException] if the body is not valid JSON or lacks mandatory parameters.
  factory TokenResult.fromResponse({
    required String body,
    required Map<String, String> headers,
  }) {
    // 1. Enforce Response Caching Guardrails
    final cacheControl = headers.entries
        .firstWhere(
          (e) => e.key.toLowerCase() == 'cache-control',
          orElse: () => const MapEntry('', ''),
        )
        .value;

    final directives = cacheControl
        .toLowerCase()
        .split(',')
        .map((s) => s.trim())
        .toSet();

    if (!directives.contains('no-store')) {
      throw ArgumentError(
        'Security violation: Token endpoint responses must be strictly excluded from proxy caches. '
        'Missing mandatory "Cache-Control: no-store" header. Got: "$cacheControl".',
      );
    }

    // 2. Parse JSON body
    final dynamic json = jsonDecode(body);
    if (json is! Map<String, dynamic>) {
      throw const FormatException('Token response body is not a JSON object.');
    }

    // 3. Handle OAuth Error Response
    if (json.containsKey('error')) {
      final error = json['error'];
      if (error is! String || error.isEmpty) {
        throw const FormatException(
          'Invalid "error" field in token error response.',
        );
      }

      // Enforce strictly ASCII NQSCHAR syntax: %x20-21 / %x23-5B / %x5D-7E
      final nqscharRegex = RegExp(r'^[\x20-\x21\x23-\x5B\x5D-\x7E]+$');
      if (!nqscharRegex.hasMatch(error)) {
        throw const FormatException(
          'Security violation: "error" field contains invalid characters violating ABNF NQSCHAR syntax.',
        );
      }

      final errorDescription = json['error_description'];
      if (errorDescription != null) {
        if (errorDescription is! String ||
            (errorDescription.isNotEmpty &&
                !nqscharRegex.hasMatch(errorDescription))) {
          throw const FormatException(
            'Security violation: "error_description" field contains invalid characters violating ABNF NQSCHAR syntax.',
          );
        }
      }

      final errorUri = json['error_uri'];
      if (errorUri != null) {
        if (errorUri is! String || errorUri.isEmpty) {
          throw const FormatException(
            'Invalid "error_uri" field in token error response.',
          );
        }
        final uriRegex = RegExp(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$");
        if (!uriRegex.hasMatch(errorUri) ||
            Uri.tryParse(errorUri)?.isAbsolute != true) {
          throw const FormatException(
            'Security violation: "error_uri" is not a valid absolute URI or contains invalid characters.',
          );
        }
      }

      return TokenError(
        error: error,
        errorDescription: errorDescription as String?,
        errorUri: errorUri as String?,
      );
    }

    // 4. Handle OAuth Success Response
    final accessToken = json['access_token'];
    final tokenType = json['token_type'];

    if (accessToken is! String || accessToken.isEmpty) {
      throw const FormatException(
        'Missing or invalid "access_token" in response.',
      );
    }
    if (tokenType is! String || tokenType.isEmpty) {
      throw const FormatException(
        'Missing or invalid "token_type" in response.',
      );
    }

    // Validate token_type (type-name = 1*name-char where name-char = "-" / "." / "_" / DIGIT / ALPHA, or absolute URI)
    final typeNameRegex = RegExp(r'^[A-Za-z0-9\-._]+$');
    final parsedUri = Uri.tryParse(tokenType);
    final isAbsoluteUri = parsedUri != null && parsedUri.isAbsolute;

    if (!typeNameRegex.hasMatch(tokenType) && !isAbsoluteUri) {
      throw FormatException(
        'Invalid token_type format in response: "$tokenType". '
        'Must conform to type-name ABNF or be a valid absolute URI.',
      );
    }

    int? expiresIn;
    if (json.containsKey('expires_in')) {
      final exp = json['expires_in'];
      if (exp is int) {
        expiresIn = exp;
      } else if (exp is String) {
        expiresIn = int.tryParse(exp);
      }
      if (expiresIn == null) {
        throw const FormatException(
          'Invalid "expires_in" parameter in response.',
        );
      }
    }

    return TokenSuccess(
      accessToken: accessToken,
      tokenType: tokenType,
      expiresIn: expiresIn,
      refreshToken: json['refresh_token'] as String?,
      scope: json['scope'] as String?,
      rawPayload: json,
    );
  }
}

/// Represents a successful token exchange response.
@immutable
class TokenSuccess extends TokenResult {
  /// The access token issued by the authorization server.
  final String accessToken;

  /// The type of the token (case-insensitively matches "Bearer").
  final String tokenType;

  /// The lifetime in seconds of the access token (optional).
  final int? expiresIn;

  /// The refresh token, which can be used to obtain new access tokens (optional).
  final String? refreshToken;

  /// The scope of the access token (optional).
  final String? scope;

  /// The raw JSON payload returned by the server.
  final Map<String, dynamic> rawPayload;

  /// Creates a [TokenSuccess] response containing the access tokens.
  const TokenSuccess({
    required this.accessToken,
    required this.tokenType,
    required this.rawPayload,
    this.expiresIn,
    this.refreshToken,
    this.scope,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is TokenSuccess &&
          runtimeType == other.runtimeType &&
          accessToken == other.accessToken &&
          tokenType == other.tokenType &&
          expiresIn == other.expiresIn &&
          refreshToken == other.refreshToken &&
          scope == other.scope;

  @override
  int get hashCode =>
      accessToken.hashCode ^
      tokenType.hashCode ^
      expiresIn.hashCode ^
      refreshToken.hashCode ^
      scope.hashCode;

  @override
  String toString() =>
      'TokenSuccess(tokenType: $tokenType, accessToken: ***, expiresIn: $expiresIn)';
}

/// Represents an OAuth 2.1 protocol error response.
@immutable
class TokenError extends TokenResult {
  /// The error code (e.g. "invalid_request", "invalid_grant").
  final String error;

  /// Human-readable text providing additional information (optional).
  final String? errorDescription;

  /// A URI identifying a human-readable web page with information about the error (optional).
  final String? errorUri;

  /// Creates a [TokenError] response containing the protocol error details.
  const TokenError({required this.error, this.errorDescription, this.errorUri});

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is TokenError &&
          runtimeType == other.runtimeType &&
          error == other.error &&
          errorDescription == other.errorDescription &&
          errorUri == other.errorUri;

  @override
  int get hashCode =>
      error.hashCode ^ errorDescription.hashCode ^ errorUri.hashCode;

  @override
  String toString() =>
      'TokenError(error: $error, description: $errorDescription)';
}
