import 'dart:convert';
import 'package:meta/meta.dart';

import '../abnf_validators.dart';

/// Represents the result of an OAuth 2.1 token exchange request.
///
/// This is a sealed class that is split into [TokenSuccess] and [TokenError].
@immutable
sealed class TokenResult {
  const TokenResult();

  /// Parses a token endpoint HTTP response.
  ///
  /// Throws [ArgumentError] if the mandatory `Cache-Control: no-store` header
  /// is missing.
  /// Throws [FormatException] if the body is not valid JSON, lacks mandatory
  /// parameters, or if [statusCode] conflicts with the response payload type.
  factory TokenResult.fromResponse({
    required String body,
    required Map<String, String> headers,
    int? statusCode,
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
        'Security violation: Token endpoint responses must be strictly '
        'excluded from proxy caches. Missing mandatory '
        '"Cache-Control: no-store" header. Got: "$cacheControl".',
      );
    }

    // 2. Parse JSON body
    final dynamic json = jsonDecode(body);
    if (json is! Map<String, dynamic>) {
      throw const FormatException('Token response body is not a JSON object.');
    }

    // 3. Handle OAuth Error Response
    if (json.containsKey('error')) {
      return _parseTokenError(json, statusCode);
    }

    // 4. Handle OAuth Success Response
    return _parseTokenSuccess(json, statusCode);
  }
}

final RegExp _tokenTypeNameRegex = RegExp(r'^[A-Za-z0-9\-._]+$');

TokenError _parseTokenError(Map<String, dynamic> json, int? statusCode) {
  if (statusCode != null && statusCode < 400) {
    throw FormatException(
      'Invalid HTTP status code $statusCode for token error response; '
      'expected >= 400.',
    );
  }

  final error = json['error'];
  if (error is! String || error.isEmpty) {
    throw const FormatException(
      'Invalid "error" field in token error response.',
    );
  }

  // Enforce strictly ASCII NQSCHAR syntax: %x20-21 / %x23-5B / %x5D-7E
  if (!nqscharRequiredRegex.hasMatch(error)) {
    throw const FormatException(
      'Security violation: "error" field contains invalid characters '
      'violating ABNF NQSCHAR syntax.',
    );
  }

  final errorDescription = json['error_description'];
  if (errorDescription is! String? ||
      (errorDescription != null &&
          errorDescription.isNotEmpty &&
          !nqscharRequiredRegex.hasMatch(errorDescription))) {
    throw const FormatException(
      'Security violation: "error_description" field contains invalid '
      'characters violating ABNF NQSCHAR syntax.',
    );
  }

  final errorUri = json['error_uri'];
  if (errorUri is! String? ||
      (errorUri != null && !isValidErrorUri(errorUri))) {
    throw const FormatException(
      'Security violation: "error_uri" is not a valid absolute URI or '
      'contains invalid characters.',
    );
  }

  return TokenError(
    error: error,
    errorDescription: errorDescription,
    errorUri: errorUri,
  );
}

TokenSuccess _parseTokenSuccess(Map<String, dynamic> json, int? statusCode) {
  if (statusCode != null && statusCode != 200) {
    throw FormatException(
      'Invalid HTTP status code $statusCode for token success response; '
      'expected 200.',
    );
  }

  final accessToken = json['access_token'];
  if (accessToken is! String || !vscharRequiredRegex.hasMatch(accessToken)) {
    throw const FormatException(
      'Missing or invalid "access_token" in response: must be a non-empty '
      'VSCHAR string.',
    );
  }

  final tokenType = json['token_type'];
  if (tokenType is! String || tokenType.isEmpty) {
    throw const FormatException('Missing or invalid "token_type" in response.');
  }

  // Validate token_type (type-name = 1*name-char where
  // name-char = "-" / "." / "_" / DIGIT / ALPHA, or absolute URI)
  final isAbsoluteUri = Uri.tryParse(tokenType)?.isAbsolute ?? false;
  if (!_tokenTypeNameRegex.hasMatch(tokenType) && !isAbsoluteUri) {
    throw FormatException(
      'Invalid token_type format in response: "$tokenType". '
      'Must conform to type-name ABNF or be a valid absolute URI.',
    );
  }

  final expiresIn = json['expires_in'];
  if (expiresIn is! int? || (expiresIn != null && expiresIn <= 0)) {
    throw const FormatException(
      'Invalid "expires_in" parameter in response: must be a positive integer '
      'JSON number.',
    );
  }

  final refreshToken = json['refresh_token'];
  if (refreshToken is! String? ||
      (refreshToken != null && !vscharRequiredRegex.hasMatch(refreshToken))) {
    throw const FormatException(
      'Invalid "refresh_token" parameter in response: must be a non-empty '
      'VSCHAR string.',
    );
  }

  final scope = json['scope'];
  if (scope is! String? ||
      (scope != null && !isValidScopeString(scope, allowEmpty: true))) {
    throw const FormatException(
      'Invalid "scope" parameter in response: must be a String of valid '
      'NQCHAR scope tokens.',
    );
  }

  return TokenSuccess(
    accessToken: accessToken,
    tokenType: tokenType,
    expiresIn: expiresIn,
    refreshToken: refreshToken,
    scope: scope,
    rawPayload: json,
  );
}

/// Represents a successful token exchange response.
@immutable
final class TokenSuccess extends TokenResult {
  /// The access token issued by the authorization server.
  final String accessToken;

  /// The type of the token (case-insensitively matches "Bearer").
  final String tokenType;

  /// The lifetime in seconds of the access token (optional).
  final int? expiresIn;

  /// The refresh token, which can be used to obtain new access tokens
  /// (optional).
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
      'TokenSuccess(tokenType: $tokenType, accessToken: ***, '
      'expiresIn: $expiresIn)';
}

/// Represents an OAuth 2.1 protocol error response.
@immutable
final class TokenError extends TokenResult {
  /// The error code (e.g. "invalid_request", "invalid_grant").
  final String error;

  /// Human-readable text providing additional information (optional).
  final String? errorDescription;

  /// A URI identifying a human-readable web page with information about the
  /// error (optional).
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
