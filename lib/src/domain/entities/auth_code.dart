import 'package:meta/meta.dart';

/// Domain entity representing an issued authorization code.
@immutable
class AuthCode {
  /// The high-entropy authorization code string.
  final String code;

  /// The client ID to which the code was issued.
  final String clientId;

  /// The redirection URI specified in the authorization request.
  final Uri redirectUri;

  /// The resource owner user ID.
  final String userId;

  /// The approved scope of the authorization code.
  final String? scope;

  /// The PKCE code challenge.
  final String codeChallenge;

  /// The PKCE code challenge method (e.g. S256).
  final String codeChallengeMethod;

  /// The expiration timestamp of the code.
  final DateTime expiresAt;

  /// Whether this authorization code has been used to request tokens.
  final bool isUsed;

  /// List of token IDs/hashes issued by this code.
  final List<String> issuedTokenIds;

  /// Creates a new [AuthCode] instance.
  AuthCode({
    required this.code,
    required this.clientId,
    required this.redirectUri,
    required this.userId,
    required this.codeChallenge,
    required this.codeChallengeMethod,
    required this.expiresAt,
    this.scope,
    this.isUsed = false,
    this.issuedTokenIds = const [],
  }) {
    final vscharRequiredRegex = RegExp(r'^[\x20-\x7E]+$');
    if (code.isEmpty ||
        code.trim() != code ||
        !vscharRequiredRegex.hasMatch(code)) {
      throw ArgumentError(
        'code must not be empty, must be thoroughly trimmed, and '
        'must contain only printable ASCII characters (VSCHAR).',
      );
    }

    if (clientId.isEmpty ||
        clientId.trim() != clientId ||
        !vscharRequiredRegex.hasMatch(clientId)) {
      throw ArgumentError(
        'clientId must not be empty, must be thoroughly trimmed, and '
        'must contain only printable ASCII characters (VSCHAR).',
      );
    }

    const allowedMethods = {'S256', 'plain'};
    if (!allowedMethods.contains(codeChallengeMethod)) {
      throw ArgumentError(
        'Unsupported codeChallengeMethod "$codeChallengeMethod". Only S256 and plain are supported.',
      );
    }
  }

  /// Returns whether this authorization code is expired.
  bool get isExpired => DateTime.now().isAfter(expiresAt);

  /// Returns whether this authorization code is valid (unexpired and unused).
  bool get isValid => !isExpired && !isUsed;

  /// Creates a copy of this [AuthCode] with the given fields replaced.
  AuthCode copyWith({
    String? code,
    String? clientId,
    Uri? redirectUri,
    String? userId,
    String? scope,
    String? codeChallenge,
    String? codeChallengeMethod,
    DateTime? expiresAt,
    bool? isUsed,
    List<String>? issuedTokenIds,
  }) {
    return AuthCode(
      code: code ?? this.code,
      clientId: clientId ?? this.clientId,
      redirectUri: redirectUri ?? this.redirectUri,
      userId: userId ?? this.userId,
      scope: scope ?? this.scope,
      codeChallenge: codeChallenge ?? this.codeChallenge,
      codeChallengeMethod: codeChallengeMethod ?? this.codeChallengeMethod,
      expiresAt: expiresAt ?? this.expiresAt,
      isUsed: isUsed ?? this.isUsed,
      issuedTokenIds: issuedTokenIds ?? this.issuedTokenIds,
    );
  }
}
