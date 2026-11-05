import 'package:meta/meta.dart';

import '../abnf_validators.dart';

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
  }) {
    if (!isValidVscharParam(code)) {
      throw ArgumentError(
        'code must not be empty, must be thoroughly trimmed, and '
        'must contain only printable ASCII characters (VSCHAR).',
      );
    }

    if (!isValidVscharParam(clientId)) {
      throw ArgumentError(
        'clientId must not be empty, must be thoroughly trimmed, and '
        'must contain only printable ASCII characters (VSCHAR).',
      );
    }

    if (!isValidVscharParam(userId)) {
      throw ArgumentError.value(
        userId,
        'userId',
        'userId must not be empty, must be thoroughly trimmed, and '
            'must contain only printable ASCII characters (VSCHAR).',
      );
    }

    if (!codeVerifierAbnfRegex.hasMatch(codeChallenge)) {
      throw ArgumentError.value(
        codeChallenge,
        'codeChallenge',
        'codeChallenge must be 43..128 unreserved characters '
            '(Appendix A.18).',
      );
    }

    if (codeChallengeMethod != 'S256') {
      throw ArgumentError.value(
        codeChallengeMethod,
        'codeChallengeMethod',
        'codeChallengeMethod must be "S256".',
      );
    }

    if (scope != null && !isValidScopeString(scope!)) {
      throw ArgumentError.value(
        scope,
        'scope',
        'scope must be a space-delimited list of non-empty NQCHAR tokens '
            '(Appendix A.4).',
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
    );
  }
}
