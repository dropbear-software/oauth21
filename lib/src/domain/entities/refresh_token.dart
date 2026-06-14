import 'package:meta/meta.dart';

/// Domain entity representing an issued refresh token.
@immutable
class RefreshToken {
  /// The cryptographic hash of the refresh token value (SHA-256).
  final String tokenHash;

  /// The client ID to which the token was issued.
  final String clientId;

  /// The resource owner user ID.
  final String? userId;

  /// The scope of the refresh token.
  final String? scope;

  /// The expiration timestamp.
  final DateTime expiresAt;

  /// Whether the refresh token has been explicitly revoked.
  final bool isRevoked;

  /// The timestamp when the refresh token was revoked, if any.
  final DateTime? revokedAt;

  /// Whether the token was already re-used within the rotation grace window.
  final bool usedInGraceWindow;

  /// Creates a new [RefreshToken] instance.
  const RefreshToken({
    required this.tokenHash,
    required this.clientId,
    required this.expiresAt,
    this.userId,
    this.scope,
    this.isRevoked = false,
    this.revokedAt,
    this.usedInGraceWindow = false,
  });

  /// Returns whether this refresh token is expired.
  bool get isExpired => DateTime.now().isAfter(expiresAt);

  /// Returns whether this refresh token is valid (unexpired and not revoked).
  bool get isValid => !isExpired && !isRevoked;

  /// Creates a copy of this [RefreshToken] with the given fields replaced.
  RefreshToken copyWith({
    String? tokenHash,
    String? clientId,
    String? userId,
    String? scope,
    DateTime? expiresAt,
    bool? isRevoked,
    DateTime? revokedAt,
    bool? usedInGraceWindow,
  }) {
    return RefreshToken(
      tokenHash: tokenHash ?? this.tokenHash,
      clientId: clientId ?? this.clientId,
      userId: userId ?? this.userId,
      scope: scope ?? this.scope,
      expiresAt: expiresAt ?? this.expiresAt,
      isRevoked: isRevoked ?? this.isRevoked,
      revokedAt: revokedAt ?? this.revokedAt,
      usedInGraceWindow: usedInGraceWindow ?? this.usedInGraceWindow,
    );
  }
}
