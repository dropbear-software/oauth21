import 'package:meta/meta.dart';

/// Domain entity representing an issued access token.
@immutable
class AccessToken {
  /// The cryptographic hash of the access token value (SHA-256).
  final String tokenHash;

  /// The client ID to which the token was issued.
  final String clientId;

  /// The resource owner user ID.
  final String? userId;

  /// The scope of the access token.
  final String? scope;

  /// The expiration timestamp.
  final DateTime expiresAt;

  /// Whether the access token has been explicitly revoked.
  final bool isRevoked;

  /// Creates a new [AccessToken] instance.
  const AccessToken({
    required this.tokenHash,
    required this.clientId,
    required this.expiresAt,
    this.userId,
    this.scope,
    this.isRevoked = false,
  });

  /// Returns whether this access token is expired.
  bool get isExpired => DateTime.now().isAfter(expiresAt);

  /// Returns whether this access token is valid (unexpired and not revoked).
  bool get isValid => !isExpired && !isRevoked;

  /// Creates a copy of this [AccessToken] with the given fields replaced.
  AccessToken copyWith({
    String? tokenHash,
    String? clientId,
    String? userId,
    String? scope,
    DateTime? expiresAt,
    bool? isRevoked,
  }) {
    return AccessToken(
      tokenHash: tokenHash ?? this.tokenHash,
      clientId: clientId ?? this.clientId,
      userId: userId ?? this.userId,
      scope: scope ?? this.scope,
      expiresAt: expiresAt ?? this.expiresAt,
      isRevoked: isRevoked ?? this.isRevoked,
    );
  }
}
