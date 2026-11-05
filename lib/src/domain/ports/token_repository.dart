import '../entities/access_token.dart';
import '../entities/refresh_token.dart';

/// Abstract port interface for persisting access and refresh tokens.
///
/// To prevent session hijacking via database leaks, token identifiers must only
/// be stored and queried as cryptographic hashes.
abstract interface class TokenRepository {
  /// Saves the access token entity to persistent storage.
  Future<void> saveAccessToken(AccessToken token);

  /// Saves the refresh token entity to persistent storage.
  Future<void> saveRefreshToken(RefreshToken token);

  /// Resolves an access token by its SHA-256 hash.
  ///
  /// Returns `null` if the token does not exist or has been deleted.
  Future<AccessToken?> findAccessTokenByHash(String hashedValue);

  /// Resolves a refresh token by its SHA-256 hash.
  ///
  /// Returns `null` if the token does not exist or has been deleted.
  Future<RefreshToken?> findRefreshTokenByHash(String hashedValue);

  /// Revokes a refresh token by its SHA-256 hash.
  Future<void> revokeRefreshTokenByHash(String hashedValue);

  /// Saves newly issued tokens atomically unless [AccessToken.authorizationCode]
  /// has already been tombstoned by a concurrent replay call to
  /// [revokeByAuthorizationCode].
  ///
  /// Returns `true` if the tokens were saved as active, or `false` if the
  /// originating authorization code was already compromised (in which case the
  /// tokens are recorded as revoked and ineligible for the grace window).
  Future<bool> saveIssuedTokens({
    required AccessToken accessToken,
    RefreshToken? refreshToken,
  });

  /// Atomically rotates the refresh token matching [oldTokenHash] and persists
  /// [newAccessToken] and [newRefreshToken].
  ///
  /// Transitions the parent refresh token either from active (`!isRevoked`) to
  /// revoked (`isRevoked: true`, `revokedAt: now`, `usedInGraceWindow: false`),
  /// or—for a single retry within [graceWindow]—from
  /// `isRevoked && !usedInGraceWindow` to `usedInGraceWindow: true` without
  /// resetting `revokedAt`.
  ///
  /// Returns `false` if [oldTokenHash] does not exist, is expired, belongs to a
  /// tombstoned authorization code, has already consumed its grace window, or
  /// is outside [graceWindow].
  Future<bool> rotateRefreshToken({
    required String oldTokenHash,
    required AccessToken newAccessToken,
    required RefreshToken newRefreshToken,
    Duration graceWindow = const Duration(seconds: 30),
  });

  /// Tombstones [authorizationCode] and revokes all access and refresh tokens
  /// descended from [authorizationCode] (marking refresh tokens with
  /// `usedInGraceWindow: true` so they cannot be redeemed during the grace
  /// window).
  Future<void> revokeByAuthorizationCode(String authorizationCode);

  /// Revokes all access and refresh tokens issued to the given client and user
  /// (marking refresh tokens with `usedInGraceWindow: true`).
  Future<void> revokeAllTokensForClientAndUser(String clientId, String? userId);
}
