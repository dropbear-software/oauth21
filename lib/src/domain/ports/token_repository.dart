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
}
