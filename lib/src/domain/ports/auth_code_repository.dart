import '../entities/auth_code.dart';

/// Abstract port interface for managing authorization codes in the server.
abstract interface class AuthCodeRepository {
  /// Saves the [authCode] state to persistent storage.
  Future<void> save(AuthCode authCode);

  /// Resolves an authorization code by its unique high-entropy code string.
  ///
  /// Returns `null` if the code does not exist.
  Future<AuthCode?> findByCode(String code);

  /// Marks the authorization code as used to prevent token replay attacks.
  Future<void> markAsUsed(String code);

  /// Revokes all access and refresh tokens previously issued by this code.
  ///
  /// This is used for cascade revocation when a code reuse attempt is detected.
  Future<void> revokeTokensForCode(String code);
}
