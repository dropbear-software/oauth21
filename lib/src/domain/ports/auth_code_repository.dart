import '../entities/auth_code.dart';

/// Abstract port interface for managing authorization codes in the server.
abstract interface class AuthCodeRepository {
  /// Saves the [authCode] state to persistent storage.
  Future<void> save(AuthCode authCode);

  /// Resolves an authorization code by its unique high-entropy code string.
  ///
  /// Returns `null` if the code does not exist.
  Future<AuthCode?> findByCode(String code);

  /// Atomically marks the authorization code as used (Compare-And-Swap from
  /// `isUsed == false` to `isUsed == true`) to prevent concurrent token replay
  /// attacks.
  ///
  /// Returns `true` for the single caller that wins the transition, or `false`
  /// if the authorization code does not exist or has already been consumed.
  Future<bool> tryConsume(String code);
}
