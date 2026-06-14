/// Abstract port interface for cryptographic utilities required by the server.
abstract interface class CryptoService {
  /// Generates a cryptographically secure, URL-safe random string containing
  /// the specified number of bits of entropy (defaults to 256).
  ///
  /// The resulting string must have a guessing probability <= 2^-128.
  String generateRandomEntropyString([int bits = 256]);

  /// Computes the SHA-256 hash of the input string, returning its hex representation.
  String hashString(String input);

  /// Computes the SHA-256 hash of the input string and base64url encodes it.
  String hashAndBase64UrlEncode(String input);

  /// Verifies a plain secret/password against its stored cryptographic hash.
  bool verifyPasswordHash(String plain, String hashed);
}
