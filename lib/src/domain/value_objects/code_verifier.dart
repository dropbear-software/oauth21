import 'dart:math';
import 'package:meta/meta.dart';

/// A cryptographically secure random string used as a code verifier.
///
/// Under OAuth 2.1, the code verifier must have a minimum length of 43
/// characters and a maximum length of 128 characters, and must only contain
/// URL-safe unreserved characters.
@immutable
class CodeVerifier {
  /// The raw code verifier string value.
  final String value;

  /// The allowed character pool for the code verifier.
  static const String _allowedChars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

  /// Regex pattern matching only the unreserved character set.
  static final RegExp _characterSetRegex = RegExp(r'^[A-Za-z0-9\-._~]+$');

  /// Creates a [CodeVerifier] with a predefined [value].
  ///
  /// Throws [ArgumentError] if the [value] does not meet OAuth 2.1 criteria
  /// (length between 43 and 128 characters, containing only unreserved characters).
  CodeVerifier(this.value) {
    if (value.length < 43 || value.length > 128) {
      throw ArgumentError(
        'Code verifier length must be between 43 and 128 characters. '
        'Got length ${value.length}.',
      );
    }
    if (!_characterSetRegex.hasMatch(value)) {
      throw ArgumentError(
        'Code verifier contains invalid characters. Only ASCII alphanumeric '
        'characters and "-", ".", "_", "~" are allowed.',
      );
    }
  }

  /// Generates a cryptographically secure random [CodeVerifier] of the specified [length].
  ///
  /// [length] must be between 43 and 128 (defaults to 43).
  factory CodeVerifier.generate([int length = 43]) {
    if (length < 43 || length > 128) {
      throw ArgumentError(
        'Invalid generation length: must be between 43 and 128. Got $length.',
      );
    }

    final random = Random.secure();
    final buffer = StringBuffer();
    for (var i = 0; i < length; i++) {
      final index = random.nextInt(_allowedChars.length);
      buffer.write(_allowedChars[index]);
    }
    return CodeVerifier(buffer.toString());
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is CodeVerifier &&
          runtimeType == other.runtimeType &&
          value == other.value;

  @override
  int get hashCode => value.hashCode;

  @override
  String toString() => 'CodeVerifier(value: ***)';
}
