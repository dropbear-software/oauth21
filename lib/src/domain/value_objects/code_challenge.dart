import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:meta/meta.dart';
import 'code_verifier.dart';

/// A code challenge derived from a [CodeVerifier] using a cryptographic transform.
///
/// Under OAuth 2.1, the code challenge method must default to `S256`.
/// The insecure `plain` method is blocked unless an explicit opt-in is provided.
@immutable
class CodeChallenge {
  /// The derived challenge string value.
  final String value;

  /// The transformation method used (`S256` or `plain`).
  final String method;

  const CodeChallenge._(this.value, this.method);

  /// Computes a [CodeChallenge] using the mandatory `S256` algorithm.
  ///
  /// The S256 formula is: `BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`
  /// with all trailing padding characters (`=`) removed.
  factory CodeChallenge.s256(CodeVerifier verifier) {
    final bytes = utf8.encode(verifier.value);
    final hash = sha256.convert(bytes);
    // base64Url.encode generates URL-safe base64, but we must strip any trailing '=' padding
    final challenge = base64Url.encode(hash.bytes).replaceAll('=', '');
    return CodeChallenge._(challenge, 'S256');
  }

  /// Computes a [CodeChallenge] using the `plain` transformation method.
  ///
  /// [allowPlain] must be set to `true` to opt-in, otherwise this throws [ArgumentError].
  factory CodeChallenge.plain(
    CodeVerifier verifier, {
    required bool allowPlain,
  }) {
    if (!allowPlain) {
      throw ArgumentError(
        'The plain code challenge method is insecure and blocked by default under OAuth 2.1. '
        'Provide explicit permission (allowPlain: true) to enable it.',
      );
    }
    return CodeChallenge._(verifier.value, 'plain');
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is CodeChallenge &&
          runtimeType == other.runtimeType &&
          value == other.value &&
          method == other.method;

  @override
  int get hashCode => value.hashCode ^ method.hashCode;

  @override
  String toString() => 'CodeChallenge(method: $method, value: ***)';
}
