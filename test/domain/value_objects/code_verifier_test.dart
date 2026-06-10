import 'package:oauth21/src/domain/value_objects/code_verifier.dart';
import 'package:test/test.dart';

void main() {
  group('CodeVerifier', () {
    group('constructor validation', () {
      test('should accept valid verifier of length 43', () {
        final val = 'A' * 43;
        final verifier = CodeVerifier(val);
        expect(verifier.value, equals(val));
      });

      test('should accept valid verifier of length 128', () {
        final val = 'z' * 128;
        final verifier = CodeVerifier(val);
        expect(verifier.value, equals(val));
      });

      test('should reject verifier shorter than 43 characters', () {
        final val = 'A' * 42;
        expect(() => CodeVerifier(val), throwsArgumentError);
      });

      test('should reject verifier longer than 128 characters', () {
        final val = 'A' * 129;
        expect(() => CodeVerifier(val), throwsArgumentError);
      });

      test('should accept all unreserved characters', () {
        // Allowed pool: [A-Z], [a-z], [0-9], -, ., _, ~
        const val =
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
        // Need to make it at least 43 characters (which it is: 66 characters)
        expect(val.length, greaterThanOrEqualTo(43));
        final verifier = CodeVerifier(val);
        expect(verifier.value, equals(val));
      });

      test('should reject invalid characters', () {
        final base = 'A' * 42;
        expect(() => CodeVerifier('$base+'), throwsArgumentError);
        expect(() => CodeVerifier('$base/'), throwsArgumentError);
        expect(() => CodeVerifier('$base='), throwsArgumentError);
        expect(() => CodeVerifier('$base '), throwsArgumentError);
        expect(() => CodeVerifier('$base%'), throwsArgumentError);
        expect(() => CodeVerifier('$base#'), throwsArgumentError);
      });

      test(
        'should reject verifiers containing multi-byte or non-ASCII characters even if length matches',
        () {
          // 'A' * 41 (length 41) + '🚀' (length 2 code units) = total length 43
          final surrogatePairValue = '${'A' * 41}🚀';
          expect(surrogatePairValue.length, equals(43));
          expect(() => CodeVerifier(surrogatePairValue), throwsArgumentError);

          // 'A' * 42 (length 42) + 'é' (length 1 code unit) = total length 43
          final accentedValue = '${'A' * 42}é';
          expect(accentedValue.length, equals(43));
          expect(() => CodeVerifier(accentedValue), throwsArgumentError);
        },
      );
    });

    group('generation', () {
      test('should generate verifier with default length (43)', () {
        final verifier = CodeVerifier.generate();
        expect(verifier.value.length, equals(43));
      });

      test('should generate verifier with custom valid length', () {
        final verifier = CodeVerifier.generate(100);
        expect(verifier.value.length, equals(100));
      });

      test('should throw if custom length is invalid', () {
        expect(() => CodeVerifier.generate(42), throwsArgumentError);
        expect(() => CodeVerifier.generate(129), throwsArgumentError);
      });

      test('should only contain unreserved characters', () {
        final verifier = CodeVerifier.generate(128);
        final unreservedRegex = RegExp(r'^[A-Za-z0-9\-._~]+$');
        expect(unreservedRegex.hasMatch(verifier.value), isTrue);
      });

      test('should generate unique values on sequential calls', () {
        final v1 = CodeVerifier.generate();
        final v2 = CodeVerifier.generate();
        expect(v1, isNot(equals(v2)));
        expect(v1.value, isNot(equals(v2.value)));
      });
    });

    group('equality & representations', () {
      test('should support value equality and hashCode', () {
        final v1 = CodeVerifier('A' * 43);
        final v2 = CodeVerifier('A' * 43);
        final v3 = CodeVerifier('B' * 43);

        expect(v1, equals(v2));
        expect(v1.hashCode, equals(v2.hashCode));
        expect(v1, isNot(equals(v3)));
      });

      test('should mask value in toString() representation', () {
        final verifier = CodeVerifier.generate();
        expect(verifier.toString(), equals('CodeVerifier(value: ***)'));
        expect(verifier.toString(), isNot(contains(verifier.value)));
      });
    });
  });
}
