import 'package:oauth21/src/domain/value_objects/code_challenge.dart';
import 'package:oauth21/src/domain/value_objects/code_verifier.dart';
import 'package:test/test.dart';

void main() {
  group('CodeChallenge', () {
    // RFC 7636 Section 4.2 Test Vector
    const rfcVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const rfcChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    group('S256 method', () {
      test(
        'should correctly compute S256 challenge using RFC 7636 test vector',
        () {
          final verifier = CodeVerifier(rfcVerifier);
          final challenge = CodeChallenge.s256(verifier);

          expect(challenge.method, equals('S256'));
          expect(challenge.value, equals(rfcChallenge));
        },
      );

      test(
        'should strictly conform to ABNF code-challenge syntax limits over high iterations',
        () {
          // Enforces length between 43 and 128 characters, containing ONLY unreserved characters: [A-Za-z0-9\-._~]
          // This implicitly ensures NO padding (=), NO standard base64 plus (+), and NO forward slash (/) exist.
          final codeChallengeRegex = RegExp(r'^[A-Za-z0-9\-._~]{43,128}$');

          // Run 200 iterations to guarantee high statistical coverage of varied hash byte distributions
          for (var i = 0; i < 200; i++) {
            final verifier = CodeVerifier.generate();
            final challenge = CodeChallenge.s256(verifier);

            expect(
              codeChallengeRegex.hasMatch(challenge.value),
              isTrue,
              reason:
                  'Generated challenge "${challenge.value}" contains characters violating the unreserved ABNF spec pool.',
            );
          }
        },
      );
    });

    group('plain method', () {
      test('should throw if allowPlain is false', () {
        final verifier = CodeVerifier(rfcVerifier);
        expect(
          () => CodeChallenge.plain(verifier, allowPlain: false),
          throwsArgumentError,
        );
      });

      test(
        'should succeed and match verifier value when allowPlain is true',
        () {
          final verifier = CodeVerifier(rfcVerifier);
          final challenge = CodeChallenge.plain(verifier, allowPlain: true);

          expect(challenge.method, equals('plain'));
          expect(challenge.value, equals(rfcVerifier));
        },
      );
    });

    group('equality & representations', () {
      test('should support value equality and hashCode', () {
        final verifier = CodeVerifier(rfcVerifier);
        final c1 = CodeChallenge.s256(verifier);
        final c2 = CodeChallenge.s256(verifier);

        expect(c1, equals(c2));
        expect(c1.hashCode, equals(c2.hashCode));
      });

      test('should mask value in toString() representation', () {
        final verifier = CodeVerifier(rfcVerifier);
        final challenge = CodeChallenge.s256(verifier);
        expect(challenge.toString(), contains('method: S256'));
        expect(challenge.toString(), contains('value: ***'));
        expect(challenge.toString(), isNot(contains(rfcChallenge)));
      });
    });
  });
}
