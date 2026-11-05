import 'package:oauth21/src/domain/ports/oauth_req_parser.dart';
import 'package:test/test.dart';

void main() {
  group('DefaultRequestParser', () {
    const parser = DefaultRequestParser();

    test('should parse a successful redirect URI', () {
      final uri = Uri.parse(
        'https://client.example.com/callback?code=splat-code&state=xyz-state',
      );
      final result = parser.parseRedirect(uri);

      expect(result.code, equals('splat-code'));
      expect(result.state, equals('xyz-state'));
      expect(result.iss, isNull);
      expect(result.error, isNull);
      expect(result.errorDescription, isNull);
    });

    test(
      'should parse a redirect URI containing the optional iss parameter',
      () {
        final uri = Uri.parse(
          'https://client.example.com/callback?code=splat-code&state=xyz-state'
          '&iss=https%3A%2F%2Fauth.example.com',
        );
        final result = parser.parseRedirect(uri);

        expect(result.code, equals('splat-code'));
        expect(result.state, equals('xyz-state'));
        expect(result.iss, equals('https://auth.example.com'));
      },
    );

    test('should parse an error redirect URI', () {
      final uri = Uri.parse(
        'https://client.example.com/callback?error=access_denied'
        '&error_description=User+aborted+auth',
      );
      final result = parser.parseRedirect(uri);

      expect(result.code, isNull);
      expect(result.state, isNull);
      expect(result.error, equals('access_denied'));
      expect(result.errorDescription, equals('User aborted auth'));
    });

    test(
      'should throw ArgumentError if parameter pollution (duplicate keys) is '
      'detected',
      () {
        final uri = Uri.parse(
          'https://client.example.com/callback?code=code1&state=state1'
          '&code=code2',
        );
        expect(() => parser.parseRedirect(uri), throwsArgumentError);
      },
    );

    test('should throw ArgumentError if parameter pollution is detected on any '
        'parameter key', () {
      final duplicateStateUri = Uri.parse(
        'https://client.example.com/callback?code=splat-code&state=xyz1'
        '&state=xyz2',
      );
      final duplicateIssUri = Uri.parse(
        'https://client.example.com/callback?code=splat-code&state=xyz'
        '&iss=https%3A%2F%2Fas1.com&iss=https%3A%2F%2Fas2.com',
      );

      expect(
        () => parser.parseRedirect(duplicateStateUri),
        throwsArgumentError,
      );
      expect(() => parser.parseRedirect(duplicateIssUri), throwsArgumentError);
    });

    group('ABNF Character & Structural Verification', () {
      test(
        'should reject redirect URI if state contains non-VSCHAR characters',
        () {
          // Newline injection
          final malformedUri = Uri.parse(
            'https://client.example.com/callback?code=splat-code'
            '&state=xyz\nbreak',
          );
          expect(
            () => parser.parseRedirect(malformedUri),
            throwsFormatException,
          );
        },
      );

      test('should reject redirect URI if error values violate NQSCHAR syntax '
          'characters', () {
        // Forbidden double quotes
        final malformedUri = Uri.parse(
          'https://client.example.com/callback?error=access_"denied"',
        );
        expect(() => parser.parseRedirect(malformedUri), throwsFormatException);
      });

      test(
        'should reject redirect URI if code contains non-VSCHAR characters',
        () {
          // Newline injection
          final malformedUri = Uri.parse(
            'https://client.example.com/callback?code=code\nbreak',
          );
          expect(
            () => parser.parseRedirect(malformedUri),
            throwsFormatException,
          );
        },
      );

      test(
        'should reject redirect URI if error_description contains non-NQSCHAR '
        'characters',
        () {
          // Forbidden backslash
          final malformedUri = Uri.parse(
            'https://client.example.com/callback?error=invalid_request'
            r'&error_description=some\backslash',
          );
          expect(
            () => parser.parseRedirect(malformedUri),
            throwsFormatException,
          );
        },
      );

      test(
        'should treat empty value query parameters as completely omitted',
        () {
          // Empty value field
          final emptyStateUri = Uri.parse(
            'https://client.example.com/callback?code=splat-code&state=',
          );
          final result = parser.parseRedirect(emptyStateUri);
          expect(result.state, isNull);
          expect(result.code, equals('splat-code'));
        },
      );

      test('should throw ArgumentError if redirect contains neither code nor '
          'error parameters', () {
        // Missing protocol keys entirely
        final invalidProtocolUri = Uri.parse(
          'https://client.example.com/callback?random_param=unrelated',
        );
        expect(
          () => parser.parseRedirect(invalidProtocolUri),
          throwsArgumentError,
        );
      });

      test(
        'should throw ArgumentError if redirect contains both code and error '
        'parameters (#13)',
        () {
          final ambiguousUri = Uri.parse(
            'https://client.example.com/callback?code=splat-code'
            '&error=access_denied',
          );
          expect(() => parser.parseRedirect(ambiguousUri), throwsArgumentError);
        },
      );

      test('should reject redirect URI if iss contains non-VSCHAR characters '
          '(#13)', () {
        final malformedIssUri = Uri.parse(
          'https://client.example.com/callback?code=splat-code'
          '&iss=https://auth.example.com\nbreak',
        );
        expect(
          () => parser.parseRedirect(malformedIssUri),
          throwsFormatException,
        );
      });

      test(
        'should parse valid error_uri and reject malformed error_uri (#13)',
        () {
          final validErrorUri = Uri.parse(
            'https://client.example.com/callback?error=invalid_request'
            '&error_uri=https%3A%2F%2Fauth.example.com%2Fdocs%2Ferrors',
          );
          final parsed = parser.parseRedirect(validErrorUri);
          expect(
            parsed.errorUri,
            equals('https://auth.example.com/docs/errors'),
          );

          for (final badErrorUri in [
            'https://client.example.com/callback?error=invalid_request'
                '&error_uri=not-a-uri-with-scheme',
            'https://client.example.com/callback?error=invalid_request'
                '&error_uri=https://auth.example.com/"bad"',
          ]) {
            expect(
              () => parser.parseRedirect(Uri.parse(badErrorUri)),
              throwsFormatException,
              reason: 'Expected $badErrorUri to throw FormatException',
            );
          }
        },
      );
    });
  });
}
