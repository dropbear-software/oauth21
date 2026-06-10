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

    test('should parse a redirect URI containing the optional iss parameter', () {
      final uri = Uri.parse(
        'https://client.example.com/callback?code=splat-code&state=xyz-state&iss=https%3A%2F%2Fauth.example.com',
      );
      final result = parser.parseRedirect(uri);

      expect(result.code, equals('splat-code'));
      expect(result.state, equals('xyz-state'));
      expect(result.iss, equals('https://auth.example.com'));
    });

    test('should parse an error redirect URI', () {
      final uri = Uri.parse(
        'https://client.example.com/callback?error=access_denied&error_description=User+aborted+auth',
      );
      final result = parser.parseRedirect(uri);

      expect(result.code, isNull);
      expect(result.state, isNull);
      expect(result.error, equals('access_denied'));
      expect(result.errorDescription, equals('User aborted auth'));
    });

    test(
      'should throw ArgumentError if parameter pollution (duplicate keys) is detected',
      () {
        final uri = Uri.parse(
          'https://client.example.com/callback?code=code1&state=state1&code=code2',
        );
        expect(() => parser.parseRedirect(uri), throwsArgumentError);
      },
    );

    test(
      'should throw ArgumentError if parameter pollution is detected on any parameter key',
      () {
        final duplicateStateUri = Uri.parse(
          'https://client.example.com/callback?code=splat-code&state=xyz1&state=xyz2',
        );
        final duplicateIssUri = Uri.parse(
          'https://client.example.com/callback?code=splat-code&state=xyz&iss=https%3A%2F%2Fas1.com&iss=https%3A%2F%2Fas2.com',
        );

        expect(
          () => parser.parseRedirect(duplicateStateUri),
          throwsArgumentError,
        );
        expect(
          () => parser.parseRedirect(duplicateIssUri),
          throwsArgumentError,
        );
      },
    );

    group('ABNF Character & Structural Verification', () {
      test(
        'should reject redirect URI if state contains non-VSCHAR characters',
        () {
          final malformedUri = Uri.parse(
            'https://client.example.com/callback?code=splat-code&state=xyz\nbreak', // Newline injection
          );
          expect(
            () => parser.parseRedirect(malformedUri),
            throwsFormatException,
          );
        },
      );

      test(
        'should reject redirect URI if error values violate NQSCHAR syntax characters',
        () {
          final malformedUri = Uri.parse(
            'https://client.example.com/callback?error=access_"denied"', // Forbidden double quotes
          );
          expect(
            () => parser.parseRedirect(malformedUri),
            throwsFormatException,
          );
        },
      );

      test('should treat empty value query parameters as completely omitted', () {
        final emptyStateUri = Uri.parse(
          'https://client.example.com/callback?code=splat-code&state=', // Empty value field
        );
        final result = parser.parseRedirect(emptyStateUri);
        expect(result.state, isNull);
        expect(result.code, equals('splat-code'));
      });

      test(
        'should throw ArgumentError if redirect contains neither code nor error parameters',
        () {
          final invalidProtocolUri = Uri.parse(
            'https://client.example.com/callback?random_param=unrelated', // Missing protocol keys entirely
          );
          expect(
            () => parser.parseRedirect(invalidProtocolUri),
            throwsArgumentError,
          );
        },
      );
    });
  });
}
