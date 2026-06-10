import 'package:oauth21/src/domain/entities/token_result.dart';
import 'package:test/test.dart';

void main() {
  group('TokenResult', () {
    const successBody =
        '{"access_token":"token-123","token_type":"Bearer","expires_in":3600,"refresh_token":"ref-123","scope":"read"}';
    const errorBody =
        '{"error":"invalid_grant","error_description":"Invalid auth code","error_uri":"https://example.com/errors"}';

    group('Cache-Control validation', () {
      test(
        'should succeed if Cache-Control contains no-store (exact match)',
        () {
          final result = TokenResult.fromResponse(
            body: successBody,
            headers: {'Cache-Control': 'no-store'},
          );
          expect(result, isA<TokenSuccess>());
        },
      );

      test('should succeed if Cache-Control contains no-store mixed case', () {
        final result = TokenResult.fromResponse(
          body: successBody,
          headers: {'cache-control': 'NO-STORE, NO-CACHE'},
        );
        expect(result, isA<TokenSuccess>());
      });

      test('should throw if Cache-Control header is missing', () {
        expect(
          () => TokenResult.fromResponse(
            body: successBody,
            headers: {'Content-Type': 'application/json'},
          ),
          throwsArgumentError,
        );
      });

      test(
        'should throw if Cache-Control exists but does not contain no-store',
        () {
          expect(
            () => TokenResult.fromResponse(
              body: successBody,
              headers: {'Cache-Control': 'public, max-age=3600'},
            ),
            throwsArgumentError,
          );
        },
      );
    });

    group('success parsing', () {
      final validHeaders = {'Cache-Control': 'no-store'};

      test('should successfully parse full response', () {
        final result =
            TokenResult.fromResponse(body: successBody, headers: validHeaders)
                as TokenSuccess;

        expect(result.accessToken, equals('token-123'));
        expect(result.tokenType, equals('Bearer'));
        expect(result.expiresIn, equals(3600));
        expect(result.refreshToken, equals('ref-123'));
        expect(result.scope, equals('read'));
      });

      test('should accept case-insensitive "bearer" token type', () {
        const body = '{"access_token":"token-123","token_type":"bearer"}';
        final result =
            TokenResult.fromResponse(body: body, headers: validHeaders)
                as TokenSuccess;
        expect(result.tokenType, equals('bearer'));
      });

      test(
        'should parse expires_in passed as a string representation of integer',
        () {
          const body =
              '{"access_token":"token-123","token_type":"Bearer","expires_in":"7200"}';
          final result =
              TokenResult.fromResponse(body: body, headers: validHeaders)
                  as TokenSuccess;
          expect(result.expiresIn, equals(7200));
        },
      );

      test('should throw FormatException if access_token is missing', () {
        const body = '{"token_type":"Bearer"}';
        expect(
          () => TokenResult.fromResponse(body: body, headers: validHeaders),
          throwsFormatException,
        );
      });

      test('should throw FormatException if token_type is missing', () {
        const body = '{"access_token":"token-123"}';
        expect(
          () => TokenResult.fromResponse(body: body, headers: validHeaders),
          throwsFormatException,
        );
      });

      test(
        'should accept valid alternative registered token types like DPoP',
        () {
          const body = '{"access_token":"token-123","token_type":"DPoP"}';
          final result =
              TokenResult.fromResponse(body: body, headers: validHeaders)
                  as TokenSuccess;
          expect(result.tokenType, equals('DPoP'));
        },
      );

      test(
        'should reject token_type strings containing invalid character points violating ABNF syntax',
        () {
          const body =
              '{"access_token":"token-123","token_type":"Invalid Type!"}'; // Contains forbidden space and exclamation point
          expect(
            () => TokenResult.fromResponse(body: body, headers: validHeaders),
            throwsFormatException,
          );
        },
      );

      test(
        'should successfully parse vendor-specific token types formatted as absolute URIs',
        () {
          const body =
              '{"access_token":"token-123","token_type":"https://example.com/oauth/type"}';
          final result =
              TokenResult.fromResponse(body: body, headers: validHeaders)
                  as TokenSuccess;
          expect(result.tokenType, equals('https://example.com/oauth/type'));
        },
      );

      test('should throw FormatException if expires_in is invalid', () {
        const body =
            '{"access_token":"token-123","token_type":"Bearer","expires_in":"abc"}';
        expect(
          () => TokenResult.fromResponse(body: body, headers: validHeaders),
          throwsFormatException,
        );
      });

      test(
        'should throw FormatException if numerical parameters suffer from structural JSON type confusion',
        () {
          const body =
              '{"access_token":"token-123","token_type":"Bearer","expires_in":[3600]}'; // Array injection instead of primitive value
          expect(
            () => TokenResult.fromResponse(body: body, headers: validHeaders),
            throwsFormatException,
          );
        },
      );
    });

    group('error parsing', () {
      final validHeaders = {'Cache-Control': 'no-store'};

      test('should successfully parse error response', () {
        final result =
            TokenResult.fromResponse(body: errorBody, headers: validHeaders)
                as TokenError;

        expect(result.error, equals('invalid_grant'));
        expect(result.errorDescription, equals('Invalid auth code'));
        expect(result.errorUri, equals('https://example.com/errors'));
      });

      test(
        'should throw FormatException if error code is missing or empty',
        () {
          const body = '{"error":""}';
          expect(
            () => TokenResult.fromResponse(body: body, headers: validHeaders),
            throwsFormatException,
          );
        },
      );

      test(
        'should reject error responses containing characters violating strict ASCII NQSCHAR syntax',
        () {
          const body =
              '{"error":"invalid_request\nline"}'; // Contains a malicious newline code point
          expect(
            () => TokenResult.fromResponse(body: body, headers: validHeaders),
            throwsFormatException,
          );
        },
      );

      test(
        'should reject error responses if the error_description contains non-NQSCHAR characters',
        () {
          const body =
              '{"error":"invalid_grant","error_description":"Invalid \n description"}'; // Newline injection
          expect(
            () => TokenResult.fromResponse(body: body, headers: validHeaders),
            throwsFormatException,
          );
        },
      );

      test(
        'should reject error responses if the error_uri violates standard URI syntax characters',
        () {
          const body =
              '{"error":"invalid_grant","error_uri":"https://example.com/space error"}'; // Space injection in URI
          expect(
            () => TokenResult.fromResponse(body: body, headers: validHeaders),
            throwsFormatException,
          );
        },
      );
    });

    group('equality & representations', () {
      test('TokenSuccess equality', () {
        final s1 = TokenSuccess(
          accessToken: 't1',
          tokenType: 'Bearer',
          expiresIn: 10,
          rawPayload: const {},
        );
        final s2 = TokenSuccess(
          accessToken: 't1',
          tokenType: 'Bearer',
          expiresIn: 10,
          rawPayload: const {},
        );
        expect(s1, equals(s2));
        expect(s1.hashCode, equals(s2.hashCode));
      });

      test('TokenError equality', () {
        final e1 = TokenError(error: 'err1', errorDescription: 'desc');
        final e2 = TokenError(error: 'err1', errorDescription: 'desc');
        expect(e1, equals(e2));
        expect(e1.hashCode, equals(e2.hashCode));
      });

      test('should mask accessToken in TokenSuccess.toString()', () {
        final success = TokenSuccess(
          accessToken: 'super-secret-token',
          tokenType: 'Bearer',
          expiresIn: 3600,
          rawPayload: const {},
        );
        expect(success.toString(), contains('tokenType: Bearer'));
        expect(success.toString(), contains('accessToken: ***'));
        expect(success.toString(), isNot(contains('super-secret-token')));
      });

      test('should implement TokenError.toString() correctly', () {
        final error = TokenError(
          error: 'invalid_grant',
          errorDescription: 'Code expired',
        );
        expect(error.toString(), contains('invalid_grant'));
        expect(error.toString(), contains('Code expired'));
      });
    });
  });
}
