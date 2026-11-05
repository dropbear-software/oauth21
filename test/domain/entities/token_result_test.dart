import 'package:oauth21/src/domain/entities/token_result.dart';
import 'package:test/test.dart';

void main() {
  group('TokenResult', () {
    const successBody =
        '{"access_token":"token-123","token_type":"Bearer","expires_in":3600,'
        '"refresh_token":"ref-123","scope":"read"}';
    const errorBody =
        '{"error":"invalid_grant","error_description":"Invalid auth code",'
        '"error_uri":"https://example.com/errors"}';

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
        'should reject expires_in passed as a string, zero, negative, or float',
        () {
          for (final badBody in [
            '{"access_token":"token-123","token_type":"Bearer",'
                '"expires_in":"7200"}',
            '{"access_token":"token-123","token_type":"Bearer",'
                '"expires_in":0}',
            '{"access_token":"token-123","token_type":"Bearer",'
                '"expires_in":-10}',
            '{"access_token":"token-123","token_type":"Bearer",'
                '"expires_in":3600.5}',
          ]) {
            expect(
              () => TokenResult.fromResponse(
                body: badBody,
                headers: validHeaders,
              ),
              throwsFormatException,
              reason: 'Expected $badBody to throw FormatException',
            );
          }
        },
      );

      test('should reject non-VSCHAR access_token, non-string/non-VSCHAR '
          'refresh_token, or non-string/invalid-ABNF scope', () {
        for (final badBody in [
          r'{"access_token":"token\n123","token_type":"Bearer"}',
          '{"access_token":"token-123","token_type":"Bearer",'
              '"refresh_token":123}',
          '{"access_token":"token-123","token_type":"Bearer",'
              '"refresh_token":""}',
          '{"access_token":"token-123","token_type":"Bearer",'
              r'"refresh_token":"ref\n123"}',
          '{"access_token":"token-123","token_type":"Bearer",'
              '"scope":["read"]}',
          '{"access_token":"token-123","token_type":"Bearer",'
              '"scope":""}',
          '{"access_token":"token-123","token_type":"Bearer",'
              '"scope":"read  write"}',
          '{"access_token":"token-123","token_type":"Bearer",'
              r'"scope":"read\"quote"}',
        ]) {
          expect(
            () =>
                TokenResult.fromResponse(body: badBody, headers: validHeaders),
            throwsFormatException,
            reason: 'Expected $badBody to throw FormatException',
          );
        }
      });

      test(
        'should validate statusCode when provided (200 for success, >=400 for '
        'error)',
        () {
          expect(
            TokenResult.fromResponse(
              body: successBody,
              headers: validHeaders,
              statusCode: 200,
            ),
            isA<TokenSuccess>(),
          );
          expect(
            () => TokenResult.fromResponse(
              body: successBody,
              headers: validHeaders,
              statusCode: 201,
            ),
            throwsFormatException,
          );
          expect(
            () => TokenResult.fromResponse(
              body: successBody,
              headers: validHeaders,
              statusCode: 400,
            ),
            throwsFormatException,
          );
          expect(
            TokenResult.fromResponse(
              body: errorBody,
              headers: validHeaders,
              statusCode: 400,
            ),
            isA<TokenError>(),
          );
          expect(
            () => TokenResult.fromResponse(
              body: errorBody,
              headers: validHeaders,
              statusCode: 200,
            ),
            throwsFormatException,
          );
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
        'should reject token_type strings containing invalid character points '
        'violating ABNF syntax',
        () {
          // Contains forbidden space and exclamation point
          const body =
              '{"access_token":"token-123","token_type":"Invalid Type!"}';
          expect(
            () => TokenResult.fromResponse(body: body, headers: validHeaders),
            throwsFormatException,
          );
        },
      );

      test('should successfully parse vendor-specific token types formatted as '
          'absolute URIs', () {
        const body =
            '{"access_token":"token-123",'
            '"token_type":"https://example.com/oauth/type"}';
        final result =
            TokenResult.fromResponse(body: body, headers: validHeaders)
                as TokenSuccess;
        expect(result.tokenType, equals('https://example.com/oauth/type'));
      });

      test('should throw FormatException if expires_in is invalid', () {
        const body =
            '{"access_token":"token-123","token_type":"Bearer",'
            '"expires_in":"abc"}';
        expect(
          () => TokenResult.fromResponse(body: body, headers: validHeaders),
          throwsFormatException,
        );
      });

      test('should throw FormatException if numerical parameters suffer from '
          'structural JSON type confusion', () {
        // Array injection instead of primitive value
        const body =
            '{"access_token":"token-123","token_type":"Bearer",'
            '"expires_in":[3600]}';
        expect(
          () => TokenResult.fromResponse(body: body, headers: validHeaders),
          throwsFormatException,
        );
      });
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
        'should reject error responses containing characters violating strict '
        'ASCII NQSCHAR syntax',
        () {
          // Contains a malicious newline code point
          const body = '{"error":"invalid_request\nline"}';
          expect(
            () => TokenResult.fromResponse(body: body, headers: validHeaders),
            throwsFormatException,
          );
        },
      );

      test('should reject error responses if the error_description contains '
          'non-NQSCHAR characters', () {
        // Newline injection
        const body =
            '{"error":"invalid_grant",'
            '"error_description":"Invalid \n description"}';
        expect(
          () => TokenResult.fromResponse(body: body, headers: validHeaders),
          throwsFormatException,
        );
      });

      test(
        'should reject error responses if the error_uri violates standard URI '
        'syntax characters',
        () {
          // Space injection in URI
          const body =
              '{"error":"invalid_grant",'
              '"error_uri":"https://example.com/space error"}';
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
