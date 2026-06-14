import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:oauth21/src/adapters/http_adapter.dart';
import 'package:test/test.dart';

void main() {
  group('HttpAdapter', () {
    test('should execute POST request and format response', () async {
      final mockClient = MockClient((request) async {
        expect(request.method, equals('POST'));
        expect(request.url, equals(Uri.parse('https://example.com/token')));
        expect(
          request.headers['Content-Type'],
          equals('application/x-www-form-urlencoded'),
        );
        expect(request.headers['Authorization'], equals('Basic xyz'));
        expect(request.body, equals('code=123&state=xyz'));

        return http.Response(
          '{"access_token": "token123"}',
          200,
          headers: {'Cache-Control': 'no-store'},
        );
      });

      final adapter = HttpAdapter(mockClient);
      final response = await adapter.post(
        Uri.parse('https://example.com/token'),
        headers: {'Authorization': 'Basic xyz'},
        body: {'code': '123', 'state': 'xyz'},
      );

      expect(response.statusCode, equals(200));
      expect(response.body, equals('{"access_token": "token123"}'));
      expect(response.headers['Cache-Control'], equals('no-store'));
    });

    test(
      'should strictly percent-encode complex body parameters conforming to application/x-www-form-urlencoded',
      () async {
        final mockClient = MockClient((request) async {
          // Assert that spaces are translated to '+' or '%20' and ampersands/equals signs are cleanly escaped
          expect(
            request.body,
            // 'read write' -> 'read+write' (or %20)
            // 'foo&bar=baz' -> 'foo%26bar%3Dbaz'
            equals('scope=read+write&secret=foo%26bar%3Dbaz'),
          );

          return http.Response(
            '{"access_token":"t1"}',
            200,
            headers: {'Cache-Control': 'no-store'},
          );
        });

        final adapter = HttpAdapter(mockClient);
        await adapter.post(
          Uri.parse('https://example.com/token'),
          body: {'scope': 'read write', 'secret': 'foo&bar=baz'},
        );
      },
    );

    test(
      'should throw ArgumentError and abort request if token endpoint scheme is insecure http',
      () {
        final mockClient = MockClient(
          (request) async => http.Response('{}', 200),
        );
        final adapter = HttpAdapter(mockClient);

        expect(
          () => adapter.post(
            Uri.parse('http://example.com/token'), // Insecure cleartext link
            body: {'code': '123'},
          ),
          throwsArgumentError,
        );
      },
    );

    test(
      'should transparently propagate non-200 error status codes and error payloads to the domain layer',
      () async {
        final mockClient = MockClient((request) async {
          return http.Response(
            '{"error":"invalid_grant","error_description":"Code expired"}',
            400, // Standard OAuth 2.1 error status code
            headers: {'Cache-Control': 'no-store'},
          );
        });

        final adapter = HttpAdapter(mockClient);
        final response = await adapter.post(
          Uri.parse('https://example.com/token'),
          body: {'code': 'expired_code'},
        );

        expect(response.statusCode, equals(400));
        expect(response.body, contains('"error":"invalid_grant"'));
        expect(response.headers['Cache-Control'], equals('no-store'));
      },
    );

    test('should permit unencrypted cleartext HTTP exclusively on local '
        'loopback host environments', () async {
      final mockClient = MockClient((request) async {
        return http.Response('{"access_token":"loopback-token"}', 200);
      });

      final adapter = HttpAdapter(mockClient);

      // Localhost, 127.0.0.1, and [::1] loopbacks over HTTP should succeed
      final resLocalhost = await adapter.post(
        Uri.parse('http://localhost/token'),
        body: {'code': '123'},
      );
      final resIp = await adapter.post(
        Uri.parse('http://127.0.0.1/token'),
        body: {'code': '123'},
      );
      final resIp6 = await adapter.post(
        Uri.parse('http://[::1]/token'),
        body: {'code': '123'},
      );

      expect(resLocalhost.statusCode, equals(200));
      expect(resIp.statusCode, equals(200));
      expect(resIp6.statusCode, equals(200));
    });

    test('should merge and normalize varied-case header keys to prevent '
        'duplication exploits', () async {
      final mockClient = MockClient((request) async {
        // Verify that lowercase 'authorization' key absorbed the target
        expect(
          request.headers['authorization'],
          equals('Basic overridden-value'),
        );
        // Confirm no secondary duplicate variant leaked through the map
        expect(
          request.headers.keys.toList().contains('Authorization'),
          isFalse,
        );

        return http.Response('{}', 200);
      });

      final adapter = HttpAdapter(mockClient);
      await adapter.post(
        Uri.parse('https://example.com/token'),
        headers: {
          'Authorization': 'Basic original-value',
          'authorization': 'Basic overridden-value', // Varied case entry
        },
        body: {'code': '123'},
      );
    });
  });
}
