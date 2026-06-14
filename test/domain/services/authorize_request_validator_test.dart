import 'package:oauth21/oauth21.dart';
import 'package:test/test.dart';

class InMemoryClientRepository implements ClientRepository {
  final Map<String, ClientRegistration> _clients = {};

  void addClient(ClientRegistration client) {
    _clients[client.clientId] = client;
  }

  @override
  Future<ClientRegistration?> findById(String clientId) async {
    return _clients[clientId];
  }
}

void main() {
  group('AuthorizeRequestValidator', () {
    late InMemoryClientRepository clientRepo;
    late AuthorizeRequestValidator validator;
    late ClientRegistration testClient;

    setUp(() {
      clientRepo = InMemoryClientRepository();
      validator = AuthorizeRequestValidator(clientRepo);

      testClient = ClientRegistration(
        clientId: 'client-123',
        clientType: ClientType.confidential,
        clientSecretHash: 'hashed-secret',
        redirectUris: {
          Uri.parse('https://example.com/cb'),
          Uri.parse('http://127.0.0.1:8000/cb'),
          Uri.parse('http://[::1]:8000/cb'),
          Uri.parse('http://localhost:8000/cb'),
        },
        allowedScopes: {'read', 'write'},
      );
      clientRepo.addClient(testClient);
    });

    Map<String, List<String>> createParams({
      String? clientId = 'client-123',
      String? redirectUri = 'https://example.com/cb',
      String? responseType = 'code',
      String? state = 'state-xyz',
      String? codeChallenge = 'challengechallengechallengechallengechallenge',
      String? codeChallengeMethod = 'S256',
      String? scope = 'read',
    }) {
      final map = <String, List<String>>{};
      if (clientId != null) map['client_id'] = [clientId];
      if (redirectUri != null) map['redirect_uri'] = [redirectUri];
      if (responseType != null) map['response_type'] = [responseType];
      if (state != null) map['state'] = [state];
      if (codeChallenge != null) map['code_challenge'] = [codeChallenge];
      if (codeChallengeMethod != null) {
        map['code_challenge_method'] = [codeChallengeMethod];
      }
      if (scope != null) map['scope'] = [scope];
      return map;
    }

    test('should validate a correct authorize request successfully', () async {
      final params = createParams();
      final result = await validator.validate(params);

      expect(result.isValid, isTrue);
      expect(result.client?.clientId, equals('client-123'));
      expect(
        result.validatedRedirectUri,
        equals(Uri.parse('https://example.com/cb')),
      );
      expect(result.state, equals('state-xyz'));
      expect(result.requestedScopes, contains('read'));
      expect(
        result.codeChallenge,
        equals('challengechallengechallengechallengechallenge'),
      );
      expect(result.codeChallengeMethod, equals('S256'));
    });

    test('should validate with code_challenge_method plain', () async {
      final params = createParams(codeChallengeMethod: 'plain');
      final result = await validator.validate(params);

      expect(result.isValid, isTrue);
      expect(result.codeChallengeMethod, equals('plain'));
    });

    test(
      'should default redirectUri if omitted and client has only one',
      () async {
        final singleRedirectClient = ClientRegistration(
          clientId: 'client-single',
          clientType: ClientType.public,
          redirectUris: {Uri.parse('https://example.com/single')},
          allowedScopes: {'read'},
        );
        clientRepo.addClient(singleRedirectClient);

        final params = createParams(
          clientId: 'client-single',
          redirectUri: null,
        );
        final result = await validator.validate(params);

        expect(result.isValid, isTrue);
        expect(
          result.validatedRedirectUri,
          equals(Uri.parse('https://example.com/single')),
        );
      },
    );

    test('should allow loopback IP with variable port', () async {
      final params = createParams(redirectUri: 'http://127.0.0.1:9999/cb');
      final result = await validator.validate(params);

      expect(result.isValid, isTrue);
      expect(
        result.validatedRedirectUri,
        equals(Uri.parse('http://127.0.0.1:9999/cb')),
      );
    });

    test('should allow IPv6 loopback IP with variable port', () async {
      final params = createParams(redirectUri: 'http://[::1]:9999/cb');
      final result = await validator.validate(params);

      expect(result.isValid, isTrue);
      expect(
        result.validatedRedirectUri,
        equals(Uri.parse('http://[::1]:9999/cb')),
      );
    });

    test('should allow localhost with variable port', () async {
      final params = createParams(redirectUri: 'http://localhost:9999/cb');
      final result = await validator.validate(params);

      expect(result.isValid, isTrue);
      expect(
        result.validatedRedirectUri,
        equals(Uri.parse('http://localhost:9999/cb')),
      );
    });

    test('should reject duplicate client_id (non-redirectable)', () async {
      final params = createParams();
      params['client_id'] = ['client-123', 'client-456'];

      final result = await validator.validate(params);
      expect(result.isValid, isFalse);
      expect(result.isRedirectable, isFalse);
      expect(result.errorCode, equals('invalid_request'));
    });

    test('should reject duplicate redirect_uri (non-redirectable)', () async {
      final params = createParams();
      params['redirect_uri'] = ['https://example.com/cb', 'https://attack.com'];

      final result = await validator.validate(params);
      expect(result.isValid, isFalse);
      expect(result.isRedirectable, isFalse);
      expect(result.errorCode, equals('invalid_request'));
    });

    test('should reject missing client_id (non-redirectable)', () async {
      final params = createParams(clientId: null);

      final result = await validator.validate(params);
      expect(result.isValid, isFalse);
      expect(result.isRedirectable, isFalse);
      expect(result.errorCode, equals('invalid_request'));
    });

    test('should reject untrimmed client_id (non-redirectable)', () async {
      final params = createParams(clientId: 'client-123 ');

      final result = await validator.validate(params);
      expect(result.isValid, isFalse);
      expect(result.isRedirectable, isFalse);
      expect(result.errorCode, equals('invalid_request'));
    });

    test('should reject non-existent client (non-redirectable)', () async {
      final params = createParams(clientId: 'non-existent');

      final result = await validator.validate(params);
      expect(result.isValid, isFalse);
      expect(result.isRedirectable, isFalse);
      expect(result.errorCode, equals('invalid_client'));
    });

    test(
      'should reject missing redirect_uri if client has multiple registered',
      () async {
        final params = createParams(redirectUri: null);

        final result = await validator.validate(params);
        expect(result.isValid, isFalse);
        expect(result.isRedirectable, isFalse);
        expect(result.errorCode, equals('invalid_request'));
      },
    );

    test('should reject malformed redirect_uri (non-redirectable)', () async {
      final params = createParams(redirectUri: 'http://example.com:abc');

      final result = await validator.validate(params);
      expect(result.isValid, isFalse);
      expect(result.isRedirectable, isFalse);
      expect(result.errorCode, equals('invalid_request'));
      expect(
        result.errorDescription,
        equals('Malformed redirect_uri parameter.'),
      );
    });

    test(
      'should reject unregistered redirect_uri (non-redirectable)',
      () async {
        final params = createParams(redirectUri: 'https://unregistered.com/cb');

        final result = await validator.validate(params);
        expect(result.isValid, isFalse);
        expect(result.isRedirectable, isFalse);
        expect(result.errorCode, equals('invalid_request'));
      },
    );

    test(
      'should reject loopback redirect if hosts differ (non-redirectable)',
      () async {
        final params = createParams(redirectUri: 'http://127.0.0.2:8000/cb');

        final result = await validator.validate(params);
        expect(result.isValid, isFalse);
        expect(result.isRedirectable, isFalse);
        expect(result.errorCode, equals('invalid_request'));
      },
    );

    test('should reject state parameter pollution (redirectable)', () async {
      final params = createParams();
      params['state'] = ['state-1', 'state-2'];

      final result = await validator.validate(params);
      expect(result.isValid, isFalse);
      expect(result.isRedirectable, isTrue);
      expect(result.errorCode, equals('invalid_request'));
      expect(result.state, isNull);
    });

    test('should reject missing state (redirectable)', () async {
      final params = createParams(state: null);

      final result = await validator.validate(params);
      expect(result.isValid, isFalse);
      expect(result.isRedirectable, isTrue);
      expect(result.errorCode, equals('invalid_request'));
    });

    test('should reject untrimmed state (redirectable)', () async {
      final params = createParams(state: 'state-xyz ');

      final result = await validator.validate(params);
      expect(result.isValid, isFalse);
      expect(result.isRedirectable, isTrue);
      expect(result.errorCode, equals('invalid_request'));
    });

    test(
      'should reject parameter pollution on other fields (redirectable)',
      () async {
        final params = createParams();
        params['response_type'] = ['code', 'token'];

        final result = await validator.validate(params);
        expect(result.isValid, isFalse);
        expect(result.isRedirectable, isTrue);
        expect(result.errorCode, equals('invalid_request'));
        expect(result.state, equals('state-xyz'));
      },
    );

    test('should reject missing response_type (redirectable)', () async {
      final params = createParams(responseType: null);

      final result = await validator.validate(params);
      expect(result.isValid, isFalse);
      expect(result.isRedirectable, isTrue);
      expect(result.errorCode, equals('invalid_request'));
    });

    test('should reject unsupported response_type (redirectable)', () async {
      final params = createParams(responseType: 'token');

      final result = await validator.validate(params);
      expect(result.isValid, isFalse);
      expect(result.isRedirectable, isTrue);
      expect(result.errorCode, equals('unsupported_response_type'));
    });

    test('should reject missing code_challenge (redirectable)', () async {
      final params = createParams(codeChallenge: null);

      final result = await validator.validate(params);
      expect(result.isValid, isFalse);
      expect(result.isRedirectable, isTrue);
      expect(result.errorCode, equals('invalid_request'));
    });

    test('should reject malformed code_challenge (redirectable)', () async {
      final params = createParams(codeChallenge: 'too-short');

      final result = await validator.validate(params);
      expect(result.isValid, isFalse);
      expect(result.isRedirectable, isTrue);
      expect(result.errorCode, equals('invalid_request'));
    });

    test(
      'should reject missing code_challenge_method (redirectable)',
      () async {
        final params = createParams(codeChallengeMethod: null);

        final result = await validator.validate(params);
        expect(result.isValid, isFalse);
        expect(result.isRedirectable, isTrue);
        expect(result.errorCode, equals('invalid_request'));
      },
    );

    test(
      'should reject unsupported code_challenge_method (redirectable)',
      () async {
        final params = createParams(codeChallengeMethod: 'MD5');

        final result = await validator.validate(params);
        expect(result.isValid, isFalse);
        expect(result.isRedirectable, isTrue);
        expect(result.errorCode, equals('invalid_request'));
      },
    );

    test('should reject empty token inside scope (redirectable)', () async {
      final params = createParams(scope: 'read  write');

      final result = await validator.validate(params);
      expect(result.isValid, isFalse);
      expect(result.isRedirectable, isTrue);
      expect(result.errorCode, equals('invalid_request'));
    });

    test(
      'should reject invalid characters inside scope token (redirectable)',
      () async {
        final params = createParams(scope: 'read write"');

        final result = await validator.validate(params);
        expect(result.isValid, isFalse);
        expect(result.isRedirectable, isTrue);
        expect(result.errorCode, equals('invalid_request'));
      },
    );

    test('should reject unregistered scope token (redirectable)', () async {
      final params = createParams(scope: 'read admin');

      final result = await validator.validate(params);
      expect(result.isValid, isFalse);
      expect(result.isRedirectable, isTrue);
      expect(result.errorCode, equals('invalid_scope'));
    });

    test(
      'should default to client allowedScopes if scope is omitted',
      () async {
        final params = createParams(scope: null);

        final result = await validator.validate(params);
        expect(result.isValid, isTrue);
        expect(result.requestedScopes, equals(testClient.allowedScopes));
      },
    );

    test('should reject loopback redirect if path contains traversal '
        'injections (non-redirectable)', () async {
      final params = createParams(
        redirectUri: 'http://127.0.0.1:9999/cb/../malicious',
      );

      final result = await validator.validate(params);
      expect(result.isValid, isFalse);
      expect(result.isRedirectable, isFalse);
      expect(result.errorCode, equals('invalid_request'));
    });

    test('should successfully validate localhost loopback regardless of '
        'case variation', () async {
      final upperCaseLocalhostParams = createParams(
        redirectUri: 'http://LOCALHOST:9999/cb',
      );
      final mixedCaseLocalhostParams = createParams(
        redirectUri: 'http://LocalHost:9999/cb',
      );

      final upperResult = await validator.validate(upperCaseLocalhostParams);
      final mixedResult = await validator.validate(mixedCaseLocalhostParams);

      expect(upperResult.isValid, isTrue);
      expect(
        upperResult.validatedRedirectUri,
        equals(Uri.parse('http://LOCALHOST:9999/cb')),
      );

      expect(mixedResult.isValid, isTrue);
      expect(
        mixedResult.validatedRedirectUri,
        equals(Uri.parse('http://LocalHost:9999/cb')),
      );
    });
  });
}
