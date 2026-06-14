// Example scripts use print to demonstrate usage in the console.
// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:oauth21/client.dart';
import 'package:oauth21/server.dart';
import 'package:shelf/shelf.dart' as shelf;
import 'package:shelf/shelf_io.dart' as shelf_io;

void main() async {
  print('=== OAuth 2.1 End-to-End Client & Server Integration Demo ===');

  // Initialize in-memory servers and databases
  final clientRepo = InMemoryClientRepository();
  final tokenRepo = InMemoryTokenRepository();
  final authCodeRepo = InMemoryAuthCodeRepository(tokenRepo);
  final cryptoService = SHA256CryptoService();

  // Register public client (no secret, supports auth code and refresh token)
  final clientRegistration = ClientRegistration(
    clientId: 'demo-public-client',
    clientType: ClientType.public,
    allowedGrantTypes: const {'authorization_code', 'refresh_token'},
    redirectUris: {Uri.parse('http://localhost:8080/callback')},
    allowedScopes: const {'read', 'write'},
  );
  clientRepo.register(clientRegistration);

  // Initialize validators/handlers
  final authorizeValidator = AuthorizeRequestValidator(clientRepo);
  final tokenRequestHandler = TokenRequestHandler(
    clientRepository: clientRepo,
    authCodeRepository: authCodeRepo,
    tokenRepository: tokenRepo,
    cryptoService: cryptoService,
  );

  // Manual request router function
  Future<shelf.Response> handleRoutes(shelf.Request request) async {
    final path = request.url.path;

    if (request.method == 'GET' && path == 'authorize') {
      return handleAuthorizeRequest(
        request,
        validator: authorizeValidator,
        onConsentRequired: (req, validationResult) async {
          print('[Server] Authorize request is valid. User consent granted.');

          // Generate an authorization code
          final code = cryptoService.generateRandomEntropyString();

          // Save authorization code details to the repository
          final authCode = AuthCode(
            code: code,
            clientId: validationResult.client!.clientId,
            redirectUri: validationResult.validatedRedirectUri!,
            expiresAt: DateTime.now().add(const Duration(minutes: 5)),
            userId: 'user-42',
            scope: validationResult.requestedScopes.join(' '),
            codeChallenge: validationResult.codeChallenge!,
            codeChallengeMethod: validationResult.codeChallengeMethod!,
          );
          await authCodeRepo.save(authCode);

          // Redirect back with the code
          return redirectWithAuthorizationCode(
            redirectUri: validationResult.validatedRedirectUri!,
            code: code,
            state: validationResult.state!,
            issuer: 'http://localhost:8080',
          );
        },
      );
    } else if (request.method == 'POST' && path == 'token') {
      // We set isHttps to true to simulate production TLS-terminated requests
      return handleTokenRequest(request, handler: tokenRequestHandler);
    } else {
      return shelf.Response.notFound('Not Found');
    }
  }

  // Start the local server
  final server = await shelf_io.serve(handleRoutes, 'localhost', 8080);
  print('[Server] Running at http://${server.address.host}:${server.port}\n');

  // Initialize the client
  // The client requires a secure authorization endpoint URL to pass syntax validation.
  final httpClient = http.Client();
  final oauthClient = OAuthClient(
    authorizationEndpoint: 'https://localhost:8080/authorize',
    tokenEndpoint: 'http://localhost:8080/token',
    clientId: 'demo-public-client',
    httpClient: HttpAdapter(httpClient),
    expectedIssuer: 'http://localhost:8080',
  );

  try {
    print('--- Step 1: Generate PKCE Secrets ---');
    final codeVerifier = CodeVerifier.generate();
    final codeChallenge = CodeChallenge.s256(codeVerifier);
    print('[Client] Code Verifier generated (masked in toString()).');
    print('[Client] Code Challenge S256 calculated: ${codeChallenge.value}');

    print('\n--- Step 2: Client initiates Authorize Request ---');
    final authRequest = oauthClient.createAuthorizationRequest(
      redirectUri: Uri.parse('http://localhost:8080/callback'),
      state: 'random-secure-state-token',
      codeChallenge: codeChallenge,
      scope: 'read write',
    );

    // Convert the https validation URI to the actual local http endpoint for request
    final authUri = authRequest.toUri().replace(scheme: 'http');
    print('[Client] Redirecting user to: $authUri');

    // Simulate browser request to authorization endpoint
    // followRedirects is false to intercept code/state on the redirection
    final req = http.Request('GET', authUri)..followRedirects = false;
    final streamRes = await httpClient.send(req);
    final res = await http.Response.fromStream(streamRes);

    final locationHeader = res.headers['location'];
    if (locationHeader == null) {
      print('[Client] Error: Did not receive Location header redirect!');
      return;
    }
    print('[Client] Intercepted redirect Location: $locationHeader');

    print('\n--- Step 3: Validate Redirect Callback ---');
    final callbackUri = Uri.parse(locationHeader);
    const parser = DefaultRequestParser();
    final redirectParams = parser.parseRedirect(callbackUri);

    oauthClient.validateCallback(
      redirectParams,
      expectedState: 'random-secure-state-token',
    );
    print('[Client] Callback parameters verified successfully.');

    print('\n--- Step 4: Exchange Authorization Code for Tokens ---');
    final tokenResult = await oauthClient.exchangeCode(
      code: redirectParams.code!,
      codeVerifier: codeVerifier,
      redirectUri: Uri.parse('http://localhost:8080/callback'),
    );

    String? accessTokenVal;
    String? refreshTokenVal;

    switch (tokenResult) {
      case TokenSuccess(:final accessToken, :final refreshToken):
        accessTokenVal = accessToken;
        refreshTokenVal = refreshToken;
        print('[Client] Access Token obtained successfully: $accessTokenVal');
        print('[Client] Refresh Token obtained: $refreshTokenVal');
      case TokenError(:final error, :final errorDescription):
        print('[Client] Token exchange failed: $error - $errorDescription');
        return;
    }

    print('\n--- Step 5: Refresh the Access Token (Token Rotation) ---');
    if (refreshTokenVal != null) {
      final refreshResult = await oauthClient.exchangeRefreshToken(
        refreshTokenVal,
      );

      switch (refreshResult) {
        case TokenSuccess(:final accessToken, :final refreshToken):
          print('[Client] Refreshed Access Token successfully: $accessToken');
          print('[Client] New Refresh Token obtained: $refreshToken');
          // Save the rotated refresh token value
          refreshTokenVal = refreshToken;
        case TokenError(:final error, :final errorDescription):
          print('[Client] Token refresh failed: $error - $errorDescription');
      }
    }

    print('\n--- Step 6: Simulate Replay Attack (Cascading Revocation) ---');
    print(
      '[Attacker] First reuse attempt of the revoked refresh token (within grace window)...',
    );
    final replayResult1 = await oauthClient.exchangeRefreshToken(
      tokenResult.refreshToken!,
    );

    switch (replayResult1) {
      case TokenSuccess(:final accessToken, :final refreshToken):
        print(
          '[Server] Allowed first retry request within 30s grace window.\n'
          '         Access Token: $accessToken\n'
          '         Refresh Token: $refreshToken',
        );
      case TokenError(:final error, :final errorDescription):
        print('[Server] Replay blocked: $error - $errorDescription');
    }

    print(
      '\n[Attacker] Second reuse attempt of the same revoked refresh token...',
    );
    final replayResult2 = await oauthClient.exchangeRefreshToken(
      tokenResult.refreshToken!,
    );

    switch (replayResult2) {
      case TokenSuccess():
        print('[Attacker] SECURITY FAILURE: Replay succeeded twice!');
      case TokenError(:final error, :final errorDescription):
        print(
          '[Server] SECURITY SUCCESS: Replay blocked on second attempt: $error - $errorDescription\n'
          '         (triggered cascading revocation for all client/user tokens)',
        );
    }
  } finally {
    print('\n--- Step 7: Clean Up ---');
    httpClient.close();
    await server.close(force: true);
    print('[System] Local server shut down. Demo completed.');
  }
}

// ==========================================
// In-Memory Database / Repositories for Demo
// ==========================================

class InMemoryClientRepository implements ClientRepository {
  final Map<String, ClientRegistration> _clients = {};

  void register(ClientRegistration client) {
    _clients[client.clientId] = client;
  }

  @override
  Future<ClientRegistration?> findById(String clientId) async {
    return _clients[clientId];
  }
}

class InMemoryAuthCodeRepository implements AuthCodeRepository {
  final Map<String, AuthCode> _codes = {};
  final InMemoryTokenRepository tokenRepository;

  InMemoryAuthCodeRepository(this.tokenRepository);

  @override
  Future<AuthCode?> findByCode(String code) async {
    return _codes[code];
  }

  @override
  Future<void> save(AuthCode authCode) async {
    _codes[authCode.code] = authCode;
  }

  @override
  Future<void> markAsUsed(String code) async {
    final existing = _codes[code];
    if (existing != null) {
      _codes[code] = existing.copyWith(isUsed: true);
    }
  }

  @override
  Future<void> revokeTokensForCode(String code) async {
    await tokenRepository.revokeAll();
  }
}

class InMemoryTokenRepository implements TokenRepository {
  final Map<String, AccessToken> _accessTokens = {};
  final Map<String, RefreshToken> _refreshTokens = {};

  Future<void> revokeAll() async {
    _accessTokens.clear();
    for (final entry in _refreshTokens.entries) {
      _refreshTokens[entry.key] = entry.value.copyWith(
        isRevoked: true,
        revokedAt: DateTime.now(),
      );
    }
  }

  @override
  Future<void> saveAccessToken(AccessToken token) async {
    _accessTokens[token.tokenHash] = token;
  }

  @override
  Future<void> saveRefreshToken(RefreshToken token) async {
    _refreshTokens[token.tokenHash] = token;
  }

  @override
  Future<AccessToken?> findAccessTokenByHash(String hash) async {
    return _accessTokens[hash];
  }

  @override
  Future<RefreshToken?> findRefreshTokenByHash(String hash) async {
    return _refreshTokens[hash];
  }

  @override
  Future<void> revokeRefreshTokenByHash(String hash) async {
    final existing = _refreshTokens[hash];
    if (existing != null) {
      _refreshTokens[hash] = existing.copyWith(
        isRevoked: true,
        revokedAt: DateTime.now(),
      );
    }
  }

  @override
  Future<void> revokeAllTokensForClientAndUser(
    String clientId,
    String? userId,
  ) async {
    await revokeAll();
  }
}

class SHA256CryptoService implements CryptoService {
  final _random = Random.secure();

  @override
  String hashString(String input) {
    return sha256.convert(utf8.encode(input)).toString();
  }

  @override
  String hashAndBase64UrlEncode(String input) {
    final bytes = sha256.convert(utf8.encode(input)).bytes;
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  @override
  String generateRandomEntropyString([int bits = 256]) {
    final bytes = List<int>.generate(bits ~/ 8, (_) => _random.nextInt(256));
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  @override
  bool verifyPasswordHash(String password, String passwordHash) {
    return hashString(password) == passwordHash;
  }
}
