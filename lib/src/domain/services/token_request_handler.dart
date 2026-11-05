import 'dart:convert';
import '../abnf_validators.dart';
import '../entities/access_token.dart';
import '../entities/auth_code.dart';
import '../entities/client_registration.dart';
import '../entities/refresh_token.dart';
import '../ports/auth_code_repository.dart';
import '../ports/client_repository.dart';
import '../ports/crypto_service.dart';
import '../ports/token_repository.dart';

/// Represents the server's HTTP response for token requests.
class ServerTokenResponse {
  /// The HTTP status code of the response (e.g. 200, 400, 401).
  final int statusCode;

  /// The JSON body payload.
  final Map<String, dynamic> body;

  /// The HTTP headers (including Cache-Control and Pragma).
  final Map<String, String> headers;

  /// Creates a new [ServerTokenResponse] instance.
  const ServerTokenResponse({
    required this.statusCode,
    required this.body,
    required this.headers,
  });
}

/// Handler for the Token Endpoint (POST requests to /token).
class TokenRequestHandler {
  /// The repository for client registrations.
  final ClientRepository clientRepository;

  /// The repository for authorization codes.
  final AuthCodeRepository authCodeRepository;

  /// The repository for token entities.
  final TokenRepository tokenRepository;

  /// The cryptography service.
  final CryptoService cryptoService;

  static const _headers = {
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'Content-Type': 'application/json',
  };

  static const _unauthorizedHeaders = {
    ..._headers,
    'WWW-Authenticate': 'Basic',
  };

  static final RegExp _basicSchemePrefix = RegExp(r'^[Bb][Aa][Ss][Ii][Cc]\s+');

  /// Creates a new [TokenRequestHandler] instance.
  const TokenRequestHandler({
    required this.clientRepository,
    required this.authCodeRepository,
    required this.tokenRepository,
    required this.cryptoService,
  });

  /// Handles an incoming token request.
  Future<ServerTokenResponse> handle(
    Map<String, String> body, {
    String? authorizationHeader,
    bool isHttps = false,
  }) async {
    // 1. Enforce Transport Security (TLS)
    if (!isHttps) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_request',
          'error_description': 'HTTPS is required for the token endpoint.',
        },
        headers: _headers,
      );
    }

    // Normalize empty parameter values as omitted per Section 3.2 without mutating input map
    body = {
      for (final entry in body.entries)
        if (entry.value.isNotEmpty) entry.key: entry.value,
    };

    // 2. Client Authentication
    final credentials = _extractClientCredentials(body, authorizationHeader);
    if (credentials.error != null) {
      return credentials.error!;
    }

    final client = await clientRepository.findById(credentials.clientId!);
    if (client == null) {
      return _invalidClient('Client registration not found.');
    }

    final authError = _verifyClientSecret(client, credentials.clientSecret);
    if (authError != null) {
      return authError;
    }

    // 3. Grant Type routing
    final grantType = body['grant_type'];
    if (grantType == null) {
      return _badRequest('Missing grant_type parameter.');
    }

    if (!client.allowedGrantTypes.contains(grantType)) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'unauthorized_client',
          'error_description':
              'The client is not authorized for this grant type.',
        },
        headers: _headers,
      );
    }

    return switch (grantType) {
      'authorization_code' => _handleAuthorizationCode(body, client),
      'client_credentials' => _handleClientCredentials(body, client),
      'refresh_token' => _handleRefreshToken(body, client),
      _ => Future.value(
        const ServerTokenResponse(
          statusCode: 400,
          body: {
            'error': 'unsupported_grant_type',
            'error_description': 'Unsupported grant type.',
          },
          headers: _headers,
        ),
      ),
    };
  }

  ServerTokenResponse? _verifyClientSecret(
    ClientRegistration client,
    String? clientSecret,
  ) {
    if (client.clientType == ClientType.confidential) {
      if (clientSecret == null) {
        return _invalidClient('Client credentials required.');
      }
      final registeredHash = client.clientSecretHash;
      if (registeredHash == null ||
          !cryptoService.verifyPasswordHash(clientSecret, registeredHash)) {
        return _invalidClient('Client authentication failed.');
      }
    } else if (clientSecret != null) {
      // Public clients must not use a secret
      return _badRequest('Public clients must not provide a client secret.');
    }
    return null;
  }

  static ServerTokenResponse _badRequest(String description) =>
      ServerTokenResponse(
        statusCode: 400,
        body: {'error': 'invalid_request', 'error_description': description},
        headers: _headers,
      );

  static ServerTokenResponse _invalidClient(String description) =>
      ServerTokenResponse(
        statusCode: 401,
        body: {'error': 'invalid_client', 'error_description': description},
        headers: _unauthorizedHeaders,
      );

  static ({String? clientId, String? clientSecret, ServerTokenResponse? error})
  _credentialsError(ServerTokenResponse error) =>
      (clientId: null, clientSecret: null, error: error);

  static ({String? clientId, String? clientSecret, ServerTokenResponse? error})
  _extractClientCredentials(
    Map<String, String> body,
    String? authorizationHeader,
  ) {
    String? basicClientId;
    String? basicSecret;
    if (authorizationHeader != null && authorizationHeader.trim().isNotEmpty) {
      final basic = _parseBasicAuthorization(authorizationHeader.trim());
      if (basic.error != null) {
        return basic;
      }
      basicClientId = basic.clientId;
      basicSecret = basic.clientSecret;
    }

    final bodyClientId = body['client_id'];
    final bodySecret = body['client_secret'];

    if (basicClientId != null && bodySecret != null) {
      return _credentialsError(
        _badRequest('Multiple client authentication methods attempted.'),
      );
    }

    if (basicClientId != null &&
        bodyClientId != null &&
        bodyClientId != basicClientId) {
      return _credentialsError(
        _badRequest(
          'Conflicting client_id in Authorization header and request body.',
        ),
      );
    }

    final clientId = basicClientId ?? bodyClientId;
    final clientSecret = basicSecret ?? bodySecret;

    if (clientId == null) {
      return _credentialsError(_badRequest('Missing client_id.'));
    }

    if (!isValidVscharParam(clientId) ||
        (clientSecret != null && !vscharOptionalRegex.hasMatch(clientSecret))) {
      return _credentialsError(
        _badRequest(
          'Client credentials contain invalid characters or untrimmed whitespace.',
        ),
      );
    }

    return (clientId: clientId, clientSecret: clientSecret, error: null);
  }

  static ({String? clientId, String? clientSecret, ServerTokenResponse? error})
  _parseBasicAuthorization(String trimmedHeader) {
    if (!_basicSchemePrefix.hasMatch(trimmedHeader)) {
      return _credentialsError(
        _invalidClient('Unsupported Authorization header scheme.'),
      );
    }

    final base64Credentials = trimmedHeader
        .replaceFirst(_basicSchemePrefix, '')
        .trim();
    try {
      final decoded = utf8.decode(base64.decode(base64Credentials));
      final parts = decoded.split(':');
      if (parts.length != 2 || parts[0].isEmpty) {
        return _credentialsError(
          _invalidClient('Malformed Authorization header.'),
        );
      }
      final clientId = Uri.decodeQueryComponent(parts[0]);
      final clientSecret = Uri.decodeQueryComponent(parts[1]);
      if (!isValidVscharParam(clientId) ||
          !vscharOptionalRegex.hasMatch(clientSecret)) {
        return _credentialsError(
          _invalidClient(
            'Client credentials in Authorization header violate VSCHAR syntax.',
          ),
        );
      }
      return (clientId: clientId, clientSecret: clientSecret, error: null);
    } on Object catch (_) {
      return _credentialsError(
        _invalidClient('Malformed Authorization header.'),
      );
    }
  }

  Future<ServerTokenResponse> _handleAuthorizationCode(
    Map<String, String> body,
    ClientRegistration client,
  ) async {
    final code = body['code'];
    final codeVerifier = body['code_verifier'];

    if (code == null || code.isEmpty || !isValidVscharParam(code)) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_request',
          'error_description': 'Missing or malformed code parameter.',
        },
        headers: _headers,
      );
    }

    if (codeVerifier == null ||
        codeVerifier.isEmpty ||
        !codeVerifierAbnfRegex.hasMatch(codeVerifier)) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_request',
          'error_description': 'Missing or malformed code_verifier parameter.',
        },
        headers: _headers,
      );
    }

    final authCode = await authCodeRepository.findByCode(code);
    if (authCode == null) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_grant',
          'error_description': 'Invalid authorization code.',
        },
        headers: _headers,
      );
    }

    // Verify client binding
    if (authCode.clientId != client.clientId) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_grant',
          'error_description':
              'Authorization code was not issued to this client.',
        },
        headers: _headers,
      );
    }

    // Per OAuth 2.1 Sections 4.1.3 & 10.2, redirect_uri is optional at /token;
    // if provided, enforce exact string match against the bound redirectUri.
    final reqRedirectUri = body['redirect_uri'];
    if (reqRedirectUri != null &&
        reqRedirectUri != authCode.redirectUri.toString()) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_grant',
          'error_description':
              'Provided redirect_uri does not match the authorization code.',
        },
        headers: _headers,
      );
    }

    // Enforce PKCE verifier check (OAuth 2.1 requires S256 exclusively)
    if (authCode.codeChallengeMethod != 'S256') {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_grant',
          'error_description':
              'Only S256 code_challenge_method is supported in OAuth 2.1.',
        },
        headers: _headers,
      );
    }

    final challengeCheck = cryptoService.hashAndBase64UrlEncode(codeVerifier);
    if (!CryptoService.safeEquals(challengeCheck, authCode.codeChallenge)) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_grant',
          'error_description': 'PKCE verification failed.',
        },
        headers: _headers,
      );
    }

    // Code reuse check (Must revoke everything issued by it, even if expired)
    if (authCode.isUsed) {
      return _revokeCompromisedCodeFamily(authCode);
    }

    // Check expiration
    if (authCode.isExpired) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_grant',
          'error_description': 'Authorization code has expired.',
        },
        headers: _headers,
      );
    }

    // Atomically consume authorization code (Compare-And-Swap false -> true)
    final consumed = await authCodeRepository.tryConsume(code);
    if (!consumed) {
      return _revokeCompromisedCodeFamily(authCode);
    }

    // Build and persist tokens carrying authorizationCode lineage
    final pair = _buildTokenPair(
      clientId: client.clientId,
      userId: authCode.userId,
      scope: authCode.scope,
      issueRefreshToken: client.allowedGrantTypes.contains('refresh_token'),
      authorizationCode: authCode.code,
    );
    final saved = await tokenRepository.saveIssuedTokens(
      accessToken: pair.accessToken,
      refreshToken: pair.refreshToken,
    );
    if (!saved) {
      return _revokeCompromisedCodeFamily(authCode);
    }

    return pair.response;
  }

  Future<ServerTokenResponse> _handleClientCredentials(
    Map<String, String> body,
    ClientRegistration client,
  ) async {
    if (client.clientType != ClientType.confidential) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_client',
          'error_description':
              'Client credentials grant is only for confidential clients.',
        },
        headers: _headers,
      );
    }

    final scopeResult = _resolveTokenScope(
      requestedScope: body['scope'],
      allowedScopes: client.allowedScopes,
      defaultScope: client.allowedScopes.join(' '),
      disallowedDescription: 'Requested scope is not allowed.',
    );
    if (scopeResult.error != null) {
      return scopeResult.error!;
    }

    final pair = _buildTokenPair(
      clientId: client.clientId,
      userId: null,
      scope: scopeResult.scope,
      issueRefreshToken: false,
    );
    await tokenRepository.saveAccessToken(pair.accessToken);
    return pair.response;
  }

  Future<ServerTokenResponse> _handleRefreshToken(
    Map<String, String> body,
    ClientRegistration client,
  ) async {
    final refreshTokenVal = body['refresh_token'];
    if (refreshTokenVal == null ||
        refreshTokenVal.isEmpty ||
        !isValidVscharParam(refreshTokenVal)) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_request',
          'error_description': 'Missing or malformed refresh_token parameter.',
        },
        headers: _headers,
      );
    }

    final hashed = cryptoService.hashString(refreshTokenVal);
    final oldRefreshToken = await tokenRepository.findRefreshTokenByHash(
      hashed,
    );
    if (oldRefreshToken == null) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_grant',
          'error_description': 'Invalid refresh token.',
        },
        headers: _headers,
      );
    }

    // Validate client binding
    if (oldRefreshToken.clientId != client.clientId) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_grant',
          'error_description': 'Refresh token client ID mismatch.',
        },
        headers: _headers,
      );
    }

    // Replay pre-check: if already revoked and outside grace window (or grace already consumed),
    // trigger cascading family revocation immediately.
    if (oldRefreshToken.isRevoked) {
      final revokedAt = oldRefreshToken.revokedAt;
      final isWithinGrace =
          revokedAt != null &&
          DateTime.now().difference(revokedAt) <= const Duration(seconds: 30);
      final alreadyUsedGrace = oldRefreshToken.usedInGraceWindow;

      if (!isWithinGrace || alreadyUsedGrace) {
        return _revokeCompromisedRefreshFamily(oldRefreshToken);
      }
    }

    // Expiration check
    if (oldRefreshToken.isExpired) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_grant',
          'error_description': 'Refresh token has expired.',
        },
        headers: _headers,
      );
    }

    // Scope validation (MUST run before mutating/revoking oldRefreshToken)
    final scopeResult = _resolveTokenScope(
      requestedScope: body['scope'],
      allowedScopes: oldRefreshToken.scope?.split(' ').toSet() ?? const {},
      defaultScope: oldRefreshToken.scope,
      disallowedDescription:
          'Requested scope exceeds originally granted scope.',
    );
    if (scopeResult.error != null) {
      return scopeResult.error!;
    }

    // Atomically rotate refresh token and persist replacement token pair
    final pair = _buildTokenPair(
      clientId: client.clientId,
      userId: oldRefreshToken.userId,
      scope: scopeResult.scope,
      issueRefreshToken: true,
      authorizationCode: oldRefreshToken.authorizationCode,
      refreshExpiresAt: oldRefreshToken.expiresAt,
    );
    final rotated = await tokenRepository.rotateRefreshToken(
      oldTokenHash: hashed,
      newAccessToken: pair.accessToken,
      newRefreshToken: pair.refreshToken!,
    );
    if (!rotated) {
      return _revokeCompromisedRefreshFamily(oldRefreshToken);
    }

    return pair.response;
  }

  static ({String? scope, ServerTokenResponse? error}) _resolveTokenScope({
    required String? requestedScope,
    required Set<String> allowedScopes,
    required String? defaultScope,
    required String disallowedDescription,
  }) {
    if (requestedScope == null || requestedScope.isEmpty) {
      return (scope: defaultScope, error: null);
    }
    final parsedScopes = parseAndDeduplicateScope(requestedScope);
    if (parsedScopes == null) {
      return (
        scope: null,
        error: const ServerTokenResponse(
          statusCode: 400,
          body: {
            'error': 'invalid_scope',
            'error_description': 'Requested scope is malformed.',
          },
          headers: _headers,
        ),
      );
    }
    for (final token in parsedScopes) {
      if (!allowedScopes.contains(token)) {
        return (
          scope: null,
          error: ServerTokenResponse(
            statusCode: 400,
            body: {
              'error': 'invalid_scope',
              'error_description': disallowedDescription,
            },
            headers: _headers,
          ),
        );
      }
    }
    return (scope: parsedScopes.join(' '), error: null);
  }

  Future<ServerTokenResponse> _revokeCompromisedCodeFamily(
    AuthCode authCode,
  ) async {
    await tokenRepository.revokeByAuthorizationCode(authCode.code);
    await tokenRepository.revokeAllTokensForClientAndUser(
      authCode.clientId,
      authCode.userId,
    );
    return const ServerTokenResponse(
      statusCode: 400,
      body: {
        'error': 'invalid_grant',
        'error_description': 'Authorization code has already been used.',
      },
      headers: _headers,
    );
  }

  Future<ServerTokenResponse> _revokeCompromisedRefreshFamily(
    RefreshToken token,
  ) async {
    if (token.authorizationCode != null) {
      await tokenRepository.revokeByAuthorizationCode(token.authorizationCode!);
    }
    await tokenRepository.revokeAllTokensForClientAndUser(
      token.clientId,
      token.userId,
    );
    return const ServerTokenResponse(
      statusCode: 400,
      body: {
        'error': 'invalid_grant',
        'error_description':
            'Refresh token has already been used. Grant revoked.',
      },
      headers: _headers,
    );
  }

  ({
    AccessToken accessToken,
    RefreshToken? refreshToken,
    ServerTokenResponse response,
  })
  _buildTokenPair({
    required String clientId,
    required String? userId,
    required String? scope,
    required bool issueRefreshToken,
    String? authorizationCode,
    DateTime? refreshExpiresAt,
  }) {
    final rawAccessToken = cryptoService.generateRandomEntropyString();
    final hashedAccessToken = cryptoService.hashString(rawAccessToken);
    final accessExpiresAt = DateTime.now().add(const Duration(hours: 1));

    final accessTokenEntity = AccessToken(
      tokenHash: hashedAccessToken,
      clientId: clientId,
      expiresAt: accessExpiresAt,
      userId: userId,
      scope: scope,
      authorizationCode: authorizationCode,
    );

    String? rawRefreshToken;
    RefreshToken? refreshTokenEntity;
    if (issueRefreshToken) {
      rawRefreshToken = cryptoService.generateRandomEntropyString();
      final hashedRefreshToken = cryptoService.hashString(rawRefreshToken);
      final effectiveRefreshExpiresAt =
          refreshExpiresAt ?? DateTime.now().add(const Duration(days: 30));

      refreshTokenEntity = RefreshToken(
        tokenHash: hashedRefreshToken,
        clientId: clientId,
        expiresAt: effectiveRefreshExpiresAt,
        userId: userId,
        scope: scope,
        authorizationCode: authorizationCode,
      );
    }

    final body = <String, dynamic>{
      'access_token': rawAccessToken,
      'token_type': 'Bearer',
      'expires_in': 3600,
    };
    if (rawRefreshToken != null) {
      body['refresh_token'] = rawRefreshToken;
    }
    if (scope != null && scope.isNotEmpty) {
      body['scope'] = scope;
    }

    return (
      accessToken: accessTokenEntity,
      refreshToken: refreshTokenEntity,
      response: ServerTokenResponse(
        statusCode: 200,
        body: body,
        headers: _headers,
      ),
    );
  }
}
