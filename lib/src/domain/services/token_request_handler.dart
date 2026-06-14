import 'dart:convert';
import '../entities/access_token.dart';
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
    bool isHttps = true,
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

    // 2. Client Authentication
    String? clientId;
    String? clientSecret;
    var attemptedBasic = false;
    var attemptedBody = false;

    if (authorizationHeader != null &&
        authorizationHeader.startsWith('Basic ')) {
      attemptedBasic = true;
      final base64Credentials = authorizationHeader.substring(6).trim();
      try {
        final decoded = utf8.decode(base64.decode(base64Credentials));
        final parts = decoded.split(':');
        if (parts.length == 2) {
          clientId = Uri.decodeComponent(parts[0]);
          clientSecret = Uri.decodeComponent(parts[1]);
        }
      } on Exception catch (_) {
        return const ServerTokenResponse(
          statusCode: 401,
          body: {
            'error': 'invalid_client',
            'error_description': 'Malformed Authorization header.',
          },
          headers: _headers,
        );
      }
    }

    if (body['client_secret'] != null) {
      attemptedBody = true;
      clientId = body['client_id'];
      clientSecret = body['client_secret'];
    }

    if (attemptedBasic && attemptedBody) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_request',
          'error_description':
              'Multiple client authentication methods attempted.',
        },
        headers: _headers,
      );
    }

    if (clientId == null && body['client_id'] != null) {
      clientId = body['client_id'];
    }

    if (clientId == null) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_request',
          'error_description': 'Missing client_id.',
        },
        headers: _headers,
      );
    }

    final client = await clientRepository.findById(clientId);
    if (client == null) {
      return const ServerTokenResponse(
        statusCode: 401,
        body: {
          'error': 'invalid_client',
          'error_description': 'Client registration not found.',
        },
        headers: _headers,
      );
    }

    // Authenticate confidential client
    if (client.clientType == ClientType.confidential) {
      if (clientSecret == null) {
        return const ServerTokenResponse(
          statusCode: 401,
          body: {
            'error': 'invalid_client',
            'error_description': 'Client credentials required.',
          },
          headers: _headers,
        );
      }
      final registeredHash = client.clientSecretHash;
      if (registeredHash == null ||
          !cryptoService.verifyPasswordHash(clientSecret, registeredHash)) {
        return const ServerTokenResponse(
          statusCode: 401,
          body: {
            'error': 'invalid_client',
            'error_description': 'Client authentication failed.',
          },
          headers: _headers,
        );
      }
    } else {
      // Public clients must not use a secret
      if (clientSecret != null) {
        return const ServerTokenResponse(
          statusCode: 400,
          body: {
            'error': 'invalid_request',
            'error_description':
                'Public clients must not provide a client secret.',
          },
          headers: _headers,
        );
      }
    }

    // 3. Grant Type routing
    final grantType = body['grant_type'];
    if (grantType == null || grantType.isEmpty) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_request',
          'error_description': 'Missing grant_type parameter.',
        },
        headers: _headers,
      );
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

    switch (grantType) {
      case 'authorization_code':
        return _handleAuthorizationCode(body, client);
      case 'client_credentials':
        return _handleClientCredentials(body, client);
      case 'refresh_token':
        return _handleRefreshToken(body, client);
      default:
        return const ServerTokenResponse(
          statusCode: 400,
          body: {
            'error': 'unsupported_grant_type',
            'error_description': 'Unsupported grant type.',
          },
          headers: _headers,
        );
    }
  }

  Future<ServerTokenResponse> _handleAuthorizationCode(
    Map<String, String> body,
    ClientRegistration client,
  ) async {
    final code = body['code'];
    final codeVerifier = body['code_verifier'];

    if (code == null || code.isEmpty) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_request',
          'error_description': 'Missing code parameter.',
        },
        headers: _headers,
      );
    }

    if (codeVerifier == null || codeVerifier.isEmpty) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_request',
          'error_description': 'Missing code_verifier parameter.',
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

    // Enforce strict invariant Redirect URI matching
    final reqRedirectUri = body['redirect_uri'];
    final parsedUri = reqRedirectUri != null
        ? Uri.tryParse(reqRedirectUri)
        : null;
    if (parsedUri == null || parsedUri != authCode.redirectUri) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_grant',
          'error_description':
              'Redirect URI is required and must match exactly.',
        },
        headers: _headers,
      );
    }

    // Enforce PKCE verifier check
    final String challengeCheck;
    if (authCode.codeChallengeMethod == 'S256') {
      challengeCheck = cryptoService.hashAndBase64UrlEncode(codeVerifier);
    } else {
      challengeCheck = codeVerifier;
    }

    if (challengeCheck != authCode.codeChallenge) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_grant',
          'error_description': 'PKCE verification failed.',
        },
        headers: _headers,
      );
    }

    // Code reuse check (Must revoke everything issued by it)
    if (authCode.isUsed) {
      await authCodeRepository.revokeTokensForCode(code);
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_grant',
          'error_description': 'Authorization code already used.',
        },
        headers: _headers,
      );
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

    // Mark as used
    await authCodeRepository.markAsUsed(code);

    // Issue tokens
    return _issueTokens(
      clientId: client.clientId,
      userId: authCode.userId,
      scope: authCode.scope,
      issueRefreshToken: client.allowedGrantTypes.contains('refresh_token'),
    );
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

    // Scope validation
    final requestedScope = body['scope'];
    String? scope;
    if (requestedScope != null && requestedScope.isNotEmpty) {
      final tokens = requestedScope.split(' ');
      for (final token in tokens) {
        if (!client.allowedScopes.contains(token)) {
          return const ServerTokenResponse(
            statusCode: 400,
            body: {
              'error': 'invalid_scope',
              'error_description': 'Requested scope is not allowed.',
            },
            headers: _headers,
          );
        }
      }
      scope = requestedScope;
    } else {
      scope = client.allowedScopes.join(' ');
    }

    return _issueTokens(
      clientId: client.clientId,
      userId: null,
      scope: scope,
      issueRefreshToken: false,
    );
  }

  Future<ServerTokenResponse> _handleRefreshToken(
    Map<String, String> body,
    ClientRegistration client,
  ) async {
    final refreshTokenVal = body['refresh_token'];
    if (refreshTokenVal == null || refreshTokenVal.isEmpty) {
      return const ServerTokenResponse(
        statusCode: 400,
        body: {
          'error': 'invalid_request',
          'error_description': 'Missing refresh_token parameter.',
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

    // Replay check: if already revoked, trigger cascading revocation
    if (oldRefreshToken.isRevoked) {
      final revokedAt = oldRefreshToken.revokedAt;
      final isWithinGrace =
          revokedAt != null &&
          DateTime.now().difference(revokedAt) <= const Duration(seconds: 30);
      final alreadyUsedGrace = oldRefreshToken.usedInGraceWindow;

      if (isWithinGrace && !alreadyUsedGrace) {
        // Mark as used in grace window to prevent further retries
        final updatedToken = oldRefreshToken.copyWith(usedInGraceWindow: true);
        await tokenRepository.saveRefreshToken(updatedToken);
      } else {
        await tokenRepository.revokeAllTokensForClientAndUser(
          oldRefreshToken.clientId,
          oldRefreshToken.userId,
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

    // Revoke old refresh token (invalidation)
    await tokenRepository.revokeRefreshTokenByHash(hashed);

    // Scope validation
    final requestedScope = body['scope'];
    String? scope;
    if (requestedScope != null && requestedScope.isNotEmpty) {
      final originalScopes = oldRefreshToken.scope?.split(' ').toSet() ?? {};
      final tokens = requestedScope.split(' ');
      for (final token in tokens) {
        if (!originalScopes.contains(token)) {
          return const ServerTokenResponse(
            statusCode: 400,
            body: {
              'error': 'invalid_scope',
              'error_description':
                  'Requested scope exceeds originally granted scope.',
            },
            headers: _headers,
          );
        }
      }
      scope = requestedScope;
    } else {
      scope = oldRefreshToken.scope;
    }

    return _issueTokens(
      clientId: client.clientId,
      userId: oldRefreshToken.userId,
      scope: scope,
      issueRefreshToken: true,
    );
  }

  Future<ServerTokenResponse> _issueTokens({
    required String clientId,
    required String? userId,
    required String? scope,
    required bool issueRefreshToken,
  }) async {
    final rawAccessToken = cryptoService.generateRandomEntropyString();
    final hashedAccessToken = cryptoService.hashString(rawAccessToken);
    final accessExpiresAt = DateTime.now().add(const Duration(hours: 1));

    final accessTokenEntity = AccessToken(
      tokenHash: hashedAccessToken,
      clientId: clientId,
      expiresAt: accessExpiresAt,
      userId: userId,
      scope: scope,
    );
    await tokenRepository.saveAccessToken(accessTokenEntity);

    String? rawRefreshToken;
    if (issueRefreshToken) {
      rawRefreshToken = cryptoService.generateRandomEntropyString();
      final hashedRefreshToken = cryptoService.hashString(rawRefreshToken);
      final refreshExpiresAt = DateTime.now().add(const Duration(days: 30));

      final refreshTokenEntity = RefreshToken(
        tokenHash: hashedRefreshToken,
        clientId: clientId,
        expiresAt: refreshExpiresAt,
        userId: userId,
        scope: scope,
      );
      await tokenRepository.saveRefreshToken(refreshTokenEntity);
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

    return ServerTokenResponse(statusCode: 200, body: body, headers: _headers);
  }
}
