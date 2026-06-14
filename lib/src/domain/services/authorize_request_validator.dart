import '../entities/client_registration.dart';
import '../ports/client_repository.dart';

/// The result of validating an authorization request.
class AuthorizeValidationResult {
  /// Whether the request parameters are valid.
  final bool isValid;

  /// Whether the client redirect URI is validated, allowing the server to
  /// redirect the user agent back to the client to report validation errors.
  final bool isRedirectable;

  /// The OAuth 2.1 error code (e.g. invalid_request, invalid_scope, etc.).
  final String? errorCode;

  /// A human-readable description of the validation error.
  final String? errorDescription;

  /// The validated client registration.
  final ClientRegistration? client;

  /// The validated redirect URI.
  final Uri? validatedRedirectUri;

  /// The state parameter passed in the authorization request.
  final String? state;

  /// The set of validated scopes requested.
  final Set<String> requestedScopes;

  /// The PKCE code challenge.
  final String? codeChallenge;

  /// The PKCE code challenge method (S256 or plain).
  final String? codeChallengeMethod;

  /// Creates a successful validation result.
  const AuthorizeValidationResult.valid({
    required this.client,
    required this.validatedRedirectUri,
    required this.state,
    required this.requestedScopes,
    required this.codeChallenge,
    required this.codeChallengeMethod,
  }) : isValid = true,
       isRedirectable = false,
       errorCode = null,
       errorDescription = null;

  /// Creates a failed validation result.
  const AuthorizeValidationResult.invalid({
    required this.isRedirectable,
    required this.errorCode,
    required this.errorDescription,
    this.client,
    this.validatedRedirectUri,
    this.state,
  }) : isValid = false,
       requestedScopes = const {},
       codeChallenge = null,
       codeChallengeMethod = null;
}

/// Service that validates incoming parameters at the authorization endpoint.
class AuthorizeRequestValidator {
  /// The repository used to look up client registrations.
  final ClientRepository clientRepository;

  /// Creates a new [AuthorizeRequestValidator] instance.
  const AuthorizeRequestValidator(this.clientRepository);

  /// Validates incoming authorization request parameters.
  Future<AuthorizeValidationResult> validate(
    Map<String, List<String>> params,
  ) async {
    // 1. Parameter Pollution Check for critical parameters
    final clientIds = params['client_id'] ?? [];
    if (clientIds.length > 1) {
      return const AuthorizeValidationResult.invalid(
        isRedirectable: false,
        errorCode: 'invalid_request',
        errorDescription: 'Parameter pollution detected for client_id.',
      );
    }

    final redirectUris = params['redirect_uri'] ?? [];
    if (redirectUris.length > 1) {
      return const AuthorizeValidationResult.invalid(
        isRedirectable: false,
        errorCode: 'invalid_request',
        errorDescription: 'Parameter pollution detected for redirect_uri.',
      );
    }

    // 2. Client verification
    if (clientIds.isEmpty || clientIds.first.isEmpty) {
      return const AuthorizeValidationResult.invalid(
        isRedirectable: false,
        errorCode: 'invalid_request',
        errorDescription: 'Missing client_id parameter.',
      );
    }

    final clientId = clientIds.first;
    final vscharRequiredRegex = RegExp(r'^[\x20-\x7E]+$');
    if (clientId.trim() != clientId ||
        !vscharRequiredRegex.hasMatch(clientId)) {
      return const AuthorizeValidationResult.invalid(
        isRedirectable: false,
        errorCode: 'invalid_request',
        errorDescription:
            'client_id is empty, untrimmed, or contains invalid characters.',
      );
    }

    final client = await clientRepository.findById(clientId);
    if (client == null) {
      return const AuthorizeValidationResult.invalid(
        isRedirectable: false,
        errorCode: 'invalid_client',
        errorDescription: 'Client registration not found.',
      );
    }

    // 3. Redirect URI match
    Uri validatedRedirectUri;
    if (redirectUris.isEmpty || redirectUris.first.isEmpty) {
      if (client.redirectUris.length == 1) {
        validatedRedirectUri = client.redirectUris.first;
      } else {
        return const AuthorizeValidationResult.invalid(
          isRedirectable: false,
          errorCode: 'invalid_request',
          errorDescription:
              'Missing redirect_uri, and client has multiple or zero '
              'registered redirect URIs.',
        );
      }
    } else {
      final reqRedirectStr = redirectUris.first;
      try {
        validatedRedirectUri = Uri.parse(reqRedirectStr);
      } on FormatException catch (_) {
        return const AuthorizeValidationResult.invalid(
          isRedirectable: false,
          errorCode: 'invalid_request',
          errorDescription: 'Malformed redirect_uri parameter.',
        );
      }

      if (!_isRedirectUriAllowed(client, validatedRedirectUri)) {
        return const AuthorizeValidationResult.invalid(
          isRedirectable: false,
          errorCode: 'invalid_request',
          errorDescription:
              'Requested redirect_uri is not registered for this client.',
        );
      }
    }

    // From this point onward, errors can be redirected back to the client's
    // validatedRedirectUri. However, we must also extract and validate "state"
    // because we need it in the redirection.
    final states = params['state'] ?? [];
    if (states.length > 1) {
      return AuthorizeValidationResult.invalid(
        isRedirectable: true,
        errorCode: 'invalid_request',
        errorDescription: 'Parameter pollution detected for state.',
        client: client,
        validatedRedirectUri: validatedRedirectUri,
      );
    }

    if (states.isEmpty || states.first.isEmpty) {
      return AuthorizeValidationResult.invalid(
        isRedirectable: true,
        errorCode: 'invalid_request',
        errorDescription: 'Missing state parameter.',
        client: client,
        validatedRedirectUri: validatedRedirectUri,
      );
    }

    final state = states.first;
    if (state.trim() != state || !vscharRequiredRegex.hasMatch(state)) {
      return AuthorizeValidationResult.invalid(
        isRedirectable: true,
        errorCode: 'invalid_request',
        errorDescription: 'state is untrimmed or contains invalid characters.',
        client: client,
        validatedRedirectUri: validatedRedirectUri,
      );
    }

    // Parameter pollution check for remaining fields
    for (final entry in params.entries) {
      if (entry.value.length > 1) {
        return AuthorizeValidationResult.invalid(
          isRedirectable: true,
          errorCode: 'invalid_request',
          errorDescription:
              'Parameter pollution detected for key: ${entry.key}.',
          client: client,
          validatedRedirectUri: validatedRedirectUri,
          state: state,
        );
      }
    }

    // Validate response_type
    final responseTypes = params['response_type'] ?? [];
    if (responseTypes.isEmpty || responseTypes.first.isEmpty) {
      return AuthorizeValidationResult.invalid(
        isRedirectable: true,
        errorCode: 'invalid_request',
        errorDescription: 'Missing response_type parameter.',
        client: client,
        validatedRedirectUri: validatedRedirectUri,
        state: state,
      );
    }
    final responseType = responseTypes.first;
    if (responseType != 'code') {
      return AuthorizeValidationResult.invalid(
        isRedirectable: true,
        errorCode: 'unsupported_response_type',
        errorDescription: 'response_type must be strictly "code".',
        client: client,
        validatedRedirectUri: validatedRedirectUri,
        state: state,
      );
    }

    // Validate PKCE (code_challenge and code_challenge_method are mandatory)
    final codeChallenges = params['code_challenge'] ?? [];
    if (codeChallenges.isEmpty || codeChallenges.first.isEmpty) {
      return AuthorizeValidationResult.invalid(
        isRedirectable: true,
        errorCode: 'invalid_request',
        errorDescription: 'Missing code_challenge parameter.',
        client: client,
        validatedRedirectUri: validatedRedirectUri,
        state: state,
      );
    }
    final codeChallenge = codeChallenges.first;
    final challengeRegex = RegExp(r'^[A-Za-z0-9\-\._~]{43,128}$');
    if (!challengeRegex.hasMatch(codeChallenge)) {
      return AuthorizeValidationResult.invalid(
        isRedirectable: true,
        errorCode: 'invalid_request',
        errorDescription: 'code_challenge violates ABNF constraints.',
        client: client,
        validatedRedirectUri: validatedRedirectUri,
        state: state,
      );
    }

    final codeChallengeMethods = params['code_challenge_method'] ?? [];
    if (codeChallengeMethods.isEmpty || codeChallengeMethods.first.isEmpty) {
      return AuthorizeValidationResult.invalid(
        isRedirectable: true,
        errorCode: 'invalid_request',
        errorDescription: 'Missing code_challenge_method parameter.',
        client: client,
        validatedRedirectUri: validatedRedirectUri,
        state: state,
      );
    }
    final codeChallengeMethod = codeChallengeMethods.first;
    if (codeChallengeMethod != 'S256' && codeChallengeMethod != 'plain') {
      return AuthorizeValidationResult.invalid(
        isRedirectable: true,
        errorCode: 'invalid_request',
        errorDescription:
            'Unsupported code_challenge_method. Only S256 and plain '
            'are supported.',
        client: client,
        validatedRedirectUri: validatedRedirectUri,
        state: state,
      );
    }

    // Validate scope (if present)
    final scopes = params['scope'] ?? [];
    final requestedScopes = <String>{};
    if (scopes.isNotEmpty && scopes.first.isNotEmpty) {
      final scopeStr = scopes.first;
      final tokens = scopeStr.split(' ');
      final scopeTokenRegex = RegExp(r'^[\x21\x23-\x5B\x5D-\x7E]+$');
      for (final token in tokens) {
        if (token.isEmpty) {
          return AuthorizeValidationResult.invalid(
            isRedirectable: true,
            errorCode: 'invalid_request',
            errorDescription:
                'Scope contains empty tokens or consecutive spaces.',
            client: client,
            validatedRedirectUri: validatedRedirectUri,
            state: state,
          );
        }
        if (!scopeTokenRegex.hasMatch(token)) {
          return AuthorizeValidationResult.invalid(
            isRedirectable: true,
            errorCode: 'invalid_request',
            errorDescription: 'Scope token "$token" violates ABNF constraints.',
            client: client,
            validatedRedirectUri: validatedRedirectUri,
            state: state,
          );
        }
        if (!client.allowedScopes.contains(token)) {
          return AuthorizeValidationResult.invalid(
            isRedirectable: true,
            errorCode: 'invalid_scope',
            errorDescription:
                'Scope token "$token" is not allowed for this client.',
            client: client,
            validatedRedirectUri: validatedRedirectUri,
            state: state,
          );
        }
        requestedScopes.add(token);
      }
    } else {
      // Default to client's allowed scopes if parameter is omitted.
      requestedScopes.addAll(client.allowedScopes);
    }

    return AuthorizeValidationResult.valid(
      client: client,
      validatedRedirectUri: validatedRedirectUri,
      state: state,
      requestedScopes: requestedScopes,
      codeChallenge: codeChallenge,
      codeChallengeMethod: codeChallengeMethod,
    );
  }

  bool _isRedirectUriAllowed(ClientRegistration client, Uri requestedUri) {
    final reqNormalized = requestedUri.normalizePath();
    for (final registeredUri in client.redirectUris) {
      final regNormalized = registeredUri.normalizePath();
      if (regNormalized == reqNormalized) {
        return true;
      }
      if (_isLoopback(regNormalized) && _isLoopback(reqNormalized)) {
        if (_matchLoopback(regNormalized, reqNormalized)) {
          return true;
        }
      }
    }
    return false;
  }

  bool _isLoopback(Uri uri) {
    if (uri.scheme != 'http') return false;
    final host = uri.host.toLowerCase();
    return host == '127.0.0.1' ||
        host == '::1' ||
        host == '[::1]' ||
        host == 'localhost';
  }

  bool _matchLoopback(Uri registered, Uri requested) {
    if (registered.host.toLowerCase() != requested.host.toLowerCase()) {
      return false;
    }
    final regNormalized = registered.replace(port: 0);
    final reqNormalized = requested.replace(port: 0);
    return regNormalized == reqNormalized;
  }
}
