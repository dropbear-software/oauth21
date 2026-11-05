import 'package:meta/meta.dart';

import '../abnf_validators.dart';
import '../entities/client_registration.dart';
import '../ports/client_repository.dart';
import '../redirect_uri_policy.dart';

/// The result of validating an authorization request.
///
/// This is a sealed hierarchy with three outcomes:
/// - [AuthorizeRequestValid]: The request is valid and ready for user consent.
/// - [AuthorizeRedirectableError]: The client and redirect URI were verified,
///   so the error can be safely redirected back to the client.
/// - [AuthorizeDirectError]: The `client_id` or `redirect_uri` is invalid, so
///   the error must be rendered directly to the user agent without redirecting.
@immutable
sealed class AuthorizeValidationResult {
  /// Creates an [AuthorizeValidationResult].
  const AuthorizeValidationResult();
}

/// Represents a valid authorization request ready for user authentication and
/// consent.
@immutable
final class AuthorizeRequestValid extends AuthorizeValidationResult {
  /// The validated client registration.
  final ClientRegistration client;

  /// The validated redirect URI.
  final Uri validatedRedirectUri;

  /// The optional `state` parameter passed in the authorization request.
  final String? state;

  /// The set of validated scopes requested.
  final Set<String> requestedScopes;

  /// The PKCE code challenge.
  final String codeChallenge;

  /// The PKCE code challenge method (`S256`).
  final String codeChallengeMethod;

  /// Creates a valid authorization request result.
  const AuthorizeRequestValid({
    required this.client,
    required this.validatedRedirectUri,
    required this.requestedScopes,
    required this.codeChallenge,
    required this.codeChallengeMethod,
    this.state,
  });
}

/// Represents an authorization request validation error where the client and
/// redirect URI have been verified, allowing the authorization server to
/// redirect the user agent back to [validatedRedirectUri] with the error.
@immutable
final class AuthorizeRedirectableError extends AuthorizeValidationResult {
  /// The validated client registration.
  final ClientRegistration client;

  /// The validated redirect URI to which the error response may be sent.
  final Uri validatedRedirectUri;

  /// The OAuth 2.1 error code (e.g. `invalid_request`, `invalid_scope`,
  /// `unauthorized_client`, `unsupported_response_type`).
  final String errorCode;

  /// A human-readable description of the validation error.
  final String errorDescription;

  /// The optional validated `state` parameter to echo in the error redirect.
  final String? state;

  /// Creates a redirectable authorization validation error.
  const AuthorizeRedirectableError({
    required this.client,
    required this.validatedRedirectUri,
    required this.errorCode,
    required this.errorDescription,
    this.state,
  });
}

/// Represents an authorization request validation error where `client_id` or
/// `redirect_uri` failed validation, requiring the server to inform the user
/// agent directly (e.g. HTTP 400) rather than redirecting.
@immutable
final class AuthorizeDirectError extends AuthorizeValidationResult {
  /// The OAuth 2.1 error code (e.g. `invalid_request`, `invalid_client`).
  final String errorCode;

  /// A human-readable description of the validation error.
  final String errorDescription;

  /// Creates a non-redirectable authorization validation error.
  const AuthorizeDirectError({
    required this.errorCode,
    required this.errorDescription,
  });
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
      return const AuthorizeDirectError(
        errorCode: 'invalid_request',
        errorDescription: 'Parameter pollution detected for client_id.',
      );
    }

    final redirectUris = params['redirect_uri'] ?? [];
    if (redirectUris.length > 1) {
      return const AuthorizeDirectError(
        errorCode: 'invalid_request',
        errorDescription: 'Parameter pollution detected for redirect_uri.',
      );
    }

    // 2. Client verification (empty value is treated as omitted per Section 3.1)
    final clientId = _singleNonEmptyValue(clientIds);
    if (clientId == null) {
      return const AuthorizeDirectError(
        errorCode: 'invalid_request',
        errorDescription: 'Missing client_id parameter.',
      );
    }

    if (!isValidVscharParam(clientId)) {
      return const AuthorizeDirectError(
        errorCode: 'invalid_request',
        errorDescription:
            'client_id is empty, untrimmed, or contains invalid characters.',
      );
    }

    final client = await clientRepository.findById(clientId);
    if (client == null) {
      return const AuthorizeDirectError(
        errorCode: 'invalid_client',
        errorDescription: 'Client registration not found.',
      );
    }

    // 3. Redirect URI match
    final redirectResult = _resolveRedirectUri(
      client,
      _singleNonEmptyValue(redirectUris),
    );
    if (redirectResult.error != null) {
      return redirectResult.error!;
    }

    // 4. Validate redirectable authorization parameters
    return _validateRedirectableParameters(params, client, redirectResult.uri!);
  }

  ({Uri? uri, AuthorizeDirectError? error}) _resolveRedirectUri(
    ClientRegistration client,
    String? reqRedirectStr,
  ) {
    if (reqRedirectStr == null) {
      if (client.redirectUris.length != 1) {
        return (
          uri: null,
          error: const AuthorizeDirectError(
            errorCode: 'invalid_request',
            errorDescription:
                'Missing redirect_uri, and client has multiple or zero '
                'registered redirect URIs.',
          ),
        );
      }
      final defaultUri = client.redirectUris.first;
      if (!isAllowedRedirectUri(defaultUri)) {
        return (
          uri: null,
          error: const AuthorizeDirectError(
            errorCode: 'invalid_request',
            errorDescription:
                'The redirect_uri is not an allowed OAuth 2.1 redirect URI.',
          ),
        );
      }
      return (uri: defaultUri, error: null);
    }

    final requestedUri = Uri.tryParse(reqRedirectStr);
    if (requestedUri == null) {
      return (
        uri: null,
        error: const AuthorizeDirectError(
          errorCode: 'invalid_request',
          errorDescription: 'Malformed redirect_uri parameter.',
        ),
      );
    }

    if (_hasRawDotSegment(reqRedirectStr) ||
        !isAllowedRedirectUri(requestedUri) ||
        !_isRedirectUriAllowed(client, requestedUri, reqRedirectStr)) {
      return (
        uri: null,
        error: const AuthorizeDirectError(
          errorCode: 'invalid_request',
          errorDescription:
              'Requested redirect_uri is not registered for this client.',
        ),
      );
    }

    return (uri: requestedUri, error: null);
  }

  AuthorizeValidationResult _validateRedirectableParameters(
    Map<String, List<String>> params,
    ClientRegistration client,
    Uri validatedRedirectUri,
  ) {
    // From this point onward, errors can be redirected back to the client's
    // validatedRedirectUri. Extract and validate optional "state" (Section 4.1.1).
    final states = params['state'] ?? const [];
    if (states.length > 1) {
      return AuthorizeRedirectableError(
        client: client,
        validatedRedirectUri: validatedRedirectUri,
        errorCode: 'invalid_request',
        errorDescription: 'Parameter pollution detected for state.',
      );
    }

    final state = _singleNonEmptyValue(states);
    if (state != null && !isValidVscharParam(state)) {
      return AuthorizeRedirectableError(
        client: client,
        validatedRedirectUri: validatedRedirectUri,
        errorCode: 'invalid_request',
        errorDescription: 'state is untrimmed or contains invalid characters.',
      );
    }

    // Parameter pollution check for remaining fields
    for (final entry in params.entries) {
      if (entry.value.length > 1) {
        return AuthorizeRedirectableError(
          client: client,
          validatedRedirectUri: validatedRedirectUri,
          errorCode: 'invalid_request',
          errorDescription:
              'Parameter pollution detected for key: ${entry.key}.',
          state: state,
        );
      }
    }

    // Verify client is authorized for the authorization_code grant (Section 4.1.2.1)
    if (!client.allowedGrantTypes.contains('authorization_code')) {
      return AuthorizeRedirectableError(
        client: client,
        validatedRedirectUri: validatedRedirectUri,
        errorCode: 'unauthorized_client',
        errorDescription:
            'The client is not authorized to request an authorization code '
            'using this method.',
        state: state,
      );
    }

    // Validate response_type
    final responseType = _singleNonEmptyValue(params['response_type']);
    if (responseType == null) {
      return AuthorizeRedirectableError(
        client: client,
        validatedRedirectUri: validatedRedirectUri,
        errorCode: 'invalid_request',
        errorDescription: 'Missing response_type parameter.',
        state: state,
      );
    }
    if (responseType != 'code') {
      return AuthorizeRedirectableError(
        client: client,
        validatedRedirectUri: validatedRedirectUri,
        errorCode: 'unsupported_response_type',
        errorDescription: 'response_type must be strictly "code".',
        state: state,
      );
    }

    // Validate PKCE (code_challenge and code_challenge_method are mandatory)
    final pkce = _validatePkceParameters(params);
    if (pkce.errorDescription != null) {
      return AuthorizeRedirectableError(
        client: client,
        validatedRedirectUri: validatedRedirectUri,
        errorCode: 'invalid_request',
        errorDescription: pkce.errorDescription!,
        state: state,
      );
    }

    // Validate scope (if present)
    final scopeResult = _resolveRequestedScopes(
      client,
      _singleNonEmptyValue(params['scope']),
    );
    if (scopeResult.errorDescription != null) {
      return AuthorizeRedirectableError(
        client: client,
        validatedRedirectUri: validatedRedirectUri,
        errorCode: 'invalid_scope',
        errorDescription: scopeResult.errorDescription!,
        state: state,
      );
    }

    return AuthorizeRequestValid(
      client: client,
      validatedRedirectUri: validatedRedirectUri,
      state: state,
      requestedScopes: scopeResult.scopes!,
      codeChallenge: pkce.codeChallenge!,
      codeChallengeMethod: pkce.codeChallengeMethod!,
    );
  }

  ({
    String? codeChallenge,
    String? codeChallengeMethod,
    String? errorDescription,
  })
  _validatePkceParameters(Map<String, List<String>> params) {
    final codeChallenge = _singleNonEmptyValue(params['code_challenge']);
    if (codeChallenge == null) {
      return (
        codeChallenge: null,
        codeChallengeMethod: null,
        errorDescription: 'Missing code_challenge parameter.',
      );
    }
    if (!codeVerifierAbnfRegex.hasMatch(codeChallenge)) {
      return (
        codeChallenge: null,
        codeChallengeMethod: null,
        errorDescription: 'code_challenge violates ABNF constraints.',
      );
    }

    final codeChallengeMethod = _singleNonEmptyValue(
      params['code_challenge_method'],
    );
    if (codeChallengeMethod == null) {
      return (
        codeChallenge: null,
        codeChallengeMethod: null,
        errorDescription: 'Missing code_challenge_method parameter.',
      );
    }
    if (codeChallengeMethod != 'S256') {
      return (
        codeChallenge: null,
        codeChallengeMethod: null,
        errorDescription: 'The code_challenge_method must be "S256".',
      );
    }

    return (
      codeChallenge: codeChallenge,
      codeChallengeMethod: codeChallengeMethod,
      errorDescription: null,
    );
  }

  static ({Set<String>? scopes, String? errorDescription})
  _resolveRequestedScopes(ClientRegistration client, String? scopeStr) {
    if (scopeStr == null) {
      return (scopes: {...client.allowedScopes}, errorDescription: null);
    }
    final parsedScopes = parseAndDeduplicateScope(scopeStr);
    if (parsedScopes == null) {
      return (
        scopes: null,
        errorDescription: 'The requested scope is malformed.',
      );
    }
    for (final token in parsedScopes) {
      if (!client.allowedScopes.contains(token)) {
        return (
          scopes: null,
          errorDescription:
              'Scope token "$token" is not allowed for this client.',
        );
      }
    }
    return (scopes: parsedScopes, errorDescription: null);
  }

  String? _singleNonEmptyValue(List<String>? values) {
    if (values == null || values.isEmpty) {
      return null;
    }
    final first = values.first;
    return first.isEmpty ? null : first;
  }

  bool _hasRawDotSegment(String rawUri) {
    final schemeEnd = rawUri.indexOf('://');
    final pathStart = schemeEnd != -1
        ? rawUri.indexOf('/', schemeEnd + 3)
        : rawUri.indexOf('/');
    if (pathStart == -1) {
      return false;
    }
    var pathEnd = rawUri.indexOf('?', pathStart);
    final fragStart = rawUri.indexOf('#', pathStart);
    if (pathEnd == -1 || (fragStart != -1 && fragStart < pathEnd)) {
      pathEnd = fragStart;
    }
    final rawPath = pathEnd == -1
        ? rawUri.substring(pathStart)
        : rawUri.substring(pathStart, pathEnd);
    for (final segment in rawPath.split('/')) {
      try {
        final decoded = Uri.decodeComponent(segment);
        if (decoded == '.' || decoded == '..') {
          return true;
        }
      } on Object catch (_) {
        return true;
      }
    }
    return false;
  }

  bool _isRedirectUriAllowed(
    ClientRegistration client,
    Uri requestedUri,
    String rawRequestedUri,
  ) {
    if (!isAllowedRedirectUri(requestedUri)) {
      return false;
    }
    for (final registeredUri in client.redirectUris) {
      if (!isAllowedRedirectUri(registeredUri)) {
        continue;
      }
      if (registeredUri.toString() == rawRequestedUri &&
          registeredUri.toString() == requestedUri.toString()) {
        return true;
      }
      if (registeredUri.scheme.toLowerCase() == 'http' &&
          isLoopbackHost(registeredUri.host) &&
          requestedUri.scheme.toLowerCase() == 'http' &&
          isLoopbackHost(requestedUri.host)) {
        if (_matchLoopback(registeredUri, requestedUri)) {
          return true;
        }
      }
    }
    return false;
  }

  bool _matchLoopback(Uri registered, Uri requested) {
    return registered.scheme.toLowerCase() == 'http' &&
        requested.scheme.toLowerCase() == 'http' &&
        registered.host.toLowerCase() == requested.host.toLowerCase() &&
        registered.path == requested.path &&
        registered.query == requested.query;
  }
}
