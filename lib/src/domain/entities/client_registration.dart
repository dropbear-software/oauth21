import 'package:meta/meta.dart';

import '../abnf_validators.dart';
import '../redirect_uri_policy.dart';

/// Represents the registration profile of an OAuth 2.1 client.
enum ClientType {
  /// Clients incapable of maintaining credentials (e.g. mobile apps, SPAs).
  public,

  /// Clients capable of maintaining credentials securely (e.g. web apps).
  confidential,
}

/// Domain entity representing a registered client with the authorization
/// server.
@immutable
class ClientRegistration {
  /// The client's unique identifier.
  final String clientId;

  /// The type of client (public or confidential).
  final ClientType clientType;

  /// The hashed client secret (confidential clients only).
  final String? clientSecretHash;

  /// The set of pre-registered redirect URIs.
  final Set<Uri> redirectUris;

  /// The set of scopes this client is authorized to request.
  final Set<String> allowedScopes;

  /// The set of grant types this client is authorized to use.
  final Set<String> allowedGrantTypes;

  /// Creates a new [ClientRegistration].
  ClientRegistration({
    required this.clientId,
    required this.clientType,
    required Set<Uri> redirectUris,
    this.clientSecretHash,
    Set<String> allowedScopes = const {},
    Set<String> allowedGrantTypes = const {'authorization_code'},
  }) : redirectUris = Set<Uri>.unmodifiable(redirectUris),
       allowedScopes = Set<String>.unmodifiable(allowedScopes),
       allowedGrantTypes = Set<String>.unmodifiable(allowedGrantTypes) {
    // 1. Validate clientId is non-empty, trimmed, and contains only VSCHAR
    if (!isValidVscharParam(clientId)) {
      throw ArgumentError(
        'clientId must not be empty, must be thoroughly trimmed, and '
        'must contain only printable ASCII characters (VSCHAR).',
      );
    }

    // 2. Validate redirect URIs
    for (final uri in this.redirectUris) {
      if (!isAllowedRedirectUri(uri)) {
        throw ArgumentError.value(
          uri,
          'redirectUris',
          'Each redirectUri must use https, loopback http, or a reverse-domain '
              'private-use scheme, and must not contain fragments or userinfo.',
        );
      }
    }

    // 3. Validate allowed scopes conform to ABNF scope-token syntax
    for (final scope in this.allowedScopes) {
      if (scope.isEmpty || !nqcharRequiredRegex.hasMatch(scope)) {
        throw ArgumentError(
          'Scope token "$scope" contains invalid characters violating ABNF '
          'scope syntax.',
        );
      }
    }

    // 4. Validate allowed grant types conform to Appendix A.10 / Section 6.3
    for (final grantType in this.allowedGrantTypes) {
      if (!isValidGrantTypeParam(grantType)) {
        throw ArgumentError.value(
          grantType,
          'allowedGrantTypes',
          'Grant type "$grantType" violates Appendix A.10 / Section 6.3 '
              'grant-type syntax.',
        );
      }
    }
  }
}
