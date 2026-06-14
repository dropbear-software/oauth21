import '../entities/client_registration.dart';

/// Abstract port interface for managing client registrations in the server.
abstract interface class ClientRepository {
  /// Resolves a registered client by its unique identifier.
  ///
  /// Returns `null` if the client registration does not exist.
  Future<ClientRegistration?> findById(String clientId);
}
