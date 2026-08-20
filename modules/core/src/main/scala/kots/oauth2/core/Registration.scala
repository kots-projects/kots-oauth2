package kots.oauth2.core

final case class ClientRegistration(
    redirectUris: Set[RedirectUri],
    authMethod: ClientAuthMethod,
    scopes: Scopes,
    grantTypes: Set[GrantType] = ClientRegistration.DefaultGrantTypes
)

object ClientRegistration {

  /** The grant types a registration that names none may use. */
  val DefaultGrantTypes: Set[GrantType] = Set(GrantType.AuthorizationCode)
}
