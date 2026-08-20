package kots.oauth2.http

import kots.oauth2.core.ClientAuthMethod
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.GrantType
import kots.oauth2.core.ParseFailure
import io.circe.Json
import munit.FunSuite

class RegistrationSpec extends FunSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private def body(fields: (String, Json)*): Map[String, Json] = Map(fields: _*)

  private val uris: Json = Json.arr(Json.fromString("https://client.example/cb"))

  test("a registration parses its redirect uris, method and scope") {
    val parsed = Registration
      .parse(
        body(
          "redirect_uris" -> uris,
          "token_endpoint_auth_method" -> Json.fromString("client_secret_post"),
          "scope" -> Json.fromString("read write")
        )
      )
      .toOption
      .get
    assertEquals(parsed.redirectUris.map(_.value), Set("https://client.example/cb"))
    assertEquals(parsed.authMethod, ClientAuthMethod.ClientSecretPost)
    assertEquals(parsed.scopes.value.map(_.value), Set("read", "write"))
  }

  test("a registration defaults to basic authentication and no scope") {
    val parsed = Registration.parse(body("redirect_uris" -> uris)).toOption.get
    assertEquals(parsed.authMethod, ClientAuthMethod.ClientSecretBasic)
    assertEquals(parsed.scopes.value, Set.empty[kots.oauth2.core.Scope])
  }

  test("a registration without a valid redirect uri is refused") {
    assertEquals(
      Registration.parse(body()).left.toOption.map(_.code),
      Some("invalid_redirect_uri")
    )
    assertEquals(
      Registration
        .parse(body("redirect_uris" -> Json.arr(Json.fromString("https://client.example/*"))))
        .left
        .toOption
        .map(_.code),
      Some("invalid_redirect_uri")
    )
    assertEquals(
      Registration.parse(body("redirect_uris" -> Json.arr())).left.toOption.map(_.code),
      Some("invalid_redirect_uri")
    )
  }

  test("a registration with unusable metadata is refused") {
    assertEquals(
      Registration
        .parse(
          body("redirect_uris" -> uris, "token_endpoint_auth_method" -> Json.fromString("private_key_jwt"))
        )
        .left
        .toOption
        .map(_.code),
      Some("invalid_client_metadata")
    )
    assertEquals(
      Registration
        .parse(body("redirect_uris" -> uris, "scope" -> Json.fromString("read  write")))
        .left
        .toOption
        .map(_.code),
      Some("invalid_client_metadata")
    )
  }

  test("a registration response renders the issued credentials and metadata") {
    val parsed =
      Registration.parse(body("redirect_uris" -> uris, "scope" -> Json.fromString("read"))).toOption.get
    val rendered = ClientRegistrationResponse.render(
      ClientRegistrationResponse(
        unsafe(kots.oauth2.core.ClientId.from("client-9")),
        Some(unsafe(ClientSecret.from("s3cret-9"))),
        parsed
      )
    )
    assertEquals(rendered("client_id"), Json.fromString("client-9"))
    assertEquals(rendered("client_secret"), Json.fromString("s3cret-9"))
    assertEquals(rendered("token_endpoint_auth_method"), Json.fromString("client_secret_basic"))
    assertEquals(rendered("redirect_uris"), uris)
    assertEquals(rendered("scope"), Json.fromString("read"))
  }

  test("a public registration response carries no secret") {
    val parsed = Registration
      .parse(body("redirect_uris" -> uris, "token_endpoint_auth_method" -> Json.fromString("none")))
      .toOption
      .get
    val rendered = ClientRegistrationResponse.render(
      ClientRegistrationResponse(unsafe(kots.oauth2.core.ClientId.from("client-9")), None, parsed)
    )
    assert(!rendered.contains("client_secret"))
  }

  test("an issued secret is accompanied by the moment it expires") {
    val parsed =
      Registration.parse(body("redirect_uris" -> uris, "scope" -> Json.fromString("read"))).toOption.get
    val rendered = ClientRegistrationResponse.render(
      ClientRegistrationResponse(
        unsafe(kots.oauth2.core.ClientId.from("client-9")),
        Some(unsafe(ClientSecret.from("s3cret-9"))),
        parsed
      )
    )
    assertEquals(rendered.get("client_secret_expires_at"), Some(Json.fromLong(0L)))
  }

  test("a response without a secret carries no expiry either") {
    val parsed = Registration
      .parse(body("redirect_uris" -> uris, "token_endpoint_auth_method" -> Json.fromString("none")))
      .toOption
      .get
    val rendered = ClientRegistrationResponse.render(
      ClientRegistrationResponse(unsafe(kots.oauth2.core.ClientId.from("client-9")), None, parsed)
    )
    assert(!rendered.contains("client_secret_expires_at"))
  }

  test("a registration for no scope omits the member rather than rendering it empty") {
    val parsed = Registration.parse(body("redirect_uris" -> uris)).toOption.get
    val rendered = ClientRegistrationResponse.render(
      ClientRegistrationResponse(unsafe(kots.oauth2.core.ClientId.from("client-9")), None, parsed)
    )
    assert(!rendered.contains("scope"), rendered.toString)
  }

  test("a registration reads the grant types it will use, the authorization code when it names none") {
    val named = Registration
      .parse(
        body(
          "redirect_uris" -> uris,
          "grant_types" -> Json.arr(Json.fromString("client_credentials"), Json.fromString("refresh_token"))
        )
      )
      .map(_.grantTypes)
    assertEquals(named, Right(Set[GrantType](GrantType.ClientCredentials, GrantType.RefreshToken)))
    assertEquals(
      Registration.parse(body("redirect_uris" -> uris)).map(_.grantTypes),
      Right(Set[GrantType](GrantType.AuthorizationCode))
    )
  }

  test("a registration naming an unknown grant type, or none in a list, is refused") {
    List(
      Json.arr(Json.fromString("password")),
      Json.arr(),
      Json.arr(Json.fromInt(1)),
      Json.fromString("authorization_code")
    ).foreach(types =>
      assertEquals(
        Registration.parse(body("redirect_uris" -> uris, "grant_types" -> types)).left.toOption.map(_.code),
        Some("invalid_client_metadata")
      )
    )
  }

  test("a registration answer names the grant types the client may use, in order") {
    val registration = Registration
      .parse(
        body(
          "redirect_uris" -> uris,
          "grant_types" -> Json.arr(Json.fromString("refresh_token"), Json.fromString("authorization_code"))
        )
      )
      .toOption
      .get
    val rendered = ClientRegistrationResponse.render(
      ClientRegistrationResponse(unsafe(kots.oauth2.core.ClientId.from("client-1")), None, registration)
    )
    assertEquals(
      rendered.get("grant_types"),
      Some(Json.arr(Json.fromString("authorization_code"), Json.fromString("refresh_token")))
    )
  }
}
