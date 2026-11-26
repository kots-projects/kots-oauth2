package kots.oauth2.store.sql

import cats.effect.IO
import kots.data.Fragment
import kots.oauth2.core.CertificateThumbprint
import kots.oauth2.core.ClientAuthMethod
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.ClientSecretHash
import kots.oauth2.core.GrantType
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.RegistrationToken
import kots.oauth2.core.RegistrationTokenHash
import kots.oauth2.core.Scopes
import kots.oauth2.jose.Fakes
import kots.oauth2.jose.Jwks
import kots.oauth2.store.Client
import munit.CatsEffectSuite

abstract class SqlClientStoreSpec(backend: Backend) extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val id: ClientId = unsafe(ClientId.from("client-1"))

  private val registered: Client = Client(
    id,
    Set(
      unsafe(RedirectUri.from("https://client.example/cb")),
      unsafe(RedirectUri.from("https://client.example/other"))
    ),
    unsafe(Scopes.parse("read write")),
    ClientAuthMethod.ClientSecretBasic,
    Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret")))),
    keys = Jwks(List(Fakes.rsa("key-1"), Fakes.ec("key-2"))),
    registrationTokenHash =
      Some(RegistrationTokenHash.of(unsafe(RegistrationToken.from("registration-token")))),
    secret = Some(unsafe(ClientSecret.from("s3cret"))),
    certificateThumbprint = Some(unsafe(CertificateThumbprint.from(Fakes.ClientCertificateThumbprint)))
  )

  private val stores = ResourceFunFixture(
    backend.database.evalMap(database =>
      SqlClientStore.create[IO](database).toOption.get.map(store => (store, database))
    )
  )

  stores.test("a saved client is found with every field and key intact") { case (store, _) =>
    for {
      _ <- store.save(registered)
      found <- store.find(id)
      absent <- store.find(unsafe(ClientId.from("absent")))
    } yield {
      assertEquals(found, Some(registered))
      assertEquals(absent, None)
    }
  }

  stores.test("saving the same client id replaces the registration") { case (store, _) =>
    for {
      _ <- store.save(registered)
      _ <- store.save(
        registered.copy(scopes = unsafe(Scopes.parse("read")), keys = Jwks(Nil), secret = None)
      )
      found <- store.find(id)
    } yield {
      assertEquals(found.map(_.scopes), Some(unsafe(Scopes.parse("read"))))
      assertEquals(found.map(_.keys), Some(Jwks(Nil)))
      assertEquals(found.flatMap(_.secret), None)
    }
  }

  stores.test("a deleted client is gone with its keys") { case (store, _) =>
    for {
      _ <- store.save(registered)
      _ <- store.delete(id)
      found <- store.find(id)
      _ <- store.delete(unsafe(ClientId.from("absent")))
    } yield assertEquals(found, None)
  }

  stores.test(
    "the grant types a client is allowed survive a save, and a row without them allows every grant"
  ) { case (store, database) =>
    val coded = Set[GrantType](GrantType.AuthorizationCode, GrantType.RefreshToken)
    for {
      _ <- store.save(registered.copy(grantTypes = coded))
      restricted <- store.find(id)
      _ <- database.session.use(_.execute(Fragment.sql("UPDATE clients SET grant_types = NULL")))
      legacy <- store.find(id)
    } yield {
      assertEquals(restricted.map(_.grantTypes), Some(coded))
      assertEquals(legacy.map(_.grantTypes), Some(GrantType.all.toSet))
    }
  }
}

class EmbeddedClientStoreSpec extends SqlClientStoreSpec(Backend.embedded)

class PostgresClientStoreSpec extends SqlClientStoreSpec(Backend.postgres)
