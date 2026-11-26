package kots.oauth2.store.sql

import cats.effect.IO
import kots.oauth2.core.AuthorizationDetail
import kots.oauth2.core.AuthorizationDetailType
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.ClientId
import kots.oauth2.core.GrantId
import kots.oauth2.core.Location
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.store.Grant
import munit.CatsEffectSuite

abstract class SqlGrantStoreSpec(backend: Backend) extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val grant: Grant = Grant(
    id = unsafe(GrantId.from("grant-1")),
    clientId = unsafe(ClientId.from("client-1")),
    subject = unsafe(Subject.from("user-1")),
    scopes = unsafe(Scopes.parse("read write")),
    details = AuthorizationDetails.of(
      List(
        AuthorizationDetail.of(
          unsafe(AuthorizationDetailType.from("account")),
          locations = List(unsafe(Location.from("https://api.example")))
        )
      )
    ),
    revoked = false
  )

  private val stores = ResourceFunFixture(
    backend.database.evalMap(database => SqlGrantStore.create[IO](database).toOption.get)
  )

  stores.test("a saved grant is found with every field intact") { store =>
    for {
      _ <- store.save(grant)
      found <- store.find(grant.id)
      absent <- store.find(unsafe(GrantId.from("absent")))
    } yield {
      assertEquals(found, Some(grant))
      assertEquals(absent, None)
    }
  }

  stores.test("saving the same grant id replaces the record") { store =>
    for {
      _ <- store.save(grant)
      _ <- store.save(grant.copy(scopes = unsafe(Scopes.parse("read")), details = AuthorizationDetails.empty))
      found <- store.find(grant.id)
    } yield {
      assertEquals(found.map(_.scopes), Some(unsafe(Scopes.parse("read"))))
      assertEquals(found.map(_.details), Some(AuthorizationDetails.empty))
    }
  }

  stores.test("a revoked grant stays readable and marked") { store =>
    for {
      _ <- store.save(grant)
      _ <- store.revoke(grant.id)
      found <- store.find(grant.id)
      _ <- store.revoke(unsafe(GrantId.from("absent")))
    } yield assertEquals(found.map(_.revoked), Some(true))
  }
}

class EmbeddedGrantStoreSpec extends SqlGrantStoreSpec(Backend.embedded)

class PostgresGrantStoreSpec extends SqlGrantStoreSpec(Backend.postgres)
