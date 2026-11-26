package kots.oauth2.store.sql

import cats.effect.IO
import kots.oauth2.core.ClientId
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.store.ConsentRecord
import munit.CatsEffectSuite

abstract class SqlConsentStoreSpec(backend: Backend) extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val subject: Subject = unsafe(Subject.from("user-1"))

  private val stores = ResourceFunFixture(
    backend.database.evalMap(database => SqlConsentStore.create[IO](database).toOption.get)
  )

  stores.test("consents union across grants and decide by subset") { store =>
    for {
      _ <- store.grant(ConsentRecord(clientId, subject, unsafe(Scopes.parse("read"))))
      _ <- store.grant(ConsentRecord(clientId, subject, unsafe(Scopes.parse("write"))))
      allowed <- store.decide(clientId, subject, unsafe(Scopes.parse("read write")))
      denied <- store.decide(clientId, subject, unsafe(Scopes.parse("admin")))
      foreign <- store.decide(unsafe(ClientId.from("client-2")), subject, unsafe(Scopes.parse("read")))
      _ <- store.revoke(clientId, subject)
      revoked <- store.decide(clientId, subject, unsafe(Scopes.parse("read")))
    } yield {
      assertEquals(allowed, true)
      assertEquals(denied, false)
      assertEquals(foreign, false)
      assertEquals(revoked, false)
    }
  }
}

class EmbeddedConsentStoreSpec extends SqlConsentStoreSpec(Backend.embedded)

class PostgresConsentStoreSpec extends SqlConsentStoreSpec(Backend.postgres)
