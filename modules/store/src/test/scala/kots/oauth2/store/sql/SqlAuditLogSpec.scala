package kots.oauth2.store.sql

import cats.effect.IO
import kots.oauth2.core.ClientId
import kots.oauth2.core.GrantId
import kots.oauth2.core.GrantType
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Subject
import kots.oauth2.store.AuditEvent
import munit.CatsEffectSuite

abstract class SqlAuditLogSpec(backend: Backend) extends CatsEffectSuite {

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val subject: Subject = unsafe(Subject.from("user-1"))

  private val logs = ResourceFunFixture(
    backend.database.evalMap(database => SqlAuditLog.create[IO](database).toOption.get)
  )

  logs.test("audit events read back in order with their fields") { log =>
    val grant = unsafe(GrantId.from("grant-1"))
    val recorded = List(
      AuditEvent.Issued(clientId, subject, grant, GrantType.IdJag),
      AuditEvent.Refreshed(clientId, subject, grant),
      AuditEvent.Revoked(clientId, grant),
      AuditEvent.Introspected(clientId, active = true),
      AuditEvent.AuthenticationFailed(Some(clientId)),
      AuditEvent.AuthenticationFailed(None),
      AuditEvent.AssertionReplayed(clientId)
    )
    for {
      _ <- recorded.foldLeft(IO.unit)((io, event) => io >> log.record(event))
      events <- log.events
    } yield assertEquals(events, recorded)
  }
}

class EmbeddedAuditLogSpec extends SqlAuditLogSpec(Backend.embedded)

class PostgresAuditLogSpec extends SqlAuditLogSpec(Backend.postgres)
