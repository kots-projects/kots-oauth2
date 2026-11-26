package kots.oauth2.store.sql

import java.sql.Connection
import java.sql.DriverManager
import java.util.concurrent.atomic.AtomicInteger

import cats.effect.IO
import kots.oauth2.core.ClientId
import kots.oauth2.core.GrantId
import kots.oauth2.core.GrantType
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Subject
import kots.oauth2.store.AuditEvent
import munit.CatsEffectSuite

class SqlSupportStoresSpec extends CatsEffectSuite {

  private val databases = new AtomicInteger(0)

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val subject: Subject = unsafe(Subject.from("user-1"))

  private def connect: IO[Connection] = {
    val name = s"support-${databases.get}"
    IO.blocking {
      Class.forName("org.h2.Driver")
      DriverManager.getConnection(s"jdbc:h2:mem:$name;DB_CLOSE_DELAY=-1")
    }
  }

  override def beforeEach(context: BeforeEach): Unit = {
    databases.incrementAndGet()
    ()
  }

  test("audit events read back in order with their fields") {
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
      log <- SqlAuditLog.create[IO](connect).toOption.get
      _ <- recorded.foldLeft(IO.unit)((io, event) => io >> log.record(event))
      events <- log.events
    } yield assertEquals(events, recorded)
  }
}
