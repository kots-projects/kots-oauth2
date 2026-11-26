package kots.oauth2.store.sql

import java.sql.Connection
import java.sql.ResultSet
import java.sql.Timestamp

import cats.effect.kernel.Sync
import cats.syntax.flatMap._

import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.GrantId
import kots.oauth2.core.GrantType
import kots.oauth2.core.RequestUri
import kots.oauth2.core.Subject
import kots.oauth2.store.AuditEvent
import kots.oauth2.store.AuditLog
import kots.oauth2.store.PushedRequest
import kots.oauth2.store.PushedRequestStore

final class SqlPushedRequestStore[F[_]: Sync] private (connect: F[Connection], clock: Clock[F])
    extends SqlSessions[F](connect)
    with PushedRequestStore[F] {

  def save(record: PushedRequest): F[Unit] = session { connection =>
    withTransaction(connection) {
      execute(connection, "DELETE FROM pushed_requests WHERE request_uri = ?", record.uri.value)
      val insert = connection.prepareStatement(
        "INSERT INTO pushed_requests(request_uri, client_id, parameters, expires_at) VALUES(?, ?, ?, ?)"
      )
      try {
        insert.setString(1, record.uri.value)
        insert.setString(2, record.clientId.value)
        insert.setString(3, DetailRows.encodeFields(record.parameters))
        insert.setTimestamp(4, Timestamp.from(record.expiresAt))
        insert.executeUpdate()
        ()
      } finally insert.close()
    }
  }

  def peek(uri: RequestUri): F[Option[PushedRequest]] =
    clock.instant.flatMap { now =>
      session { connection =>
        selectOne(connection, uri).filter(record => !record.isExpired(now))
      }
    }

  def consume(uri: RequestUri): F[Option[PushedRequest]] =
    clock.instant.flatMap { now =>
      session { connection =>
        withTransaction(connection) {
          selectOne(connection, uri).flatMap { record =>
            val removed = execute(connection, "DELETE FROM pushed_requests WHERE request_uri = ?", uri.value)
            if (removed == 1 && !record.isExpired(now)) Some(record) else None
          }
        }
      }
    }

  def sweep: F[Int] =
    clock.instant.flatMap { now =>
      session { connection =>
        val statement = connection.prepareStatement("DELETE FROM pushed_requests WHERE expires_at <= ?")
        try {
          statement.setTimestamp(1, Timestamp.from(now))
          statement.executeUpdate()
        } finally statement.close()
      }
    }

  private def selectOne(connection: Connection, uri: RequestUri): Option[PushedRequest] = {
    val select = connection.prepareStatement("SELECT * FROM pushed_requests WHERE request_uri = ?")
    try {
      select.setString(1, uri.value)
      val results = select.executeQuery()
      if (results.next())
        Some(
          PushedRequest(
            uri = DetailRows.required(RequestUri.from(results.getString("request_uri"))),
            clientId = DetailRows.required(ClientId.from(results.getString("client_id"))),
            parameters = DetailRows.decodeFields(results.getString("parameters")),
            expiresAt = results.getTimestamp("expires_at").toInstant
          )
        )
      else None
    } finally select.close()
  }
}

object SqlPushedRequestStore {

  def create[F[_]: Sync](
      connect: F[Connection],
      clock: Clock[F]
  ): Either[String, F[SqlPushedRequestStore[F]]] =
    SqlSupportStores.bootstrapped(connect, new SqlPushedRequestStore(connect, clock))
}

final class SqlAuditLog[F[_]: Sync] private (connect: F[Connection])
    extends SqlSessions[F](connect)
    with AuditLog[F] {

  def record(event: AuditEvent): F[Unit] = session { connection =>
    val insert = connection.prepareStatement(
      "INSERT INTO audit_events(name, client_id, subject, grant_id, active, grant_type) " +
        "VALUES(?, ?, ?, ?, ?, ?)"
    )
    try {
      insert.setString(1, event.name)
      insert.setNull(6, java.sql.Types.VARCHAR)
      event match {
        case AuditEvent.Issued(clientId, subject, grantId, grant) =>
          insert.setString(2, clientId.value)
          insert.setString(3, subject.value)
          insert.setString(4, grantId.value)
          insert.setNull(5, java.sql.Types.BOOLEAN)
          insert.setString(6, grant.value)
        case AuditEvent.Refreshed(clientId, subject, grantId) =>
          insert.setString(2, clientId.value)
          insert.setString(3, subject.value)
          insert.setString(4, grantId.value)
          insert.setNull(5, java.sql.Types.BOOLEAN)
        case AuditEvent.Revoked(clientId, grantId) =>
          insert.setString(2, clientId.value)
          insert.setNull(3, java.sql.Types.VARCHAR)
          insert.setString(4, grantId.value)
          insert.setNull(5, java.sql.Types.BOOLEAN)
        case AuditEvent.Introspected(clientId, active) =>
          insert.setString(2, clientId.value)
          insert.setNull(3, java.sql.Types.VARCHAR)
          insert.setNull(4, java.sql.Types.VARCHAR)
          insert.setBoolean(5, active)
        case AuditEvent.AuthenticationFailed(clientId) =>
          optional(insert, 2, clientId.map(_.value))
          insert.setNull(3, java.sql.Types.VARCHAR)
          insert.setNull(4, java.sql.Types.VARCHAR)
          insert.setNull(5, java.sql.Types.BOOLEAN)
        case AuditEvent.AssertionReplayed(clientId) =>
          insert.setString(2, clientId.value)
          insert.setNull(3, java.sql.Types.VARCHAR)
          insert.setNull(4, java.sql.Types.VARCHAR)
          insert.setNull(5, java.sql.Types.BOOLEAN)
      }
      insert.executeUpdate()
      ()
    } finally insert.close()
  }

  def events: F[List[AuditEvent]] = session { connection =>
    val statement = connection.createStatement()
    try {
      val results = statement.executeQuery(
        "SELECT name, client_id, subject, grant_id, active, grant_type FROM audit_events ORDER BY seq"
      )
      Iterator.continually(results).takeWhile(_.next()).map(eventOf).toList
    } finally statement.close()
  }

  private def eventOf(results: ResultSet): AuditEvent = {
    def client: ClientId = DetailRows.required(ClientId.from(results.getString("client_id")))
    def subject: Subject = DetailRows.required(Subject.from(results.getString("subject")))
    def grant: GrantId = DetailRows.required(GrantId.from(results.getString("grant_id")))
    def grantType: GrantType =
      DetailRows.required(GrantType.from(results.getString("grant_type")))
    results.getString("name") match {
      case "issued"             => AuditEvent.Issued(client, subject, grant, grantType)
      case "refreshed"          => AuditEvent.Refreshed(client, subject, grant)
      case "revoked"            => AuditEvent.Revoked(client, grant)
      case "introspected"       => AuditEvent.Introspected(client, results.getBoolean("active"))
      case "assertion_replayed" => AuditEvent.AssertionReplayed(client)
      case _                    =>
        AuditEvent.AuthenticationFailed(
          Option(results.getString("client_id")).map(raw => DetailRows.required(ClientId.from(raw)))
        )
    }
  }
}

object SqlAuditLog {

  def create[F[_]: Sync](connect: F[Connection]): Either[String, F[SqlAuditLog[F]]] =
    SqlSupportStores.bootstrapped(connect, new SqlAuditLog(connect))
}

private[sql] object SqlSupportStores {

  def bootstrapped[F[_]: Sync, A](connect: F[Connection], store: => A): Either[String, F[A]] =
    ConnectionMigrations
      .of(connect, Schema.migrations)
      .map(engine =>
        engine.apply.flatMap {
          case Left(reason) => Sync[F].raiseError(new IllegalStateException(reason))
          case Right(_)     => Sync[F].pure(store)
        }
      )
}
