package kots.oauth2.store.sql

import cats.effect.kernel.MonadCancelThrow
import cats.syntax.all._

import kots.data.Database
import kots.data.Decoder
import kots.oauth2.core.ClientId
import kots.oauth2.core.GrantId
import kots.oauth2.core.GrantType
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Subject
import kots.oauth2.store.AuditEvent
import kots.oauth2.store.AuditLog
import kots.oauth2.store.sql.Sql._

final class SqlAuditLog[F[_]: MonadCancelThrow] private (database: Database[F]) extends AuditLog[F] {

  def record(event: AuditEvent): F[Unit] = database.session.use { session =>
    val (clientId, subject, grantId, active, grantType) = SqlAuditLog.columns(event)
    session
      .execute(
        sql"INSERT INTO audit_events(name, client_id, subject, grant_id, active, grant_type) ${values(
            param(event.name),
            param(clientId.map(_.value)),
            param(subject.map(_.value)),
            param(grantId.map(_.value)),
            param(active),
            param(grantType.map(_.value))
          )}"
      )
      .void
  }

  def events: F[List[AuditEvent]] = database.session.use { session =>
    session
      .query(
        sql"SELECT name, client_id, subject, grant_id, active, grant_type FROM audit_events ORDER BY seq"
      )(
        SqlAuditLog.Row
      )
      .flatMap(rows => required(rows.traverse(SqlAuditLog.event)))
  }
}

object SqlAuditLog {

  private type Columns =
    (Option[ClientId], Option[Subject], Option[GrantId], Option[Boolean], Option[GrantType])

  private type Row = (String, Option[String], Option[String], Option[String], Option[Boolean], Option[String])

  private val Row: Decoder[Row] = (
    Decoder[String],
    Decoder[Option[String]],
    Decoder[Option[String]],
    Decoder[Option[String]],
    Decoder[Option[Boolean]],
    Decoder[Option[String]]
  ).tupled

  private def columns(event: AuditEvent): Columns =
    event match {
      case AuditEvent.Issued(clientId, subject, grantId, grant) =>
        (Some(clientId), Some(subject), Some(grantId), None, Some(grant))
      case AuditEvent.Refreshed(clientId, subject, grantId) =>
        (Some(clientId), Some(subject), Some(grantId), None, None)
      case AuditEvent.Revoked(clientId, grantId)     => (Some(clientId), None, Some(grantId), None, None)
      case AuditEvent.Introspected(clientId, active) => (Some(clientId), None, None, Some(active), None)
      case AuditEvent.AuthenticationFailed(clientId) => (clientId, None, None, None, None)
      case AuditEvent.AssertionReplayed(clientId)    => (Some(clientId), None, None, None, None)
    }

  private def event(row: Row): Either[ParseFailure, AuditEvent] =
    row match {
      case (name, clientId, subject, grantId, active, grantType) =>
        def present(column: String, value: Option[String]): Either[ParseFailure, String] =
          value.toRight(ParseFailure("AuditEvent", s"no $column"))
        val client = present("client_id", clientId).flatMap(ClientId.from)
        val owner = present("subject", subject).flatMap(Subject.from)
        val grant = present("grant_id", grantId).flatMap(GrantId.from)
        name match {
          case "issued" =>
            (client, owner, grant, present("grant_type", grantType).flatMap(GrantType.from))
              .mapN(AuditEvent.Issued(_, _, _, _))
          case "refreshed"          => (client, owner, grant).mapN(AuditEvent.Refreshed(_, _, _))
          case "revoked"            => (client, grant).mapN(AuditEvent.Revoked(_, _))
          case "introspected"       => client.map(AuditEvent.Introspected(_, active.getOrElse(false)))
          case "assertion_replayed" => client.map(AuditEvent.AssertionReplayed(_))
          case _ => clientId.traverse(ClientId.from).map(AuditEvent.AuthenticationFailed(_))
        }
    }

  def create[F[_]: MonadCancelThrow](database: Database[F]): Either[String, F[SqlAuditLog[F]]] =
    Schema.applied(database, new SqlAuditLog(database))
}
