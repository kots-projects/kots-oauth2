package kots.oauth2.store.sql

import cats.effect.kernel.MonadCancelThrow
import cats.syntax.all._

import kots.data.Database
import kots.data.Decoder
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.ClientId
import kots.oauth2.core.GrantId
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.Wire
import kots.oauth2.store.Grant
import kots.oauth2.store.GrantStore
import kots.oauth2.store.sql.Sql._

final class SqlGrantStore[F[_]: MonadCancelThrow] private (database: Database[F]) extends GrantStore[F] {

  def save(grant: Grant): F[Unit] = database.transaction.use { transaction =>
    transaction.execute(sql"DELETE FROM grant_details WHERE grant_id = ${param(grant.id.value)}") *>
      transaction.execute(sql"DELETE FROM grants WHERE grant_id = ${param(grant.id.value)}") *>
      transaction.execute(
        sql"INSERT INTO grants(grant_id, client_id, subject, scopes, revoked) ${values(
            param(grant.id.value),
            param(grant.clientId.value),
            param(grant.subject.value),
            param(Wire[Scopes].encode(grant.scopes)),
            param(grant.revoked)
          )}"
      ) *>
      DetailRows.insert(transaction, "grant_details", "grant_id", grant.id.value, grant.details)
  }

  def find(id: GrantId): F[Option[Grant]] = database.session.use { session =>
    session
      .query(
        sql"SELECT grant_id, client_id, subject, scopes, revoked FROM grants WHERE grant_id = ${param(id.value)}"
      )(SqlGrantStore.Row)
      .flatMap(_.headOption.traverse { row =>
        DetailRows
          .read(session, "grant_details", "grant_id", id.value)
          .flatMap(details => required(SqlGrantStore.grant(row, details)))
      })
  }

  def revoke(id: GrantId): F[Unit] = database.session.use { session =>
    session.execute(sql"UPDATE grants SET revoked = TRUE WHERE grant_id = ${param(id.value)}").void
  }
}

object SqlGrantStore {

  private type Row = (String, String, String, String, Boolean)

  private val Row: Decoder[Row] =
    (Decoder[String], Decoder[String], Decoder[String], Decoder[String], Decoder[Boolean]).tupled

  private def grant(row: Row, details: AuthorizationDetails): Either[ParseFailure, Grant] =
    row match {
      case (id, clientId, subject, scopes, revoked) =>
        for {
          grantId <- GrantId.from(id)
          client <- ClientId.from(clientId)
          owner <- Subject.from(subject)
          granted <- Wire[Scopes].decode(scopes)
        } yield Grant(grantId, client, owner, granted, details, revoked)
    }

  def create[F[_]: MonadCancelThrow](database: Database[F]): Either[String, F[SqlGrantStore[F]]] =
    Schema.applied(database, new SqlGrantStore(database))
}
