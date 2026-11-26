package kots.oauth2.store.sql

import cats.effect.kernel.MonadCancelThrow
import cats.syntax.all._

import kots.data.Database
import kots.data.Fragment
import kots.data.Session
import kots.oauth2.core.ClientId
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.Wire
import kots.oauth2.store.ConsentRecord
import kots.oauth2.store.ConsentStore
import kots.oauth2.store.sql.Sql._

final class SqlConsentStore[F[_]: MonadCancelThrow] private (database: Database[F]) extends ConsentStore[F] {

  def grant(record: ConsentRecord): F[Unit] = database.transaction.use { transaction =>
    existing(transaction, record.clientId, record.subject).flatMap { granted =>
      val merged = granted.fold(record.scopes)(Scopes.union(_, record.scopes))
      transaction.execute(sql"DELETE FROM consents WHERE ${owned(record.clientId, record.subject)}") *>
        transaction
          .execute(
            sql"INSERT INTO consents(client_id, subject, scopes) ${values(
                param(record.clientId.value),
                param(record.subject.value),
                param(Wire[Scopes].encode(merged))
              )}"
          )
          .void
    }
  }

  def revoke(clientId: ClientId, subject: Subject): F[Unit] = database.session.use { session =>
    session.execute(sql"DELETE FROM consents WHERE ${owned(clientId, subject)}").void
  }

  def decide(clientId: ClientId, subject: Subject, scopes: Scopes): F[Boolean] = database.session.use {
    session =>
      existing(session, clientId, subject).map(_.exists(allowed => Scopes.isSubsetOf(scopes, allowed)))
  }

  private def owned(clientId: ClientId, subject: Subject): Fragment =
    sql"client_id = ${param(clientId.value)} AND subject = ${param(subject.value)}"

  private def existing(session: Session[F], clientId: ClientId, subject: Subject): F[Option[Scopes]] =
    session
      .query[String](sql"SELECT scopes FROM consents WHERE ${owned(clientId, subject)}")
      .flatMap(_.headOption.traverse(raw => required(Wire[Scopes].decode(raw))))
}

object SqlConsentStore {

  def create[F[_]: MonadCancelThrow](database: Database[F]): Either[String, F[SqlConsentStore[F]]] =
    Schema.applied(database, new SqlConsentStore(database))
}
