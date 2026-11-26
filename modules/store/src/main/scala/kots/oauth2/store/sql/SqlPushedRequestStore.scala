package kots.oauth2.store.sql

import java.time.Instant

import cats.effect.kernel.MonadCancelThrow
import cats.syntax.all._

import kots.data.Database
import kots.data.Decoder
import kots.data.Session
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RequestUri
import kots.oauth2.store.PushedRequest
import kots.oauth2.store.PushedRequestStore
import kots.oauth2.store.sql.Sql._

final class SqlPushedRequestStore[F[_]: MonadCancelThrow] private (database: Database[F], clock: Clock[F])
    extends PushedRequestStore[F] {

  def save(record: PushedRequest): F[Unit] = database.transaction.use { transaction =>
    remove(transaction, record.uri) *>
      transaction
        .execute(
          sql"INSERT INTO pushed_requests(request_uri, client_id, parameters, expires_at) ${values(
              param(record.uri.value),
              param(record.clientId.value),
              param(DetailRows.encodeFields(record.parameters)),
              moment(record.expiresAt)
            )}"
        )
        .void
  }

  def peek(uri: RequestUri): F[Option[PushedRequest]] =
    clock.instant.flatMap { now =>
      database.session.use(selectOne(_, uri)).map(_.filter(record => !record.isExpired(now)))
    }

  def consume(uri: RequestUri): F[Option[PushedRequest]] =
    clock.instant.flatMap { now =>
      database.transaction.use { transaction =>
        selectOne(transaction, uri).flatMap(_.flatTraverse { record =>
          remove(transaction, uri).map(removed =>
            if (removed == 1L && !record.isExpired(now)) Some(record) else None
          )
        })
      }
    }

  def sweep: F[Int] =
    clock.instant.flatMap { now =>
      database.session.use(
        _.execute(sql"DELETE FROM pushed_requests WHERE expires_at <= ${moment(now)}").map(_.toInt)
      )
    }

  private def remove(session: Session[F], uri: RequestUri): F[Long] =
    session.execute(sql"DELETE FROM pushed_requests WHERE request_uri = ${param(uri.value)}")

  private def selectOne(session: Session[F], uri: RequestUri): F[Option[PushedRequest]] =
    session
      .query(
        sql"SELECT request_uri, client_id, parameters, expires_at FROM pushed_requests WHERE request_uri = ${param(uri.value)}"
      )(SqlPushedRequestStore.Row)
      .flatMap(_.headOption.traverse(row => required(SqlPushedRequestStore.record(row))))
}

object SqlPushedRequestStore {

  private type Row = (String, String, String, Instant)

  private val Row: Decoder[Row] = (Decoder[String], Decoder[String], Decoder[String], Sql.instant).tupled

  private def record(row: Row): Either[ParseFailure, PushedRequest] =
    row match {
      case (uri, clientId, parameters, expiresAt) =>
        (RequestUri.from(uri), ClientId.from(clientId)).mapN(
          PushedRequest(_, _, DetailRows.decodeFields(parameters), expiresAt)
        )
    }

  def create[F[_]: MonadCancelThrow](
      database: Database[F],
      clock: Clock[F]
  ): Either[String, F[SqlPushedRequestStore[F]]] =
    Schema.applied(database, new SqlPushedRequestStore(database, clock))
}
