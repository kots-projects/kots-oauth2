package kots.oauth2.store.sql

import java.time.Instant

import cats.effect.kernel.MonadCancelThrow
import cats.syntax.all._

import kots.data.Database
import kots.data.Decoder
import kots.data.Session
import kots.oauth2.core.AuthorizationCode
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.CodeChallenge
import kots.oauth2.core.CodeChallengeMethod
import kots.oauth2.core.GrantId
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Pkce
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.ResourceIndicator
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.Wire
import kots.oauth2.store.CodeRecord
import kots.oauth2.store.CodeStore
import kots.oauth2.store.sql.Sql._

final class SqlCodeStore[F[_]: MonadCancelThrow] private (database: Database[F], clock: Clock[F])
    extends CodeStore[F] {

  def save(record: CodeRecord): F[Unit] = database.transaction.use { transaction =>
    transaction.execute(sql"DELETE FROM code_details WHERE code = ${param(record.code.value)}") *>
      transaction.execute(sql"DELETE FROM codes WHERE code = ${param(record.code.value)}") *>
      insertRecord(transaction, record)
  }

  def consume(code: AuthorizationCode): F[Option[CodeRecord]] =
    clock.instant.flatMap { now =>
      database.transaction.use { transaction =>
        selectOne(transaction, code).flatMap(_.flatTraverse { record =>
          for {
            removed <- transaction.execute(sql"DELETE FROM codes WHERE code = ${param(code.value)}")
            _ <- transaction.execute(sql"DELETE FROM code_details WHERE code = ${param(code.value)}")
          } yield if (removed == 1L && !record.isExpired(now)) Some(record) else None
        })
      }
    }

  def redeem(code: AuthorizationCode, grant: GrantId): F[Unit] = database.transaction.use { transaction =>
    transaction.execute(sql"DELETE FROM redeemed_codes WHERE code = ${param(code.value)}") *>
      transaction
        .execute(
          sql"INSERT INTO redeemed_codes(code, grant_id) ${values(param(code.value), param(grant.value))}"
        )
        .void
  }

  def redeemed(code: AuthorizationCode): F[Option[GrantId]] = database.session.use { session =>
    session
      .query[String](sql"SELECT grant_id FROM redeemed_codes WHERE code = ${param(code.value)}")
      .flatMap(_.headOption.traverse(raw => required(GrantId.from(raw))))
  }

  def sweep: F[Int] =
    clock.instant.flatMap { now =>
      database.session.use { session =>
        session.execute(
          sql"DELETE FROM code_details WHERE code IN (SELECT code FROM codes WHERE expires_at <= ${moment(now)})"
        ) *> session.execute(sql"DELETE FROM codes WHERE expires_at <= ${moment(now)}").map(_.toInt)
      }
    }

  private def insertRecord(session: Session[F], record: CodeRecord): F[Unit] =
    session.execute(
      sql"INSERT INTO codes(code, client_id, redirect_uri, subject, scopes, challenge, challenge_method, expires_at, resource) ${values(
          param(record.code.value),
          param(record.clientId.value),
          param(record.redirectUri.value),
          param(record.subject.value),
          param(Wire[Scopes].encode(record.scopes)),
          param(record.pkce.map(_.challenge.value)),
          param(record.pkce.map(_.method.value)),
          moment(record.expiresAt),
          param(record.resource.map(_.value))
        )}"
    ) *> DetailRows.insert(session, "code_details", "code", record.code.value, record.details)

  private def selectOne(session: Session[F], code: AuthorizationCode): F[Option[CodeRecord]] =
    session
      .query(
        sql"SELECT code, client_id, redirect_uri, subject, scopes, challenge, challenge_method, expires_at, resource FROM codes WHERE code = ${param(code.value)}"
      )(SqlCodeStore.Row)
      .flatMap(_.headOption.traverse { row =>
        DetailRows
          .read(session, "code_details", "code", row._1)
          .flatMap(details => required(SqlCodeStore.record(row, details)))
      })
}

object SqlCodeStore {

  private type Row =
    (String, String, String, String, String, Option[String], Option[String], Instant, Option[String])

  private val Row: Decoder[Row] = (
    Decoder[String],
    Decoder[String],
    Decoder[String],
    Decoder[String],
    Decoder[String],
    Decoder[Option[String]],
    Decoder[Option[String]],
    Sql.instant,
    Decoder[Option[String]]
  ).tupled

  private def record(row: Row, details: AuthorizationDetails): Either[ParseFailure, CodeRecord] =
    row match {
      case (code, clientId, redirectUri, subject, scopes, challenge, method, expiresAt, resource) =>
        for {
          parsedCode <- AuthorizationCode.from(code)
          client <- ClientId.from(clientId)
          redirect <- RedirectUri.from(redirectUri)
          owner <- Subject.from(subject)
          granted <- Wire[Scopes].decode(scopes)
          pkce <- challenge.traverse(raw =>
            (CodeChallenge.from(raw), CodeChallengeMethod.from(method.getOrElse(""))).mapN(Pkce(_, _))
          )
          indicator <- resource.traverse(ResourceIndicator.from)
        } yield CodeRecord(parsedCode, client, redirect, owner, granted, details, pkce, expiresAt, indicator)
    }

  def create[F[_]: MonadCancelThrow](
      database: Database[F],
      clock: Clock[F]
  ): Either[String, F[SqlCodeStore[F]]] =
    Schema.applied(database, new SqlCodeStore(database, clock))
}
