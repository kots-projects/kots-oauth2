package kots.oauth2.store.sql

import java.time.Instant

import cats.effect.kernel.MonadCancelThrow
import cats.syntax.all._

import kots.data.Database
import kots.data.Decoder
import kots.data.Fragment
import kots.data.Session
import kots.oauth2.core.AccessToken
import kots.oauth2.core.AccessTokenHash
import kots.oauth2.core.Audience
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.CertificateThumbprint
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.GrantId
import kots.oauth2.core.GrantType
import kots.oauth2.core.KeyThumbprint
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RefreshToken
import kots.oauth2.core.RefreshTokenHash
import kots.oauth2.core.RevocationToken
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.TokenTypeHint
import kots.oauth2.core.Wire
import kots.oauth2.store.TokenRecord
import kots.oauth2.store.TokenStore
import kots.oauth2.store.sql.Sql._

final class SqlTokenStore[F[_]] private (database: Database[F], clock: Clock[F])(implicit
    F: MonadCancelThrow[F]
) extends TokenStore[F] {

  def save(record: TokenRecord): F[Unit] = database.transaction.use { transaction =>
    purge(transaction, record.accessTokenHash) *> insertRecord(transaction, record)
  }

  def findByAccess(token: AccessToken): F[Option[TokenRecord]] =
    clock.instant.flatMap { now =>
      database.session.use { session =>
        selectOne(session, sql"access_hash = ${param(AccessTokenHash.of(token).value)}")
          .flatMap(_.flatTraverse { record =>
            if (!record.isAccessExpired(now) && record.matchesAccess(token)) F.pure(Option(record))
            else purge(session, record.accessTokenHash).as(Option.empty[TokenRecord])
          })
      }
    }

  def findByRefresh(token: RefreshToken): F[Option[TokenRecord]] =
    clock.instant.flatMap { now =>
      database.session.use { session =>
        selectOne(session, sql"refresh_hash = ${param(RefreshTokenHash.of(token).value)}")
          .flatMap(_.flatTraverse { record =>
            if (!record.isRefreshExpired(now) && record.matchesRefresh(token)) F.pure(Option(record))
            else purge(session, record.accessTokenHash).as(Option.empty[TokenRecord])
          })
      }
    }

  def drop(refreshToken: RefreshToken): F[Unit] = database.session.use(dropByRefresh(_, refreshToken))

  def retire(refreshToken: RefreshToken, grantId: GrantId): F[Unit] = database.transaction.use {
    transaction =>
      val hash = param(RefreshTokenHash.of(refreshToken).value)
      dropByRefresh(transaction, refreshToken) *>
        transaction.execute(sql"DELETE FROM retired_tokens WHERE refresh_hash = $hash") *>
        transaction
          .execute(
            sql"INSERT INTO retired_tokens(refresh_hash, grant_id) ${values(hash, param(grantId.value))}"
          )
          .void
  }

  def rotated(refreshToken: RefreshToken): F[Option[GrantId]] = database.session.use { session =>
    session
      .query[String](
        sql"SELECT grant_id FROM retired_tokens WHERE refresh_hash = ${param(RefreshTokenHash.of(refreshToken).value)}"
      )
      .flatMap(_.headOption.traverse(raw => required(GrantId.from(raw))))
  }

  def revoke(
      token: RevocationToken,
      hint: Option[TokenTypeHint],
      clientId: ClientId
  ): F[Option[GrantId]] = database.session.use { session =>
    val owned = sql"client_id = ${param(clientId.value)}"
    val byRefresh: F[Option[Option[GrantId]]] =
      RevocationToken.asRefreshToken(token).flatTraverse { refresh =>
        selectOne(session, sql"refresh_hash = ${param(RefreshTokenHash.of(refresh).value)} AND $owned")
          .flatMap(_.traverse(record => revokeGrantRows(session, record.grantId).as(Option(record.grantId))))
      }
    val byAccess: F[Option[Option[GrantId]]] =
      RevocationToken.asAccessToken(token).flatTraverse { access =>
        selectOne(session, sql"access_hash = ${param(AccessTokenHash.of(access).value)} AND $owned")
          .flatMap(_.traverse(record => purge(session, record.accessTokenHash).as(Option.empty[GrantId])))
      }
    val outcome = hint match {
      case Some(TokenTypeHint.RefreshToken) => byRefresh
      case Some(TokenTypeHint.AccessToken)  => byAccess
      case None => byRefresh.flatMap(_.fold(byAccess)(found => F.pure(Option(found))))
    }
    outcome.map(_.flatten)
  }

  def revokeGrant(grantId: GrantId): F[Unit] = database.session.use(revokeGrantRows(_, grantId))

  def sweep: F[Int] =
    clock.instant.flatMap { now =>
      val spent =
        sql"access_expires_at <= ${moment(now)} AND (refresh_expires_at IS NULL OR refresh_expires_at <= ${moment(now)})"
      database.session.use { session =>
        session.execute(
          sql"DELETE FROM token_details WHERE access_hash IN (SELECT access_hash FROM tokens WHERE $spent)"
        ) *> session.execute(sql"DELETE FROM tokens WHERE $spent").map(_.toInt)
      }
    }

  private def dropByRefresh(session: Session[F], refreshToken: RefreshToken): F[Unit] =
    removeWhere(session, sql"refresh_hash = ${param(RefreshTokenHash.of(refreshToken).value)}")

  private def revokeGrantRows(session: Session[F], grantId: GrantId): F[Unit] =
    removeWhere(session, sql"grant_id = ${param(grantId.value)}")

  private def removeWhere(session: Session[F], condition: Fragment): F[Unit] =
    session.execute(
      sql"DELETE FROM token_details WHERE access_hash IN (SELECT access_hash FROM tokens WHERE $condition)"
    ) *> session.execute(sql"DELETE FROM tokens WHERE $condition").void

  private def purge(session: Session[F], hash: AccessTokenHash): F[Unit] =
    session.execute(sql"DELETE FROM token_details WHERE access_hash = ${param(hash.value)}") *>
      session.execute(sql"DELETE FROM tokens WHERE access_hash = ${param(hash.value)}").void

  private def insertRecord(session: Session[F], record: TokenRecord): F[Unit] =
    session.execute(
      sql"INSERT INTO tokens(${SqlTokenStore.Columns}) ${values(
          param(record.accessTokenHash.value),
          param(record.refreshTokenHash.map(_.value)),
          param(record.grantId.value),
          param(record.clientId.value),
          param(record.subject.value),
          param(Wire[Scopes].encode(record.scopes)),
          moment(record.issuedAt),
          moment(record.accessExpiresAt),
          moment(record.refreshExpiresAt),
          param(record.audience.map(_.value)),
          param(record.actor.map(_.value)),
          param(record.grant.value),
          param(record.jkt.map(_.value)),
          param(record.x5t.map(_.value))
        )}"
    ) *> DetailRows.insert(
      session,
      "token_details",
      "access_hash",
      record.accessTokenHash.value,
      record.details
    )

  private def selectOne(session: Session[F], condition: Fragment): F[Option[TokenRecord]] =
    session
      .query(sql"SELECT ${SqlTokenStore.Columns} FROM tokens WHERE $condition")(SqlTokenStore.Row)
      .flatMap(_.headOption.traverse { row =>
        DetailRows
          .read(session, "token_details", "access_hash", row._1)
          .flatMap(details => required(SqlTokenStore.record(row, details)))
      })
}

object SqlTokenStore {

  private val Columns: Fragment = Fragment.sql(
    "access_hash, refresh_hash, grant_id, client_id, subject, scopes, issued_at, access_expires_at, " +
      "refresh_expires_at, audience, actor, grant_type, jkt, x5t"
  )

  private type Row = (
      String,
      Option[String],
      String,
      String,
      String,
      String,
      Instant,
      Instant,
      Option[Instant],
      Option[String],
      Option[String],
      Option[String],
      Option[String],
      Option[String]
  )

  private val Row: Decoder[Row] = (
    Decoder[String],
    Decoder[Option[String]],
    Decoder[String],
    Decoder[String],
    Decoder[String],
    Decoder[String],
    Sql.instant,
    Sql.instant,
    Decoder.option(Sql.instant),
    Decoder[Option[String]],
    Decoder[Option[String]],
    Decoder[Option[String]],
    Decoder[Option[String]],
    Decoder[Option[String]]
  ).tupled

  private def record(row: Row, details: AuthorizationDetails): Either[ParseFailure, TokenRecord] =
    row match {
      case (
            access,
            refresh,
            grantId,
            clientId,
            subject,
            scopes,
            issued,
            expires,
            refreshExpires,
            audience,
            actor,
            grantType,
            jkt,
            x5t
          ) =>
        for {
          accessHash <- AccessTokenHash.fromStored(access)
          refreshHash <- refresh.traverse(RefreshTokenHash.fromStored)
          grant <- GrantId.from(grantId)
          client <- ClientId.from(clientId)
          owner <- Subject.from(subject)
          granted <- Wire[Scopes].decode(scopes)
          target <- audience.traverse(Audience.from)
          acting <- actor.traverse(Subject.from)
          key <- jkt.traverse(KeyThumbprint.from)
          certificate <- x5t.traverse(CertificateThumbprint.from)
        } yield TokenRecord(
          accessHash,
          refreshHash,
          grant,
          client,
          owner,
          granted,
          details,
          issued,
          expires,
          refreshExpires,
          target,
          acting,
          grantType.flatMap(raw => GrantType.from(raw).toOption).getOrElse(GrantType.AuthorizationCode),
          key,
          certificate
        )
    }

  def create[F[_]: MonadCancelThrow](
      database: Database[F],
      clock: Clock[F]
  ): Either[String, F[SqlTokenStore[F]]] =
    Schema.applied(database, new SqlTokenStore(database, clock))
}
