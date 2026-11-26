package kots.oauth2.store.sql

import java.time.Instant

import cats.effect.kernel.MonadCancelThrow
import cats.syntax.all._

import kots.data.Database
import kots.data.Decoder
import kots.data.Fragment
import kots.data.Session
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.DeviceCode
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.ResourceIndicator
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.UserCode
import kots.oauth2.core.Wire
import kots.oauth2.store.DeviceRecord
import kots.oauth2.store.DeviceStore
import kots.oauth2.store.sql.Sql._

final class SqlDeviceStore[F[_]: MonadCancelThrow] private (database: Database[F], clock: Clock[F])
    extends DeviceStore[F] {

  def save(record: DeviceRecord): F[Unit] = database.transaction.use { transaction =>
    remove(transaction, record.deviceCode) *>
      transaction
        .execute(
          sql"INSERT INTO devices(${SqlDeviceStore.Columns}) ${values(
              param(record.deviceCode.value),
              param(record.userCode.value),
              param(record.clientId.value),
              param(Wire[Scopes].encode(record.scopes)),
              moment(record.expiresAt),
              param(record.subject.map(_.value)),
              param(record.denied),
              moment(record.lastPolledAt),
              param(record.resource.map(_.value))
            )}"
        )
        .void
  }

  def pending(userCode: UserCode): F[Option[DeviceRecord]] =
    clock.instant.flatMap(now =>
      database.session.use { session =>
        select(
          session,
          sql"user_code = ${param(userCode.value)} AND subject IS NULL AND denied = FALSE AND expires_at > ${moment(now)} ORDER BY expires_at DESC"
        )
      }
    )

  def approve(userCode: UserCode, subject: Subject): F[Boolean] =
    decide(userCode, sql"subject = ${param(subject.value)}")

  def deny(userCode: UserCode): F[Boolean] =
    decide(userCode, sql"denied = TRUE")

  def poll(deviceCode: DeviceCode): F[Option[DeviceRecord]] =
    clock.instant.flatMap { now =>
      database.transaction.use { transaction =>
        selectOne(transaction, deviceCode).flatMap(_.traverse { record =>
          transaction
            .execute(
              sql"UPDATE devices SET last_polled_at = ${moment(now)} WHERE device_code = ${param(deviceCode.value)}"
            )
            .as(record)
        })
      }
    }

  def consume(deviceCode: DeviceCode): F[Option[DeviceRecord]] =
    clock.instant.flatMap { now =>
      database.transaction.use { transaction =>
        selectOne(transaction, deviceCode).flatMap(_.flatTraverse { record =>
          remove(transaction, deviceCode).map(removed =>
            if (removed == 1L && !record.isExpired(now)) Some(record) else None
          )
        })
      }
    }

  def sweep: F[Int] =
    clock.instant.flatMap { now =>
      database.session.use(
        _.execute(sql"DELETE FROM devices WHERE expires_at <= ${moment(now)}").map(_.toInt)
      )
    }

  private def decide(userCode: UserCode, assignment: Fragment): F[Boolean] =
    clock.instant.flatMap { now =>
      database.session.use { session =>
        session
          .execute(
            sql"UPDATE devices SET $assignment WHERE user_code = ${param(userCode.value)} AND subject IS NULL AND denied = FALSE AND expires_at > ${moment(now)}"
          )
          .map(_ == 1L)
      }
    }

  private def remove(session: Session[F], deviceCode: DeviceCode): F[Long] =
    session.execute(sql"DELETE FROM devices WHERE device_code = ${param(deviceCode.value)}")

  private def selectOne(session: Session[F], deviceCode: DeviceCode): F[Option[DeviceRecord]] =
    select(session, sql"device_code = ${param(deviceCode.value)}")

  private def select(session: Session[F], condition: Fragment): F[Option[DeviceRecord]] =
    session
      .query(sql"SELECT ${SqlDeviceStore.Columns} FROM devices WHERE $condition")(SqlDeviceStore.Row)
      .flatMap(_.headOption.traverse(row => required(SqlDeviceStore.record(row))))
}

object SqlDeviceStore {

  private val Columns: Fragment = Fragment.sql(
    "device_code, user_code, client_id, scopes, expires_at, subject, denied, last_polled_at, resource"
  )

  private type Row =
    (String, String, String, String, Instant, Option[String], Boolean, Option[Instant], Option[String])

  private val Row: Decoder[Row] = (
    Decoder[String],
    Decoder[String],
    Decoder[String],
    Decoder[String],
    Sql.instant,
    Decoder[Option[String]],
    Decoder[Boolean],
    Decoder.option(Sql.instant),
    Decoder[Option[String]]
  ).tupled

  private def record(row: Row): Either[ParseFailure, DeviceRecord] =
    row match {
      case (deviceCode, userCode, clientId, scopes, expiresAt, subject, denied, polled, resource) =>
        for {
          device <- DeviceCode.from(deviceCode)
          user <- UserCode.from(userCode)
          client <- ClientId.from(clientId)
          granted <- Wire[Scopes].decode(scopes)
          owner <- subject.traverse(Subject.from)
          indicator <- resource.traverse(ResourceIndicator.from)
        } yield DeviceRecord(device, user, client, granted, expiresAt, owner, denied, polled, indicator)
    }

  def create[F[_]: MonadCancelThrow](
      database: Database[F],
      clock: Clock[F]
  ): Either[String, F[SqlDeviceStore[F]]] =
    Schema.applied(database, new SqlDeviceStore(database, clock))
}
