package kots.oauth2.store.sql

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

import cats.effect.kernel.MonadCancelThrow
import cats.syntax.all._

import kots.data.DataError
import kots.data.Database
import kots.data.Decoder
import kots.data.Fragment
import kots.data.Session
import kots.oauth2.store.sql.Sql._

final case class Migration(version: Int, script: String) {
  def checksum: String =
    MessageDigest
      .getInstance("SHA-256")
      .digest(script.getBytes(StandardCharsets.UTF_8))
      .map(byte => f"$byte%02x")
      .mkString
}

final class Migrations[F[_]] private (database: Database[F], steps: List[Migration])(implicit
    F: MonadCancelThrow[F]
) {

  def version: F[Int] = recorded.map(_.lastOption.fold(0)(_._1))

  def pending: F[List[Migration]] = version.map(applied => steps.filter(_.version > applied))

  def verify: F[Either[String, Int]] = recorded.map(checked)

  def apply: F[Either[String, Int]] =
    verify.flatMap {
      case Left(reason)   => F.pure(Left(reason))
      case Right(applied) =>
        steps
          .filter(_.version > applied)
          .traverse_(record)
          .as(steps.lastOption.fold(applied)(_.version).asRight[String])
          .recover { case failure: DataError => Left(failure.getMessage) }
    }

  private def checked(rows: List[(Int, String)]): Either[String, Int] = {
    val expected = steps.take(rows.size).map(step => step.version -> step.checksum)
    if (rows.size > steps.size) Left("more migrations are recorded than are known")
    else if (rows != expected) Left("the recorded migrations disagree with the known scripts")
    else Right(rows.lastOption.fold(0)(_._1))
  }

  private def record(step: Migration): F[Unit] =
    database.transaction.use { transaction =>
      transaction.script(step.script) *> transaction
        .execute(
          sql"INSERT INTO schema_version(version, checksum, applied_at) VALUES(${param(step.version)}, ${param(step.checksum)}, CURRENT_TIMESTAMP)"
        )
        .void
    }

  private def recorded: F[List[(Int, String)]] =
    database.session.use(session => ensure(session) *> session.query(Migrations.Recorded)(Migrations.Row))

  private def ensure(session: Session[F]): F[Unit] =
    session.execute(Migrations.Ensure).void
}

object Migrations {

  private val Ensure: Fragment = Fragment.sql(
    "CREATE TABLE IF NOT EXISTS schema_version(" +
      "version INT PRIMARY KEY, checksum VARCHAR(64) NOT NULL, applied_at TIMESTAMP NOT NULL)"
  )

  private val Recorded: Fragment =
    Fragment.sql("SELECT version, checksum FROM schema_version ORDER BY version")

  private val Row: Decoder[(Int, String)] = (Decoder[Int], Decoder[String]).tupled

  def of[F[_]: MonadCancelThrow](
      database: Database[F],
      steps: List[Migration]
  ): Either[String, Migrations[F]] =
    Either.cond(
      steps.map(_.version) == (1 to steps.size).toList,
      new Migrations(database, steps),
      "migrations must be numbered contiguously from one"
    )
}
