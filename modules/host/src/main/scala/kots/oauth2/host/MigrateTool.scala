package kots.oauth2.host

import scala.concurrent.duration._

import cats.effect.ExitCode
import cats.effect.IO
import cats.effect.IOApp

import kots.data.Database
import kots.data.DatabaseName
import kots.data.Endpoint
import kots.data.Login
import kots.data.Secret
import kots.data.User
import kots.data.net.NetConnector
import kots.data.pg.Pg
import kots.data.pg.PgSettings
import kots.data.pg.Security
import kots.oauth2.store.sql.Migrations
import kots.oauth2.store.sql.Schema

object MigrateTool extends IOApp {

  val PasswordVariable: String = "OAUTH2_DATABASE_PASSWORD"

  val Usage: String =
    s"usage: version | next | apply | verify <host> <port> <database> <user> [plaintext]; password in $PasswordVariable"

  private val ConnectTimeout: FiniteDuration = 10.seconds

  def run(args: List[String]): IO[ExitCode] =
    IO(sys.env.get(PasswordVariable)).flatMap(invoked(args, _))

  private[host] def invoked(args: List[String], password: Option[String]): IO[ExitCode] =
    args match {
      case command :: host :: port :: database :: user :: protection =>
        settings(host, port, database, user, protection, password) match {
          case Left(reason)   => IO.println(s"$reason\n$Usage").as(ExitCode.Error)
          case Right(session) => attempted(command, Pg.database(NetConnector[IO](ConnectTimeout), session))
        }
      case _ => IO.println(Usage).as(ExitCode.Error)
    }

  private def settings(
      host: String,
      port: String,
      database: String,
      user: String,
      protection: List[String],
      password: Option[String]
  ): Either[String, PgSettings] =
    for {
      security <- protection match {
        case Nil                => Right(Security.Verified)
        case "plaintext" :: Nil => Right(Security.Plaintext)
        case _                  => Left("not a protection")
      }
      number <- port.toIntOption.toRight(s"not a port: $port")
      endpoint <- Endpoint.parse(host, number)
      account <- User.parse(user)
      name <- DatabaseName.parse(database)
      secret <- password.toRight(s"$PasswordVariable is not set")
      login <- Login(endpoint, account, name, Secret(secret))
    } yield PgSettings(login, security)

  private def attempted(command: String, database: Database[IO]): IO[ExitCode] =
    dispatch(command, database).handleErrorWith(failure =>
      IO.println(s"failed: ${failure.getMessage}").as(ExitCode.Error)
    )

  private def dispatch(command: String, database: Database[IO]): IO[ExitCode] =
    Migrations.of(database, Schema.migrations) match {
      case Left(reason)      => IO.println(reason).as(ExitCode.Error)
      case Right(migrations) =>
        command match {
          case "version" =>
            migrations.version.flatMap(version => IO.println(s"version: $version")).as(ExitCode.Success)
          case "next" =>
            migrations.pending
              .flatMap {
                case Nil   => IO.println("next: none")
                case steps => IO.println("next: " + steps.map(_.version).mkString(" "))
              }
              .as(ExitCode.Success)
          case "apply" =>
            migrations.apply.flatMap {
              case Right(version) => IO.println(s"applied: $version").as(ExitCode.Success)
              case Left(reason)   => IO.println(reason).as(ExitCode.Error)
            }
          case "verify" =>
            migrations.verify.flatMap {
              case Right(version) => IO.println(s"verified: $version").as(ExitCode.Success)
              case Left(reason)   => IO.println(reason).as(ExitCode.Error)
            }
          case _ => IO.println(Usage).as(ExitCode.Error)
        }
    }
}
