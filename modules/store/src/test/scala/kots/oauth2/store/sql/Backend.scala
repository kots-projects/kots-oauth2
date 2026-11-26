package kots.oauth2.store.sql

import java.util.UUID

import scala.concurrent.duration._

import cats.effect.IO
import cats.effect.Resource
import kots.data.Database
import kots.data.DatabaseName
import kots.data.Endpoint
import kots.data.Fragment
import kots.data.Login
import kots.data.PoolSettings
import kots.data.Secret
import kots.data.User
import kots.data.jdbc.Jdbc
import kots.data.net.NetConnector
import kots.data.pg.Pg
import kots.data.pg.PgSettings
import kots.data.pg.Security
import org.h2.jdbcx.JdbcDataSource

/** A database a relational suite runs on: empty at each acquisition. */
trait Backend {

  def database: Resource[IO, Database[IO]]
}

object Backend {

  /** The embedded database, through the adapter over a data source. */
  val embedded: Backend = new Backend {
    def database: Resource[IO, Database[IO]] =
      Resource.eval(IO {
        val source = new JdbcDataSource()
        source.setURL(s"jdbc:h2:mem:store-${UUID.randomUUID()};DB_CLOSE_DELAY=-1")
        Jdbc.database[IO](source)
      })
  }

  /** The live server, natively: a database of its own, dropped on release. */
  val postgres: Backend = new Backend {
    def database: Resource[IO, Database[IO]] = Postgres.created.flatMap(Postgres.pooled)
  }

  object Postgres {

    val host: String = sys.env.getOrElse("OAUTH2_PG_HOST", "127.0.0.1")

    val port: Int = sys.env.get("OAUTH2_PG_PORT").fold(55433)(_.toInt)

    val user: String = "postgres"

    val password: String = sys.env.getOrElse("OAUTH2_PG_PASSWORD", "oauth2")

    private val connector = NetConnector[IO](10.seconds)

    private def settings(name: String): PgSettings =
      (for {
        endpoint <- Endpoint.parse(host, port)
        account <- User.parse(user)
        database <- DatabaseName.parse(name)
        login <- Login(endpoint, account, database, Secret(password))
      } yield PgSettings(login, Security.Plaintext)).fold(sys.error, identity)

    def database(name: String): Database[IO] = Pg.database(connector, settings(name))

    def pooled(name: String): Resource[IO, Database[IO]] =
      Pg.pooled(connector, settings(name), PoolSettings(4).fold(sys.error, identity))

    /** The name of a database created for one acquisition. */
    val created: Resource[IO, String] = {
      val server = database("postgres")
      def run(text: String): IO[Unit] = server.session.use(_.execute(Fragment.sql(text))).void
      Resource.make(
        IO(s"oauth2_${UUID.randomUUID().toString.replace("-", "")}").flatTap(name =>
          run(s"CREATE DATABASE $name")
        )
      )(name => run(s"DROP DATABASE $name"))
    }
  }
}
