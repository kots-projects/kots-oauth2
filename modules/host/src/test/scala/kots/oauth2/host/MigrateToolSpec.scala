package kots.oauth2.host

import cats.effect.ExitCode
import cats.effect.IO
import kots.oauth2.store.sql.Backend.Postgres
import munit.CatsEffectSuite

class MigrateToolSpec extends CatsEffectSuite {

  private val databases = ResourceFunFixture(Postgres.created)

  private def tool(command: String, database: String, protection: String*): IO[ExitCode] =
    MigrateTool.invoked(
      List(command, Postgres.host, Postgres.port.toString, database, Postgres.user) ++ protection,
      Some(Postgres.password)
    )

  databases.test("a fresh database reports version zero with every migration pending") { database =>
    for {
      version <- tool("version", database, "plaintext")
      next <- tool("next", database, "plaintext")
    } yield {
      assertEquals(version, ExitCode.Success)
      assertEquals(next, ExitCode.Success)
    }
  }

  databases.test("applying migrates to the last version and verifies afterwards") { database =>
    for {
      applied <- tool("apply", database, "plaintext")
      verified <- tool("verify", database, "plaintext")
      next <- tool("next", database, "plaintext")
      again <- tool("apply", database, "plaintext")
    } yield {
      assertEquals(applied, ExitCode.Success)
      assertEquals(verified, ExitCode.Success)
      assertEquals(next, ExitCode.Success)
      assertEquals(again, ExitCode.Success)
    }
  }

  databases.test("a wrong invocation prints the usage and fails") { database =>
    for {
      bare <- MigrateTool.run(Nil)
      unknown <- tool("frobnicate", database, "plaintext")
      unprotected <- tool("version", database, "cleartext")
      portless <- MigrateTool.invoked(
        List("version", Postgres.host, "none", database, Postgres.user),
        Some(Postgres.password)
      )
    } yield {
      assertEquals(bare, ExitCode.Error)
      assertEquals(unknown, ExitCode.Error)
      assertEquals(unprotected, ExitCode.Error)
      assertEquals(portless, ExitCode.Error)
    }
  }

  databases.test("a session without the password, or one the server cannot protect, fails") { database =>
    for {
      secretless <- MigrateTool.invoked(
        List("version", Postgres.host, Postgres.port.toString, database, Postgres.user, "plaintext"),
        None
      )
      verified <- tool("version", database)
    } yield {
      assertEquals(secretless, ExitCode.Error)
      assertEquals(verified, ExitCode.Error)
    }
  }

  test("an unreachable database fails without raising") {
    MigrateTool
      .invoked(List("version", "127.0.0.1", "1", "nowhere", "nobody", "plaintext"), Some("none"))
      .map(assertEquals(_, ExitCode.Error))
  }
}
