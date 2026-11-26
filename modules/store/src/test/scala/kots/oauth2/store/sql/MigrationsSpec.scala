package kots.oauth2.store.sql

import cats.effect.IO
import kots.data.Database
import munit.CatsEffectSuite

abstract class MigrationsSpec(backend: Backend) extends CatsEffectSuite {

  private val first: Migration = Migration(1, "CREATE TABLE one(id INT PRIMARY KEY)")

  private val second: Migration = Migration(2, "CREATE TABLE two(id INT PRIMARY KEY)")

  private def engine(database: Database[IO], steps: List[Migration]): Migrations[IO] =
    Migrations.of(database, steps).toOption.get

  test("migrations are refused unless numbered contiguously from one") {
    backend.database.use { database =>
      IO {
        assert(Migrations.of[IO](database, List(second)).isLeft)
        assert(Migrations.of[IO](database, List(first, first.copy(version = 3))).isLeft)
        assert(Migrations.of[IO](database, List(first, second)).isRight)
      }
    }
  }

  test("applying records each version once and reapplying is idempotent") {
    backend.database.use { database =>
      val migrations = engine(database, List(first, second))
      for {
        before <- migrations.version
        applied <- migrations.apply
        after <- migrations.version
        again <- migrations.apply
        waiting <- migrations.pending
      } yield {
        assertEquals(before, 0)
        assertEquals(applied, Right(2))
        assertEquals(after, 2)
        assertEquals(again, Right(2))
        assertEquals(waiting, Nil)
      }
    }
  }

  test("a changed script is detected by its recorded checksum") {
    backend.database.use { database =>
      for {
        _ <- engine(database, List(first)).apply
        verified <- engine(database, List(first.copy(script = "CREATE TABLE other(id INT)"))).verify
        intact <- engine(database, List(first, second)).verify
      } yield {
        assert(verified.isLeft)
        assertEquals(intact, Right(1))
      }
    }
  }

  test("a database ahead of the known scripts is refused") {
    backend.database.use { database =>
      for {
        _ <- engine(database, List(first, second)).apply
        verified <- engine(database, List(first)).verify
      } yield assert(verified.isLeft)
    }
  }

  test("a failing migration keeps the versions applied before it") {
    backend.database.use { database =>
      val broken = List(first, Migration(2, "CREATE BROKEN"))
      for {
        applied <- engine(database, broken).apply
        version <- engine(database, List(first)).version
        verified <- engine(database, List(first)).verify
      } yield {
        assert(applied.isLeft)
        assertEquals(version, 1)
        assertEquals(verified, Right(1))
      }
    }
  }

  test("the schema of the stores applies whole") {
    backend.database.use { database =>
      engine(database, Schema.migrations).apply.assertEquals(Right(Schema.migrations.size))
    }
  }
}

class EmbeddedMigrationsSpec extends MigrationsSpec(Backend.embedded)

class PostgresMigrationsSpec extends MigrationsSpec(Backend.postgres)
