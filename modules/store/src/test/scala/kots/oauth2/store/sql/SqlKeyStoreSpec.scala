package kots.oauth2.store.sql

import cats.effect.IO
import kots.oauth2.jose.Fakes
import munit.CatsEffectSuite

abstract class SqlKeyStoreSpec(backend: Backend) extends CatsEffectSuite {

  private val stores = ResourceFunFixture(
    backend.database.evalMap(database => SqlKeyStore.create[IO](database).toOption.get)
  )

  stores.test("keys publish in insertion order and rotation moves the current key") { store =>
    for {
      _ <- store.add(Fakes.rsa("key-1"))
      _ <- store.add(Fakes.ec("key-2"))
      _ <- store.retire(Fakes.rsa("key-1").kid)
      published <- store.jwks
      current <- store.current
      retiredFound <- store.find(Fakes.rsa("key-1").kid)
      _ <- store.retire(Fakes.ec("key-2").kid)
      exhausted <- store.current
    } yield {
      assertEquals(published.keys.map(_.kid.value), List("key-1", "key-2"))
      assertEquals(current.map(_.kid.value), Some("key-2"))
      assertEquals(retiredFound.map(_.kid.value), Some("key-1"))
      assertEquals(exhausted, None)
    }
  }

  stores.test("re-adding a known key identifier replaces it and revives it") { store =>
    for {
      _ <- store.add(Fakes.rsa("key-1"))
      _ <- store.retire(Fakes.rsa("key-1").kid)
      _ <- store.add(Fakes.rsa("key-1"))
      current <- store.current
      published <- store.jwks
    } yield {
      assertEquals(current.map(_.kid.value), Some("key-1"))
      assertEquals(published.keys.size, 1)
    }
  }
}

class EmbeddedKeyStoreSpec extends SqlKeyStoreSpec(Backend.embedded)

class PostgresKeyStoreSpec extends SqlKeyStoreSpec(Backend.postgres)
