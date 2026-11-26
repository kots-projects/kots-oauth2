package kots.oauth2.store.sql

import java.time.Instant

import cats.effect.IO
import cats.effect.Ref
import cats.syntax.parallel._
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RequestUri
import kots.oauth2.store.PushedRequest
import munit.CatsEffectSuite

abstract class SqlPushedRequestStoreSpec(backend: Backend) extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val uri: RequestUri = unsafe(RequestUri.from("urn:ietf:params:oauth:request_uri:one"))

  private val record: PushedRequest = PushedRequest(
    uri,
    unsafe(ClientId.from("client-1")),
    Map("response_type" -> "code", "scope" -> "read write"),
    Start.plusSeconds(60L)
  )

  private val stores = ResourceFunFixture(
    backend.database.evalMap { database =>
      for {
        moment <- Ref.of[IO, Instant](Start)
        clock = new Clock[IO] { def instant: IO[Instant] = moment.get }
        store <- SqlPushedRequestStore.create[IO](database, clock).toOption.get
      } yield (store, moment)
    }
  )

  stores.test("a pushed request is consumed once and never after its lifetime") { case (store, moment) =>
    for {
      _ <- store.save(record)
      read <- store.peek(uri)
      unspent <- store.peek(uri)
      first <- store.consume(uri)
      second <- store.consume(uri)
      _ <- store.save(record)
      _ <- moment.set(Start.plusSeconds(60L))
      expired <- store.consume(uri)
      _ <- store.save(record)
      swept <- store.sweep
    } yield {
      assertEquals(read, Some(record))
      assertEquals(unspent, Some(record))
      assertEquals(first, Some(record))
      assertEquals(second, None)
      assertEquals(expired, None)
      assertEquals(swept, 1)
    }
  }

  stores.test("a pushed request consumed by many at once is answered to one alone") { case (store, _) =>
    for {
      _ <- store.save(record)
      answers <- List.fill(8)(store.consume(uri)).parSequence
    } yield assertEquals(answers.flatten, List(record))
  }
}

class EmbeddedPushedRequestStoreSpec extends SqlPushedRequestStoreSpec(Backend.embedded)

class PostgresPushedRequestStoreSpec extends SqlPushedRequestStoreSpec(Backend.postgres)
