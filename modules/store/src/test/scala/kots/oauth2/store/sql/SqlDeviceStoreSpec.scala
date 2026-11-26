package kots.oauth2.store.sql

import java.time.Instant

import cats.effect.IO
import cats.effect.Ref
import cats.syntax.parallel._
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.DeviceCode
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.ResourceIndicator
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.core.UserCode
import kots.oauth2.store.DeviceRecord
import kots.oauth2.store.memory.InMemoryDeviceStore
import munit.CatsEffectSuite

abstract class SqlDeviceStoreSpec(backend: Backend) extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val device: DeviceCode = unsafe(DeviceCode.from("device-1"))

  private val user: UserCode = unsafe(UserCode.from("ABCD-EFGH"))

  private val subject: Subject = unsafe(Subject.from("user-1"))

  private val record: DeviceRecord = DeviceRecord(
    deviceCode = device,
    userCode = user,
    clientId = unsafe(ClientId.from("client-1")),
    scopes = unsafe(Scopes.parse("read")),
    expiresAt = Start.plusSeconds(1800L),
    subject = None,
    denied = false,
    lastPolledAt = None,
    resource = Some(unsafe(ResourceIndicator.from("https://api.example")))
  )

  private val stores = ResourceFunFixture(
    backend.database.evalMap { database =>
      for {
        moment <- Ref.of[IO, Instant](Start)
        clock = new Clock[IO] { def instant: IO[Instant] = moment.get }
        store <- SqlDeviceStore.create[IO](database, clock).toOption.get
      } yield (store, moment)
    }
  )

  stores.test("a device code consumed by many at once is answered to one alone") { case (store, _) =>
    for {
      _ <- store.save(record)
      answers <- List.fill(8)(store.consume(device)).parSequence
    } yield assertEquals(answers.flatten, List(record))
  }

  stores.test("a poll answers the record and remembers the polling moment") { case (store, moment) =>
    for {
      _ <- store.save(record)
      first <- store.poll(device)
      _ <- moment.set(Start.plusSeconds(1L))
      second <- store.poll(device)
      absent <- store.poll(unsafe(DeviceCode.from("absent")))
    } yield {
      assertEquals(first, Some(record))
      assertEquals(second.flatMap(_.lastPolledAt), Some(Start))
      assertEquals(absent, None)
    }
  }

  stores.test("an approval decides once and only while undecided and alive") { case (store, moment) =>
    for {
      _ <- store.save(record)
      approved <- store.approve(user, subject)
      again <- store.approve(user, subject)
      polled <- store.poll(device)
      _ <- moment.set(Start.plusSeconds(1800L))
      late <- store.approve(unsafe(UserCode.from("WXYZ-WXYZ")), subject)
    } yield {
      assertEquals(approved, true)
      assertEquals(again, false)
      assertEquals(polled.flatMap(_.subject), Some(subject))
      assertEquals(late, false)
    }
  }

  stores.test("a denial decides the code and an approval cannot follow") { case (store, _) =>
    for {
      _ <- store.save(record)
      denied <- store.deny(user)
      approved <- store.approve(user, subject)
      polled <- store.poll(device)
    } yield {
      assertEquals(denied, true)
      assertEquals(approved, false)
      assertEquals(polled.map(_.denied), Some(true))
    }
  }

  stores.test("a consume is single use and refuses an expired code") { case (store, moment) =>
    for {
      _ <- store.save(record)
      first <- store.consume(device)
      second <- store.consume(device)
      _ <- store.save(record)
      _ <- moment.set(Start.plusSeconds(1800L))
      expired <- store.consume(device)
    } yield {
      assertEquals(first, Some(record))
      assertEquals(second, None)
      assertEquals(expired, None)
    }
  }

  stores.test("a sweep removes only the expired records") { case (store, moment) =>
    for {
      _ <- store.save(record)
      _ <- store.save(
        record.copy(
          deviceCode = unsafe(DeviceCode.from("device-2")),
          userCode = unsafe(UserCode.from("IJKL-MNOP")),
          expiresAt = Start.plusSeconds(60L)
        )
      )
      _ <- moment.set(Start.plusSeconds(60L))
      swept <- store.sweep
      kept <- store.poll(device)
    } yield {
      assertEquals(swept, 1)
      assert(kept.isDefined)
    }
  }

  stores.test("an expired record beside a live one leaves both stores naming the live one") {
    case (store, moment) =>
      val expired = record.copy(
        deviceCode = unsafe(DeviceCode.from("device-0")),
        expiresAt = Start.plusSeconds(1L)
      )
      for {
        memory <- InMemoryDeviceStore.create[IO](new Clock[IO] { def instant: IO[Instant] = moment.get })
        _ <- store.save(expired)
        _ <- memory.save(expired)
        _ <- store.save(record)
        _ <- memory.save(record)
        _ <- moment.set(Start.plusSeconds(2L))
        relational <- store.pending(user)
        inMemory <- memory.pending(user)
      } yield {
        assertEquals(inMemory.map(_.deviceCode), Some(device))
        assertEquals(relational, inMemory)
      }
  }
}

class EmbeddedDeviceStoreSpec extends SqlDeviceStoreSpec(Backend.embedded)

class PostgresDeviceStoreSpec extends SqlDeviceStoreSpec(Backend.postgres)
