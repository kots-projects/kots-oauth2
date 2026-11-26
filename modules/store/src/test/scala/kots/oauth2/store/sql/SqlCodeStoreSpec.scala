package kots.oauth2.store.sql

import java.time.Instant

import cats.effect.IO
import cats.effect.Ref
import cats.syntax.parallel._
import kots.oauth2.core.Action
import kots.oauth2.core.AuthorizationCode
import kots.oauth2.core.AuthorizationDetail
import kots.oauth2.core.AuthorizationDetailType
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.CodeChallenge
import kots.oauth2.core.CodeChallengeMethod
import kots.oauth2.core.GrantId
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Pkce
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.ResourceIndicator
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.store.CodeRecord
import munit.CatsEffectSuite

abstract class SqlCodeStoreSpec(backend: Backend) extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val code: AuthorizationCode = unsafe(AuthorizationCode.from("code-1"))

  private val grant: GrantId = unsafe(GrantId.from("grant-1"))

  private val record: CodeRecord = CodeRecord(
    code = code,
    clientId = unsafe(ClientId.from("client-1")),
    redirectUri = unsafe(RedirectUri.from("https://client.example/cb")),
    subject = unsafe(Subject.from("user-1")),
    scopes = unsafe(Scopes.parse("read")),
    details = AuthorizationDetails.of(
      List(
        AuthorizationDetail.of(
          unsafe(AuthorizationDetailType.from("payment")),
          actions = List(unsafe(Action.from("read"))),
          fields = Map("max_amount" -> "10 eur")
        )
      )
    ),
    pkce = Some(
      Pkce(
        unsafe(CodeChallenge.from("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")),
        CodeChallengeMethod.S256
      )
    ),
    expiresAt = Start.plusSeconds(60L),
    resource = Some(unsafe(ResourceIndicator.from("https://api.example")))
  )

  private val stores = ResourceFunFixture(
    backend.database.evalMap { database =>
      for {
        moment <- Ref.of[IO, Instant](Start)
        clock = new Clock[IO] { def instant: IO[Instant] = moment.get }
        store <- SqlCodeStore.create[IO](database, clock).toOption.get
      } yield (store, moment)
    }
  )

  stores.test("a code consumed by many at once is answered to one alone") { case (store, _) =>
    for {
      _ <- store.save(record)
      answers <- List.fill(8)(store.consume(code)).parSequence
    } yield assertEquals(answers.flatten, List(record))
  }

  stores.test("a saved code is consumed once with every field intact") { case (store, _) =>
    for {
      _ <- store.save(record)
      first <- store.consume(code)
      second <- store.consume(code)
    } yield {
      assertEquals(first, Some(record))
      assertEquals(second, None)
    }
  }

  stores.test("an expired code is not consumable") { case (store, moment) =>
    for {
      _ <- store.save(record)
      _ <- moment.set(Start.plusSeconds(60L))
      consumed <- store.consume(code)
    } yield assertEquals(consumed, None)
  }

  stores.test("a redeemed code remembers its grant and the last redeem wins") { case (store, _) =>
    for {
      _ <- store.redeem(code, grant)
      remembered <- store.redeemed(code)
      _ <- store.redeem(code, unsafe(GrantId.from("grant-2")))
      replaced <- store.redeemed(code)
      unknown <- store.redeemed(unsafe(AuthorizationCode.from("absent")))
    } yield {
      assertEquals(remembered, Some(grant))
      assertEquals(replaced.map(_.value), Some("grant-2"))
      assertEquals(unknown, None)
    }
  }

  stores.test("a sweep removes only the expired codes") { case (store, moment) =>
    for {
      _ <- store.save(record)
      _ <- store.save(
        record.copy(
          code = unsafe(AuthorizationCode.from("code-2")),
          expiresAt = Start.plusSeconds(600L),
          details = AuthorizationDetails.empty
        )
      )
      _ <- moment.set(Start.plusSeconds(60L))
      swept <- store.sweep
      kept <- store.consume(unsafe(AuthorizationCode.from("code-2")))
    } yield {
      assertEquals(swept, 1)
      assert(kept.isDefined)
    }
  }
}

class EmbeddedCodeStoreSpec extends SqlCodeStoreSpec(Backend.embedded)

class PostgresCodeStoreSpec extends SqlCodeStoreSpec(Backend.postgres)
