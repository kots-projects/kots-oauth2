package kots.oauth2.host

import java.time.Instant

import cats.effect.IO
import kots.oauth2.client.BearerGuard
import kots.oauth2.core.AccessToken
import kots.oauth2.core.AccessTokenHash
import kots.oauth2.core.Audience
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.GrantId
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.store.Grant
import kots.oauth2.store.TokenRecord
import kots.oauth2.store.memory.InMemoryGrantStore
import kots.oauth2.store.memory.InMemoryTokenStore
import munit.CatsEffectSuite

class StoreGuardSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val grantId: GrantId = unsafe(GrantId.from("grant-1"))

  private val subject: Subject = unsafe(Subject.from("user-1"))

  private val scopes: Scopes = unsafe(Scopes.parse("read write"))

  private val read: Scopes = unsafe(Scopes.parse("read"))

  private val orders: Audience = unsafe(Audience.from("https://orders.example"))

  private def at(now: Instant): Clock[IO] = new Clock[IO] {
    def instant: IO[Instant] = IO.pure(now)
  }

  private def record(
      access: String,
      identifier: GrantId = grantId,
      audience: Option[Audience] = None
  ): TokenRecord =
    TokenRecord(
      accessTokenHash = AccessTokenHash.of(unsafe(AccessToken.from(access))),
      refreshTokenHash = None,
      grantId = identifier,
      clientId = clientId,
      subject = subject,
      scopes = scopes,
      details = AuthorizationDetails.empty,
      issuedAt = Start,
      accessExpiresAt = Start.plusSeconds(60L),
      refreshExpiresAt = None,
      audience = audience
    )

  private def guard(
      records: List[TokenRecord] = List(record("at-1")),
      revoked: Boolean = false,
      now: Instant = Start,
      audience: Option[Audience] = None
  ): IO[StoreGuard[IO]] =
    for {
      tokens <- InMemoryTokenStore.create[IO](at(Start))
      _ <- records.foldLeft(IO.unit)((done, saved) => done >> tokens.save(saved))
      grants <- InMemoryGrantStore.create[IO]
      _ <- grants.save(Grant(grantId, clientId, subject, scopes, AuthorizationDetails.empty, revoked))
    } yield new StoreGuard[IO](tokens, grants, at(now), audience)

  test("a stored token is accepted with what the store holds of it") {
    for {
      guarding <- guard()
      verified <- guarding.verify(Some("Bearer at-1"), read)
    } yield {
      val account = verified.toOption.get
      assertEquals(account.scopes, scopes)
      assertEquals(account.clientId, Some(clientId))
      assertEquals(account.subject, Some(subject))
      assertEquals(account.expiresAt, Some(Start.plusSeconds(60L)))
    }
  }

  test("the bearer scheme is read regardless of case") {
    for {
      guarding <- guard()
      verified <- guarding.verify(Some("bearer at-1"), Scopes.empty)
    } yield assert(verified.isRight)
  }

  test("a token sent in a form body is accepted as one sent in the authorization") {
    for {
      guarding <- guard()
      verified <- guarding.verifyRequest(None, Map("access_token" -> "at-1"), read)
    } yield assert(verified.isRight)
  }

  test("a token sent both ways is challenged as invalid_request") {
    for {
      guarding <- guard()
      refused <- guarding.verifyRequest(Some("Bearer at-1"), Map("access_token" -> "at-1"), read)
    } yield assertEquals(refused.left.toOption.map(_.status), Some(400))
  }

  test("a token the store does not hold is challenged as invalid_token") {
    for {
      guarding <- guard()
      unknown <- guarding.verify(Some("Bearer at-2"), Scopes.empty)
      unreadable <- guarding.verifyRequest(None, Map("access_token" -> "tökén"), Scopes.empty)
    } yield {
      assertEquals(unknown.left.toOption, Some(BearerGuard.invalid("the token is not active")))
      assertEquals(unreadable.left.toOption, Some(BearerGuard.invalid("the token is not active")))
    }
  }

  test("a lapsed token is challenged as invalid_token") {
    for {
      guarding <- guard(now = Start.plusSeconds(60L))
      lapsed <- guarding.verify(Some("Bearer at-1"), Scopes.empty)
    } yield assertEquals(lapsed.left.toOption, Some(BearerGuard.invalid("expired")))
  }

  test("a token of a revoked or unknown grant is challenged as invalid_token") {
    val orphan = record("at-3", unsafe(GrantId.from("grant-2")))
    for {
      revoking <- guard(revoked = true)
      revoked <- revoking.verify(Some("Bearer at-1"), Scopes.empty)
      orphaned <- guard(records = List(orphan))
      unknown <- orphaned.verify(Some("Bearer at-3"), Scopes.empty)
    } yield {
      assertEquals(revoked.left.toOption, Some(BearerGuard.invalid("the token is not active")))
      assertEquals(unknown.left.toOption, Some(BearerGuard.invalid("the token is not active")))
    }
  }

  test("a token without the required scope is challenged as insufficient_scope") {
    for {
      guarding <- guard()
      refused <- guarding.verify(Some("Bearer at-1"), unsafe(Scopes.parse("admin")))
    } yield {
      assertEquals(refused.left.toOption, Some(BearerGuard.insufficientScope))
      assertEquals(refused.left.toOption.map(_.status), Some(403))
    }
  }

  test("a token meant for another audience is challenged as invalid_token") {
    val billing = unsafe(Audience.from("https://billing.example"))
    for {
      meant <- guard(records = List(record("at-1", audience = Some(orders))), audience = Some(orders))
      accepted <- meant.verify(Some("Bearer at-1"), read)
      other <- guard(records = List(record("at-1", audience = Some(billing))), audience = Some(orders))
      refused <- other.verify(Some("Bearer at-1"), read)
      unbound <- guard(audience = Some(orders))
      unnamed <- unbound.verify(Some("Bearer at-1"), read)
    } yield {
      assert(accepted.isRight)
      assertEquals(refused.left.toOption, Some(BearerGuard.invalid("meant for another audience")))
      assertEquals(unnamed.left.toOption, Some(BearerGuard.invalid("meant for another audience")))
    }
  }

  test("a missing or malformed authorization is challenged without a reason or as invalid_request") {
    for {
      guarding <- guard()
      missing <- guarding.verify(None, Scopes.empty)
      basic <- guarding.verify(Some("Basic at-1"), Scopes.empty)
      split <- guarding.verify(Some("Bearer at-1 at-1"), Scopes.empty)
    } yield {
      assertEquals(missing.left.toOption, Some(BearerGuard.missing))
      assertEquals(missing.left.toOption.map(_.header), Some("""Bearer realm="oauth2""""))
      assertEquals(basic.left.toOption, Some(BearerGuard.missing))
      assertEquals(split.left.toOption, Some(BearerGuard.invalidRequest))
    }
  }
}
