package kots.oauth2.host

import java.time.Instant

import cats.effect.IO
import kots.oauth2.client.BearerGuard
import kots.oauth2.core.AccessToken
import kots.oauth2.core.AccessTokenHash
import kots.oauth2.core.Audience
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.CertificateThumbprint
import kots.oauth2.core.ClientId
import kots.oauth2.core.Clock
import kots.oauth2.core.GrantId
import kots.oauth2.core.JwtId
import kots.oauth2.core.KeyThumbprint
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.jose.Dpop
import kots.oauth2.jose.Fakes
import kots.oauth2.server.DpopProofs
import kots.oauth2.store.Grant
import kots.oauth2.store.TokenRecord
import kots.oauth2.store.memory.InMemoryGrantStore
import kots.oauth2.store.memory.InMemoryReplayStore
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
      audience: Option[Audience] = None,
      jkt: Option[KeyThumbprint] = None,
      x5t: Option[CertificateThumbprint] = None
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
      audience = audience,
      jkt = jkt,
      x5t = x5t
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

  private val Orders: String = "https://api.example/orders"

  private val key: KeyThumbprint = unsafe(Dpop.thumbprint(Fakes.signingJwk))

  private val certificate: CertificateThumbprint =
    unsafe(CertificateThumbprint.from(Fakes.ClientCertificateThumbprint))

  private val keyBound: List[TokenRecord] = List(record("at-1", jkt = Some(key)))

  private val certificateBound: List[TokenRecord] = List(record("at-1", x5t = Some(certificate)))

  private def proof(
      token: String = "at-1",
      method: String = "GET",
      jti: String = "proof-1",
      nonce: Option[String] = None
  ): Option[String] =
    Dpop
      .prove(
        Fakes.signingKey.alg,
        Fakes.signingPair.getPrivate,
        Fakes.signingJwk,
        unsafe(JwtId.from(jti)),
        method,
        Orders,
        Start,
        nonce,
        Some(unsafe(AccessToken.from(token)))
      )
      .toOption

  private def proving(
      records: List[TokenRecord],
      nonce: Option[IO[String]] = None
  ): IO[StoreGuard[IO]] =
    for {
      tokens <- InMemoryTokenStore.create[IO](at(Start))
      _ <- records.foldLeft(IO.unit)((done, saved) => done >> tokens.save(saved))
      grants <- InMemoryGrantStore.create[IO]
      _ <- grants.save(Grant(grantId, clientId, subject, scopes, AuthorizationDetails.empty, revoked = false))
      replays <- InMemoryReplayStore.create[IO](at(Start))
    } yield new StoreGuard[IO](
      tokens,
      grants,
      at(Start),
      None,
      Some(new DpopProofs[IO](replays, at(Start), nonce))
    )

  private def presented(compact: Option[String]): StoreGuard.Possession =
    StoreGuard.Possession("GET", Orders, compact)

  private def refusal(verified: Either[BearerGuard.Challenge, Any]): Option[String] =
    verified.left.toOption.map(_.header)

  test("a key bound token is accepted with a proof of its key for the request and the token") {
    for {
      guarding <- proving(keyBound)
      verified <- guarding.verifyBound(Some("DPoP at-1"), presented(proof()), read)
      lower <- guarding.verifyBound(Some("dpop at-1"), presented(proof(jti = "proof-2")), read)
    } yield {
      assertEquals(verified.toOption.flatMap(_.subject), Some(subject))
      assert(lower.isRight)
    }
  }

  test("a key bound token sent as a bearer token is challenged as invalid_token") {
    val bound = BearerGuard.proof("invalid_token", "the token is bound to a key")
    for {
      guarding <- proving(keyBound)
      header <- guarding.verify(Some("Bearer at-1"), read)
      form <- guarding.verifyRequest(None, Map("access_token" -> "at-1"), read)
      proven <- guarding.verifyBound(Some("Bearer at-1"), presented(proof()), read)
      unable <- guard(records = keyBound)
      unproven <- unable.verifyBound(Some("DPoP at-1"), presented(proof(jti = "proof-2")), read)
    } yield {
      assertEquals(header.left.toOption, Some(bound))
      assertEquals(form.left.toOption, Some(bound))
      assertEquals(proven.left.toOption, Some(bound))
      assertEquals(unproven.left.toOption, Some(bound))
      assertEquals(bound.status, 401)
      assertEquals(
        bound.header,
        """DPoP realm="oauth2", error="invalid_token", error_description="the token is bound to a key", """ +
          """algs="ES256 EdDSA RS256""""
      )
    }
  }

  test("a key bound token without a proof for the request and the token is challenged") {
    for {
      guarding <- proving(keyBound)
      absent <- guarding.verifyBound(Some("DPoP at-1"), presented(None), read)
      garbled <- guarding.verifyBound(Some("DPoP at-1"), presented(Some("garbled")), read)
      method <- guarding.verifyBound(Some("DPoP at-1"), presented(proof(method = "POST")), read)
      token <- guarding.verifyBound(
        Some("DPoP at-1"),
        presented(proof(token = "at-2", jti = "proof-2")),
        read
      )
      first <- guarding.verifyBound(Some("DPoP at-1"), presented(proof(jti = "proof-3")), read)
      replayed <- guarding.verifyBound(Some("DPoP at-1"), presented(proof(jti = "proof-3")), read)
    } yield {
      assertEquals(absent.left.toOption.map(_.status), Some(401))
      assert(refusal(absent).exists(_.startsWith("""DPoP realm="oauth2", error="invalid_dpop_proof"""")))
      assert(refusal(garbled).exists(_.contains("""error="invalid_dpop_proof"""")))
      assert(refusal(method).exists(_.contains("""error="invalid_dpop_proof"""")))
      assert(refusal(token).exists(_.contains("""error="invalid_dpop_proof"""")))
      assert(first.isRight)
      assert(refusal(replayed).exists(_.contains("""error="invalid_dpop_proof"""")))
    }
  }

  test("a token bound to another key is challenged as invalid_token") {
    val other = record("at-1", jkt = Some(unsafe(KeyThumbprint.from("another-key"))))
    for {
      guarding <- proving(List(other))
      refused <- guarding.verifyBound(Some("DPoP at-1"), presented(proof()), read)
    } yield assertEquals(
      refused.left.toOption,
      Some(BearerGuard.proof("invalid_token", "the token is bound to another key"))
    )
  }

  test("a token bound to no key is refused under the proof scheme") {
    for {
      guarding <- proving(List(record("at-1")))
      refused <- guarding.verifyBound(Some("DPoP at-1"), presented(proof()), read)
      split <- guarding.verifyBound(Some("DPoP at-1 at-1"), presented(proof(jti = "proof-2")), read)
      bearer <- guarding.verifyBound(Some("Bearer at-1"), presented(None), read)
    } yield {
      assertEquals(
        refused.left.toOption,
        Some(BearerGuard.proof("invalid_token", "the token is not bound to a key"))
      )
      assertEquals(split.left.toOption, Some(BearerGuard.invalidRequest))
      assert(bearer.isRight)
    }
  }

  test("a demanded nonce is asked for under the proof scheme") {
    for {
      guarding <- proving(keyBound, nonce = Some(IO.pure("n-1")))
      asked <- guarding.verifyBound(Some("DPoP at-1"), presented(proof()), read)
      carried <- guarding.verifyBound(
        Some("DPoP at-1"),
        presented(proof(jti = "proof-2", nonce = Some("n-1"))),
        read
      )
    } yield {
      assert(refusal(asked).exists(_.startsWith("""DPoP realm="oauth2", error="use_dpop_nonce"""")))
      assert(carried.isRight)
    }
  }

  test("a certificate bound token is accepted only with its certificate") {
    val other = unsafe(CertificateThumbprint.from(Fakes.OtherCertificateThumbprint))
    val bound = BearerGuard.invalid("the token is bound to another certificate")
    def over(sent: Option[CertificateThumbprint]): StoreGuard.Possession =
      StoreGuard.Possession("GET", Orders, certificate = sent)
    for {
      guarding <- guard(records = certificateBound)
      held <- guarding.verifyBound(Some("Bearer at-1"), over(Some(certificate)), read)
      another <- guarding.verifyBound(Some("Bearer at-1"), over(Some(other)), read)
      none <- guarding.verifyBound(Some("Bearer at-1"), over(None), read)
      plain <- guarding.verify(Some("Bearer at-1"), read)
      form <- guarding.verifyRequest(None, Map("access_token" -> "at-1"), read)
    } yield {
      assert(held.isRight)
      assertEquals(another.left.toOption, Some(bound))
      assertEquals(none.left.toOption, Some(bound))
      assertEquals(plain.left.toOption, Some(bound))
      assertEquals(form.left.toOption, Some(bound))
      assertEquals(bound.status, 401)
    }
  }
}
