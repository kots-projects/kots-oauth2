package kots.oauth2.server

import java.time.Instant

import cats.effect.IO
import kots.oauth2.core.ClientAuthMethod
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.ClientSecretHash
import kots.oauth2.core.ClientFault
import kots.oauth2.core.Clock
import kots.oauth2.core.CodeChallenge
import kots.oauth2.core.Entropy
import kots.oauth2.core.LifetimePolicy
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import kots.oauth2.http.AuthorizationAnswer
import kots.oauth2.http.AuthorizationRedirect
import kots.oauth2.http.Form
import kots.oauth2.store.Client
import kots.oauth2.store.ConsentRecord
import kots.oauth2.store.memory.InMemoryClientStore
import kots.oauth2.store.memory.InMemoryCodeStore
import kots.oauth2.store.memory.InMemoryConsentStore
import munit.CatsEffectSuite

class AuthorizationEndpointSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val clientId: ClientId = unsafe(ClientId.from("client-1"))

  private val subject: Subject = unsafe(Subject.from("user-1"))

  private val session: SessionId = unsafe(SessionId.from("session-1"))

  private val presented: Option[String] = Some(session.value)

  private val issuer: kots.oauth2.core.Issuer = unsafe(kots.oauth2.core.Issuer.from("https://server.example"))

  private val callback: RedirectUri = unsafe(RedirectUri.from("https://client.example/cb"))

  private val other: RedirectUri = unsafe(RedirectUri.from("https://client.example/other"))

  private val challenge: CodeChallenge =
    unsafe(CodeChallenge.from("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))

  private val registered: Client = Client(
    clientId,
    Set(callback),
    unsafe(Scopes.parse("read")),
    ClientAuthMethod.ClientSecretBasic,
    Some(ClientSecretHash.of(unsafe(ClientSecret.from("s3cret"))))
  )

  private def params: Map[String, String] =
    Map(
      "response_type" -> "code",
      "client_id" -> clientId.value,
      "redirect_uri" -> callback.value,
      "scope" -> "read",
      "state" -> "xyz",
      "code_challenge" -> challenge.value,
      "code_challenge_method" -> "S256"
    )

  private def setup(
      consented: Boolean = true,
      authenticated: Boolean = true
  ): IO[AuthorizationEndpoint[IO]] = {
    val clock = new Clock[IO] {
      def instant: IO[Instant] = IO.pure(Start)
    }
    val entropy = new Entropy[IO] {
      def bytes(n: Int): IO[Array[Byte]] = IO.pure(Array.fill(n)(7.toByte))
    }
    for {
      codes <- InMemoryCodeStore.create[IO](clock)
      consents <- InMemoryConsentStore.create[IO]
      _ <-
        if (consented) consents.grant(ConsentRecord(clientId, subject, unsafe(Scopes.parse("read"))))
        else IO.unit
      login <- SessionLogin.create[IO]
      _ <- if (authenticated) login.login(session, subject) else IO.unit
      clients <- InMemoryClientStore.create[IO](List(registered))
    } yield new AuthorizationEndpoint[IO](
      clients,
      login,
      new AuthorizationService[IO](codes, consents, clock, entropy, LifetimePolicy.defaults),
      issuer
    )
  }

  private def query(redirect: AuthorizationRedirect): Map[String, String] =
    Form.parse(redirect.location.dropWhile(_ != '?').drop(1)).toOption.get

  private def location(answer: AuthorizationAnswer): AuthorizationRedirect =
    answer match {
      case AuthorizationAnswer.Redirected(redirect)     => redirect
      case AuthorizationAnswer.SignInRequired(fallback) => fallback
      case AuthorizationAnswer.Refused(reason)          => sys.error(reason.error.code)
    }

  private def fault(answer: AuthorizationAnswer): Option[ClientFault] =
    answer match {
      case AuthorizationAnswer.Refused(reason) => Some(reason)
      case _                                   => None
    }

  private def refusal(answer: AuthorizationAnswer): Option[String] =
    answer match {
      case AuthorizationAnswer.Refused(reason) => Some(reason.error.code)
      case _                                   => None
    }

  private def pushedSetup
      : IO[(AuthorizationEndpoint[IO], kots.oauth2.store.memory.InMemoryPushedRequestStore[IO])] = {
    val clock = new Clock[IO] {
      def instant: IO[Instant] = IO.pure(Start)
    }
    val entropy = new Entropy[IO] {
      def bytes(n: Int): IO[Array[Byte]] = IO.pure(Array.fill(n)(7.toByte))
    }
    for {
      codes <- InMemoryCodeStore.create[IO](clock)
      consents <- InMemoryConsentStore.create[IO]
      _ <- consents.grant(ConsentRecord(clientId, subject, unsafe(Scopes.parse("read"))))
      login <- SessionLogin.create[IO]
      _ <- login.login(session, subject)
      clients <- InMemoryClientStore.create[IO](List(registered))
      pushed <- kots.oauth2.store.memory.InMemoryPushedRequestStore.create[IO](clock)
    } yield (
      new AuthorizationEndpoint[IO](
        clients,
        login,
        new AuthorizationService[IO](codes, consents, clock, entropy, LifetimePolicy.defaults),
        issuer,
        Some(pushed)
      ),
      pushed
    )
  }

  private val pushedUri: kots.oauth2.core.RequestUri =
    unsafe(kots.oauth2.core.RequestUri.from(kots.oauth2.core.RequestUri.Prefix + "abc"))

  test("a pushed request uri resolves to its stored authorization request") {
    for {
      pair <- pushedSetup
      (endpoint, pushed) = pair
      _ <- pushed.save(
        kots.oauth2.store.PushedRequest(pushedUri, clientId, params, Start.plusSeconds(60L))
      )
      answered <- endpoint(presented, Map("client_id" -> clientId.value, "request_uri" -> pushedUri.value))
      replayed <- endpoint(presented, Map("client_id" -> clientId.value, "request_uri" -> pushedUri.value))
    } yield {
      val fields = query(location(answered))
      assert(fields("code").nonEmpty)
      assertEquals(fields.get("state"), Some("xyz"))
      assertEquals(refusal(replayed), Some("invalid_request"))
    }
  }

  test("a request uri combined with other parameters is refused") {
    for {
      pair <- pushedSetup
      (endpoint, _) = pair
      answered <- endpoint(
        presented,
        Map("client_id" -> clientId.value, "request_uri" -> pushedUri.value, "scope" -> "read")
      )
    } yield assertEquals(refusal(answered), Some("invalid_request"))
  }

  test("a request uri of another client is refused") {
    for {
      pair <- pushedSetup
      (endpoint, pushed) = pair
      _ <- pushed.save(
        kots.oauth2.store
          .PushedRequest(pushedUri, unsafe(ClientId.from("client-2")), params, Start.plusSeconds(60L))
      )
      answered <- endpoint(presented, Map("client_id" -> clientId.value, "request_uri" -> pushedUri.value))
    } yield assertEquals(refusal(answered), Some("invalid_request"))
  }

  test("an authorized request is redirected back with the code and the state") {
    for {
      endpoint <- setup()
      answered <- endpoint(presented, params)
    } yield {
      val redirect = location(answered)
      assert(redirect.location.startsWith(callback.value + "?"))
      assert(query(redirect)("code").nonEmpty)
      assertEquals(query(redirect).get("state"), Some("xyz"))
      assertEquals(query(redirect).get("iss"), Some(issuer.value))
      assertEquals(query(redirect).get("error"), None)
    }
  }

  test("an anonymous request is redirected back as access denied") {
    for {
      endpoint <- setup(authenticated = false)
      answered <- endpoint(presented, params)
    } yield {
      val fields = query(location(answered))
      assertEquals(fields.get("error"), Some("access_denied"))
      assertEquals(fields.get("state"), Some("xyz"))
      assertEquals(fields.get("iss"), Some(issuer.value))
      assertEquals(fields.get("code"), None)
    }
  }

  test("a request without a recorded consent is redirected back as access denied") {
    for {
      endpoint <- setup(consented = false)
      answered <- endpoint(presented, params)
    } yield assertEquals(query(location(answered)).get("error"), Some("access_denied"))
  }

  test("an unknown client is answered directly with an error") {
    for {
      endpoint <- setup()
      answered <- endpoint(presented, params.updated("client_id", "client-2"))
    } yield assertEquals(refusal(answered), Some("invalid_request"))
  }

  test("an unregistered redirect uri is never redirected to") {
    for {
      endpoint <- setup()
      answered <- endpoint(presented, params.updated("redirect_uri", other.value))
    } yield assertEquals(refusal(answered), Some("invalid_request"))
  }

  test("a missing code challenge is redirected back as an invalid request") {
    for {
      endpoint <- setup()
      answered <- endpoint(presented, params - "code_challenge" - "code_challenge_method")
    } yield {
      val fields = query(location(answered))
      assertEquals(fields.get("error"), Some("invalid_request"))
      assertEquals(fields.get("state"), Some("xyz"))
    }
  }

  test("the three destinations are told apart by the answer") {
    for {
      endpoint <- setup()
      granted <- endpoint(presented, params)
      anonymous <- setup(authenticated = false).flatMap(_(presented, params))
      unknown <- endpoint(presented, params.updated("client_id", "client-2"))
    } yield {
      assert(granted.isInstanceOf[AuthorizationAnswer.Redirected], granted.toString)
      assert(anonymous.isInstanceOf[AuthorizationAnswer.SignInRequired], anonymous.toString)
      assert(unknown.isInstanceOf[AuthorizationAnswer.Refused], unknown.toString)
    }
  }

  test("a refusal the client never sees names its reason and still reads the same") {
    for {
      endpoint <- setup()
      unknownClient <- endpoint(presented, params.updated("client_id", "client-2"))
      unregistered <- endpoint(presented, params.updated("redirect_uri", other.value))
    } yield {
      assertEquals(fault(unknownClient), Some(ClientFault.UnknownClient: ClientFault))
      assertEquals(fault(unregistered), Some(ClientFault.RedirectNotRegistered: ClientFault))
      assertEquals(
        fault(unknownClient).map(_.error.body),
        Some(Map("error" -> "invalid_request", "error_description" -> "client is not registered"))
      )
      assertEquals(
        fault(unregistered).map(_.error.body),
        Some(Map("error" -> "invalid_request", "error_description" -> "redirect_uri is not registered"))
      )
    }
  }

  test("a pushed request that is unknown or does not stand alone names which") {
    for {
      pair <- pushedSetup
      (endpoint, _) = pair
      unknown <- endpoint(presented, Map("client_id" -> clientId.value, "request_uri" -> pushedUri.value))
      crowded <- endpoint(
        presented,
        Map("client_id" -> clientId.value, "request_uri" -> pushedUri.value, "state" -> "xyz")
      )
    } yield {
      assertEquals(fault(unknown), Some(ClientFault.RequestUriUnknown: ClientFault))
      assertEquals(fault(crowded), Some(ClientFault.RequestUriNotAlone: ClientFault))
    }
  }
}
