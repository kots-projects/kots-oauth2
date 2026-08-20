package kots.oauth2.client

import java.time.Instant

import cats.effect.IO
import cats.effect.kernel.Ref
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.Clock
import kots.oauth2.core.EndpointUri
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Scopes
import munit.CatsEffectSuite
import org.http4s.Charset
import org.http4s.HttpApp
import org.http4s.Response
import org.http4s.Status
import org.http4s.UrlForm
import org.http4s.client.Client

class IntrospectionGuardSpec extends CatsEffectSuite {

  private val Start: Instant = Instant.parse("2025-01-01T00:00:00Z")

  private def unsafe[A](parsed: Either[ParseFailure, A]): A =
    parsed.fold(_ => sys.error("fixture"), identity)

  private val endpoint: EndpointUri = unsafe(EndpointUri.from("https://server.example/introspect"))

  private val clock: Clock[IO] = new Clock[IO] {
    def instant: IO[Instant] = IO.pure(Start)
  }

  private val active: String =
    s"""{"active":true,"scope":"read write","client_id":"client-1","sub":"user-1","exp":${Start
        .plusSeconds(60L)
        .getEpochSecond}}"""

  private type Seen = Ref[IO, Option[(Map[String, String], Option[String])]]

  private def transport(seen: Seen, answer: Response[IO]): Client[IO] =
    Client.fromHttpApp(HttpApp[IO] { request =>
      for {
        form <- request.as[UrlForm]
        fields = form.values.map { case (name, values) => name -> values.headOption.getOrElse("") }
        authorization = request.headers.headers.find(_.name.toString == "Authorization").map(_.value)
        _ <- seen.set(Some((fields, authorization)))
      } yield answer
    })

  private def answering(status: Status, body: String): Response[IO] =
    Response[IO](status).withEntity(body)(org.http4s.EntityEncoder.stringEncoder(Charset.`UTF-8`))

  private def guard(seen: Seen, status: Status, body: String): IntrospectionGuard[IO] =
    new IntrospectionGuard[IO](
      transport(seen, answering(status, body)),
      endpoint,
      unsafe(ClientId.from("resource-1")),
      unsafe(ClientSecret.from("s3cret")),
      clock
    )

  private def seen: IO[Seen] = Ref.of[IO, Option[(Map[String, String], Option[String])]](None)

  test("an active token is accepted with what the server said of it") {
    for {
      asked <- seen
      verified <- guard(asked, Status.Ok, active)
        .verify(Some("Bearer opaque-1"), unsafe(Scopes.parse("read")))
      request <- asked.get
    } yield {
      val introspected = verified.toOption.get
      assertEquals(introspected.scopes, unsafe(Scopes.parse("read write")))
      assertEquals(introspected.clientId.map(_.value), Some("client-1"))
      assertEquals(introspected.subject.map(_.value), Some("user-1"))
      assertEquals(introspected.expiresAt, Some(Start.plusSeconds(60L)))
      assertEquals(
        request.map(_._1),
        Some(Map("token" -> "opaque-1", "token_type_hint" -> "access_token"))
      )
      assert(request.flatMap(_._2).exists(_.startsWith("Basic ")))
    }
  }

  test("a token sent in a form body is introspected as one sent in the authorization") {
    for {
      asked <- seen
      verified <- guard(asked, Status.Ok, active)
        .verifyRequest(None, Map("access_token" -> "opaque-2"), Scopes.empty)
      request <- asked.get
    } yield {
      assert(verified.isRight)
      assertEquals(request.flatMap(_._1.get("token")), Some("opaque-2"))
    }
  }

  test("an inactive or lapsed token is challenged as invalid_token") {
    val lapsed = s"""{"active":true,"exp":${Start.minusSeconds(1L).getEpochSecond}}"""
    for {
      asked <- seen
      inactive <- guard(asked, Status.Ok, """{"active":false}""").verify(Some("Bearer t"), Scopes.empty)
      expired <- guard(asked, Status.Ok, lapsed).verify(Some("Bearer t"), Scopes.empty)
    } yield {
      assertEquals(inactive.left.toOption, Some(BearerGuard.invalid("the token is not active")))
      assertEquals(expired.left.toOption, Some(BearerGuard.invalid("expired")))
    }
  }

  test("a token without the required scope is challenged as insufficient_scope") {
    for {
      asked <- seen
      refused <- guard(asked, Status.Ok, active).verify(Some("Bearer t"), unsafe(Scopes.parse("admin")))
    } yield assertEquals(refused.left.toOption, Some(BearerGuard.insufficientScope))
  }

  test("a refusing or unreadable introspection answer is challenged as invalid_token") {
    for {
      asked <- seen
      refused <- guard(asked, Status.Unauthorized, """{"error":"invalid_client"}""")
        .verify(Some("Bearer t"), Scopes.empty)
      garbled <- guard(asked, Status.Ok, "not json").verify(Some("Bearer t"), Scopes.empty)
      flagless <- guard(asked, Status.Ok, """{"scope":"read"}""").verify(Some("Bearer t"), Scopes.empty)
    } yield {
      assertEquals(refused.left.toOption, Some(BearerGuard.invalid("the token cannot be introspected")))
      assertEquals(garbled.left.toOption, Some(BearerGuard.invalid("the token cannot be introspected")))
      assertEquals(flagless.left.toOption, Some(BearerGuard.invalid("the token cannot be introspected")))
    }
  }

  test("a missing or malformed authorization is challenged before the server is asked") {
    for {
      asked <- seen
      missing <- guard(asked, Status.Ok, active).verify(None, Scopes.empty)
      split <- guard(asked, Status.Ok, active).verify(Some("Bearer a b"), Scopes.empty)
      request <- asked.get
    } yield {
      assertEquals(missing.left.toOption, Some(BearerGuard.missing))
      assertEquals(split.left.toOption, Some(BearerGuard.invalidRequest))
      assertEquals(request, None)
    }
  }
}
