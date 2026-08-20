package kots.oauth2.client

import java.time.Instant

import cats.effect.Concurrent
import cats.syntax.all._

import io.circe.HCursor
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.Clock
import kots.oauth2.core.EndpointUri
import kots.oauth2.core.Scopes
import kots.oauth2.core.Subject
import org.http4s.BasicCredentials
import org.http4s.Method
import org.http4s.Request
import org.http4s.Uri
import org.http4s.UrlForm
import org.http4s.client.Client
import org.http4s.headers.Authorization

/** Guards a resource with opaque tokens the server vouches for. */
final class IntrospectionGuard[F[_]: Concurrent](
    transport: Client[F],
    endpoint: EndpointUri,
    clientId: ClientId,
    secret: ClientSecret,
    clock: Clock[F]
) {

  def verify(
      authorization: Option[String],
      required: Scopes
  ): F[Either[BearerGuard.Challenge, IntrospectionGuard.Introspected]] =
    check(BearerGuard.token(authorization), required)

  /** Verifies the token sent in the authorization or in the form body. */
  def verifyRequest(
      authorization: Option[String],
      form: Map[String, String],
      required: Scopes
  ): F[Either[BearerGuard.Challenge, IntrospectionGuard.Introspected]] =
    check(BearerGuard.presented(authorization, form), required)

  private def check(
      presented: Either[BearerGuard.Challenge, String],
      required: Scopes
  ): F[Either[BearerGuard.Challenge, IntrospectionGuard.Introspected]] =
    presented.fold(
      _.asLeft[IntrospectionGuard.Introspected].pure[F],
      token =>
        (ask(token), clock.instant).mapN((answer, now) =>
          answer.flatMap(IntrospectionGuard.judge(_, required, now))
        )
    )

  private def ask(token: String): F[Either[BearerGuard.Challenge, Option[IntrospectionGuard.Introspected]]] =
    transport
      .run(
        Request[F](method = Method.POST, uri = Uri.unsafeFromString(endpoint.value))
          .withEntity(UrlForm("token" -> token, "token_type_hint" -> "access_token"))
          .putHeaders(Authorization(BasicCredentials(clientId.value, secret.value)))
      )
      .use(response =>
        response.bodyText.compile.string.map(text =>
          if (response.status.isSuccess) IntrospectionGuard.read(text)
          else Left(IntrospectionGuard.unanswered)
        )
      )
      .handleError(_ => Left(IntrospectionGuard.unanswered))
}

object IntrospectionGuard {

  /** What the authorization server said of an active token. */
  final case class Introspected(
      scopes: Scopes,
      clientId: Option[ClientId],
      subject: Option[Subject],
      expiresAt: Option[Instant]
  )

  val unanswered: BearerGuard.Challenge = BearerGuard.invalid("the token cannot be introspected")

  /** The introspection answer: the token's account, or none when inactive. */
  def read(text: String): Either[BearerGuard.Challenge, Option[Introspected]] =
    io.circe.parser
      .parse(text)
      .toOption
      .map(_.hcursor)
      .flatMap(cursor =>
        cursor.get[Boolean]("active").toOption.flatMap {
          case false => Some(None)
          case true  => account(cursor).map(Some(_))
        }
      )
      .toRight(unanswered)

  /** Whether an account, read at `now`, grants what the resource requires. */
  def judge(
      answer: Option[Introspected],
      required: Scopes,
      now: Instant
  ): Either[BearerGuard.Challenge, Introspected] =
    answer match {
      case None => Left(BearerGuard.invalid("the token is not active"))
      case Some(account) if account.expiresAt.exists(!now.isBefore(_)) => Left(BearerGuard.invalid("expired"))
      case Some(account) if !Scopes.isSubsetOf(required, account.scopes) =>
        Left(BearerGuard.insufficientScope)
      case Some(account) => Right(account)
    }

  private def account(cursor: HCursor): Option[Introspected] =
    (
      optional(cursor, "scope")(raw => Scopes.parse(raw).toOption).map(_.getOrElse(Scopes.empty)),
      optional(cursor, "client_id")(raw => ClientId.from(raw).toOption),
      optional(cursor, "sub")(raw => Subject.from(raw).toOption),
      cursor.get[Option[Long]]("exp").toOption.map(_.map(Instant.ofEpochSecond))
    ).mapN(Introspected.apply)

  private def optional[A](cursor: HCursor, name: String)(parse: String => Option[A]): Option[Option[A]] =
    cursor.get[Option[String]](name).toOption.flatMap(_.traverse(parse))
}
