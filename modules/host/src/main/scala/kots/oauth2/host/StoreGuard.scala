package kots.oauth2.host

import cats.syntax.all._
import cats.Monad

import kots.oauth2.client.BearerGuard
import kots.oauth2.client.IntrospectionGuard
import kots.oauth2.core.AccessToken
import kots.oauth2.core.Audience
import kots.oauth2.core.Clock
import kots.oauth2.core.Scopes
import kots.oauth2.store.GrantStore
import kots.oauth2.store.TokenRecord
import kots.oauth2.store.TokenStore

/** Guards a resource in the server's own process, reading its token store. */
final class StoreGuard[F[_]: Monad](
    tokens: TokenStore[F],
    grants: GrantStore[F],
    clock: Clock[F],
    audience: Option[Audience] = None
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
      raw =>
        (held(raw), clock.instant).mapN((record, now) =>
          record match {
            case Some(found) if audience.exists(demanded => !found.audience.contains(demanded)) =>
              Left(BearerGuard.invalid("meant for another audience"))
            case found =>
              IntrospectionGuard.judge(found.map(StoreGuard.account), required, now)
          }
        )
    )

  private def held(raw: String): F[Option[TokenRecord]] =
    AccessToken
      .from(raw)
      .toOption
      .flatTraverse(tokens.findByAccess)
      .flatMap(_.flatTraverse(record => grants.find(record.grantId).map(_.filterNot(_.revoked).as(record))))
}

object StoreGuard {

  /** What the store holds of a token, as an introspection would say it. */
  def account(record: TokenRecord): IntrospectionGuard.Introspected =
    IntrospectionGuard.Introspected(
      record.scopes,
      Some(record.clientId),
      Some(record.subject),
      Some(record.accessExpiresAt)
    )
}
