package kots.oauth2.host

import cats.syntax.all._
import cats.Monad

import kots.oauth2.client.BearerGuard
import kots.oauth2.client.IntrospectionGuard
import kots.oauth2.core.AccessToken
import kots.oauth2.core.Audience
import kots.oauth2.core.CertificateThumbprint
import kots.oauth2.core.Clock
import kots.oauth2.core.Scopes
import kots.oauth2.server.DpopProofs
import kots.oauth2.store.GrantStore
import kots.oauth2.store.TokenRecord
import kots.oauth2.store.TokenStore

/** Guards a resource in the server's own process, reading its token store. */
final class StoreGuard[F[_]: Monad](
    tokens: TokenStore[F],
    grants: GrantStore[F],
    clock: Clock[F],
    audience: Option[Audience] = None,
    proofs: Option[DpopProofs[F]] = None
) {

  def verify(
      authorization: Option[String],
      required: Scopes
  ): F[Either[BearerGuard.Challenge, IntrospectionGuard.Introspected]] =
    check(BearerGuard.token(authorization).map(StoreGuard.Sent(_, proving = false)), None, required)

  /** Verifies the token sent in the authorization or in the form body. */
  def verifyRequest(
      authorization: Option[String],
      form: Map[String, String],
      required: Scopes
  ): F[Either[BearerGuard.Challenge, IntrospectionGuard.Introspected]] =
    check(BearerGuard.presented(authorization, form).map(StoreGuard.Sent(_, proving = false)), None, required)

  /** Verifies a token with the proof and the certificate it is bound to. */
  def verifyBound(
      authorization: Option[String],
      possession: StoreGuard.Possession,
      required: Scopes
  ): F[Either[BearerGuard.Challenge, IntrospectionGuard.Introspected]] =
    check(StoreGuard.sent(authorization), Some(possession), required)

  private def check(
      presented: Either[BearerGuard.Challenge, StoreGuard.Sent],
      possession: Option[StoreGuard.Possession],
      required: Scopes
  ): F[Either[BearerGuard.Challenge, IntrospectionGuard.Introspected]] =
    presented.fold(
      _.asLeft[IntrospectionGuard.Introspected].pure[F],
      sent =>
        (held(sent.token), clock.instant).tupled.flatMap {
          case (Some((_, found)), _) if audience.exists(demanded => !found.audience.contains(demanded)) =>
            BearerGuard.invalid("meant for another audience").asLeft[IntrospectionGuard.Introspected].pure[F]
          case (Some((token, found)), now) =>
            possessed(token, found, sent, possession).map(
              _.flatMap(_ => IntrospectionGuard.judge(Some(StoreGuard.account(found)), required, now))
            )
          case (None, now) =>
            IntrospectionGuard.judge(None, required, now).pure[F]
        }
    )

  private def held(raw: String): F[Option[(AccessToken, TokenRecord)]] =
    AccessToken
      .from(raw)
      .toOption
      .flatTraverse(token => tokens.findByAccess(token).map(_.tupleLeft(token)))
      .flatMap(_.flatTraverse(found => grants.find(found._2.grantId).map(_.filterNot(_.revoked).as(found))))

  private def possessed(
      token: AccessToken,
      record: TokenRecord,
      sent: StoreGuard.Sent,
      possession: Option[StoreGuard.Possession]
  ): F[Either[BearerGuard.Challenge, Unit]] = {
    val certified = Either.cond(
      record.x5t.forall(bound => possession.flatMap(_.certificate).contains(bound)),
      (),
      BearerGuard.invalid("the token is bound to another certificate")
    )
    (record.jkt, proofs.filter(_ => sent.proving), possession) match {
      case (None, _, _) if sent.proving =>
        BearerGuard.proof("invalid_token", "the token is not bound to a key").asLeft[Unit].pure[F]
      case (None, _, _) =>
        certified.pure[F]
      case (Some(bound), Some(validator), Some(StoreGuard.Possession(method, uri, Some(compact), _))) =>
        validator.validate(compact, method, uri, Some(token)).map {
          case Left(error) =>
            Left(BearerGuard.proof(error.code, error.description.getOrElse("the proof is refused")))
          case Right(proven) if proven != bound =>
            Left(BearerGuard.proof("invalid_token", "the token is bound to another key"))
          case Right(_) => certified
        }
      case (Some(_), Some(_), _) =>
        BearerGuard.proof("invalid_dpop_proof", "a proof of the key is required").asLeft[Unit].pure[F]
      case (Some(_), None, _) =>
        BearerGuard.proof("invalid_token", "the token is bound to a key").asLeft[Unit].pure[F]
    }
  }
}

object StoreGuard {

  /** What a request shows of the key and the certificate behind it. */
  final case class Possession(
      method: String,
      uri: String,
      proof: Option[String] = None,
      certificate: Option[CertificateThumbprint] = None
  )

  private final case class Sent(token: String, proving: Boolean)

  private def sent(authorization: Option[String]): Either[BearerGuard.Challenge, Sent] =
    authorization.map(_.trim.split("\\s+").toList).getOrElse(Nil) match {
      case scheme :: token :: Nil if scheme.equalsIgnoreCase(BearerGuard.ProofScheme.trim) =>
        Right(Sent(token, proving = true))
      case scheme :: _ :: _ if scheme.equalsIgnoreCase(BearerGuard.ProofScheme.trim) =>
        Left(BearerGuard.invalidRequest)
      case _ => BearerGuard.token(authorization).map(Sent(_, proving = false))
    }

  /** What the store holds of a token, as an introspection would say it. */
  def account(record: TokenRecord): IntrospectionGuard.Introspected =
    IntrospectionGuard.Introspected(
      record.scopes,
      Some(record.clientId),
      Some(record.subject),
      Some(record.accessExpiresAt)
    )
}
