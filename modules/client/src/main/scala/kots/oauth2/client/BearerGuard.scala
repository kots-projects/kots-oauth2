package kots.oauth2.client

import java.time.Duration

import cats.syntax.all._
import cats.Monad

import kots.oauth2.core.Acr
import kots.oauth2.core.Audience
import kots.oauth2.core.Clock
import kots.oauth2.core.Issuer
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.Scopes
import kots.oauth2.jose.Jwks
import kots.oauth2.jose.Jwt
import kots.oauth2.jose.JwtClaims

final class BearerGuard[F[_]: Monad](
    keys: F[Either[ParseFailure, Jwks]],
    issuer: Issuer,
    clock: Clock[F],
    audience: Option[Audience] = None,
    tokenTypes: Set[String] = Set(Jwt.AccessTokenType),
    skew: Duration = BearerGuard.DefaultSkew
) {

  def verify(
      authorization: Option[String],
      required: Scopes,
      acr: Option[Acr] = None
  ): F[Either[BearerGuard.Challenge, JwtClaims]] =
    BearerGuard.token(authorization) match {
      case Left(challenge) =>
        challenge.asLeft[JwtClaims].pure[F]
      case Right(token) =>
        keys.flatMap {
          case Left(_) =>
            BearerGuard.invalid("the signing keys are unavailable").asLeft[JwtClaims].pure[F]
          case Right(published) =>
            clock.instant.map { now =>
              Jwt.claims(token, published, now, tokenTypes, skew) match {
                case Left(failure)                            => Left(BearerGuard.invalid(failure.reason))
                case Right(claims) if claims.issuer != issuer =>
                  Left(BearerGuard.invalid("issued by another issuer"))
                case Right(claims) if audience.exists(demanded => !claims.audience.contains(demanded)) =>
                  Left(BearerGuard.invalid("meant for another audience"))
                case Right(claims) if !Scopes.isSubsetOf(required, claims.scopes) =>
                  Left(BearerGuard.insufficientScope)
                case Right(claims) if acr.exists(demanded => !claims.acr.contains(demanded)) =>
                  Left(BearerGuard.stepUp(acr.toList))
                case Right(claims) => Right(claims)
              }
            }
        }
    }
}

object BearerGuard {

  val DefaultSkew: Duration = Duration.ofSeconds(60L)

  val Scheme: String = "Bearer "

  val Realm: String = "oauth2"

  final case class Challenge(status: Int, header: String)

  /** The token of a bearer authorization, its scheme read regardless of case. */
  def token(authorization: Option[String]): Either[Challenge, String] =
    authorization.map(_.trim.split("\\s+").toList).getOrElse(Nil) match {
      case scheme :: token :: Nil if scheme.equalsIgnoreCase(Scheme.trim) => Right(token)
      case scheme :: _ :: _ if scheme.equalsIgnoreCase(Scheme.trim)       => Left(invalidRequest)
      case _                                                              => Left(missing)
    }

  val missing: Challenge = Challenge(401, s"""Bearer realm="$Realm"""")

  val invalidRequest: Challenge =
    refusal(400, "invalid_request", "the authorization holds more than a token")

  val invalidToken: Challenge = invalid("the token is not valid")

  val insufficientScope: Challenge = refusal(403, "insufficient_scope", "a required scope is not granted")

  /** An invalid token challenge that says why. */
  def invalid(description: String): Challenge = refusal(401, "invalid_token", description)

  def stepUp(demanded: List[Acr]): Challenge = {
    val refused = refusal(401, "insufficient_user_authentication", "a stronger authentication is required")
    refused.copy(header = refused.header + s""", acr_values="${demanded.map(_.value).mkString(" ")}"""")
  }

  private def refusal(status: Int, error: String, description: String): Challenge = {
    val said = description.map(c => if (c < 0x20 || c > 0x7e || c == '"' || c == '\\') ' ' else c)
    Challenge(status, s"""Bearer realm="$Realm", error="$error", error_description="$said"""")
  }
}
