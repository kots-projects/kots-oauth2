package kots.oauth2.http

import kots.oauth2.core.OAuth2Error

/** Where the answer to an authorization request goes. */
sealed trait AuthorizationAnswer

object AuthorizationAnswer {

  final case class Redirected(redirect: AuthorizationRedirect) extends AuthorizationAnswer

  final case class SignInRequired(fallback: AuthorizationRedirect) extends AuthorizationAnswer

  final case class Refused(error: OAuth2Error) extends AuthorizationAnswer
}
