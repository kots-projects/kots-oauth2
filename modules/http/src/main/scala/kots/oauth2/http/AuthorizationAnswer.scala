package kots.oauth2.http

import kots.oauth2.core.ClientFault

/** Where the answer to an authorization request goes. */
sealed trait AuthorizationAnswer

object AuthorizationAnswer {

  final case class Redirected(redirect: AuthorizationRedirect) extends AuthorizationAnswer

  final case class SignInRequired(fallback: AuthorizationRedirect) extends AuthorizationAnswer

  final case class Refused(fault: ClientFault) extends AuthorizationAnswer
}
