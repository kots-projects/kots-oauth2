package kots.oauth2.core

/** A refusal the resource owner is shown and the client is never told. */
sealed trait ClientFault {
  def error: OAuth2Error
}

object ClientFault {

  case object UnknownClient extends ClientFault {
    def error: OAuth2Error = OAuth2Error.InvalidRequest(Some("client is not registered"))
  }

  case object RedirectNotRegistered extends ClientFault {
    def error: OAuth2Error = OAuth2Error.InvalidRequest(Some("redirect_uri is not registered"))
  }

  case object RedirectMissing extends ClientFault {
    def error: OAuth2Error = OAuth2Error.InvalidRequest(Some("redirect_uri is required"))
  }

  case object RequestUriUnknown extends ClientFault {
    def error: OAuth2Error = OAuth2Error.InvalidRequest(Some("unknown request_uri"))
  }

  case object RequestUriNotAlone extends ClientFault {
    def error: OAuth2Error = OAuth2Error.InvalidRequest(Some("request_uri stands alone"))
  }

  case object RequestUriMalformed extends ClientFault {
    def error: OAuth2Error = OAuth2Error.InvalidRequest(Some("not a request_uri"))
  }

  case object RequestUriUnsupported extends ClientFault {
    def error: OAuth2Error = OAuth2Error.InvalidRequest(Some("request_uri is not supported"))
  }

  final case class Malformed(error: OAuth2Error) extends ClientFault
}
