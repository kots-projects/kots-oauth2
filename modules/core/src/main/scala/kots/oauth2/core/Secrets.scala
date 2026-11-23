package kots.oauth2.core

import java.nio.charset.StandardCharsets

import cats.syntax.either._

final case class ClientSecret private (value: String)

object ClientSecret {
  def from(raw: String): Either[ParseFailure, ClientSecret] =
    Text.printable("ClientSecret", raw).map(new ClientSecret(_))
}

final case class ClientSecretHash private (value: String)

object ClientSecretHash {

  def of(secret: ClientSecret): ClientSecretHash = new ClientSecretHash(Digests.sha256Hex(secret.value))

  def verify(hash: ClientSecretHash, secret: ClientSecret): Boolean =
    Digests.equal(hash.value, Digests.sha256Hex(secret.value))

  def fromStored(raw: String): Either[ParseFailure, ClientSecretHash] =
    Either.cond(
      TokenHashes.isSha256Hex(raw),
      new ClientSecretHash(raw),
      TokenHashes.malformed("ClientSecretHash")
    )
}

final case class ClientCredentials(id: ClientId, secret: ClientSecret)

object ClientCredentials {

  def fromBasic(header: String): Either[ParseFailure, ClientCredentials] =
    Either
      .catchNonFatal(java.util.Base64.getDecoder.decode(header.trim))
      .leftMap(_ => ParseFailure("ClientCredentials", "not base64"))
      .flatMap { raw =>
        val text = new String(raw, StandardCharsets.UTF_8)
        val colon = text.indexOf(':')
        if (colon < 0) Left(ParseFailure("ClientCredentials", "no separator"))
        else
          for {
            idText <- decode(text.substring(0, colon))
            secretText <- decode(text.substring(colon + 1))
            id <- ClientId.from(idText)
            secret <- ClientSecret.from(secretText)
          } yield ClientCredentials(id, secret)
      }

  private def decode(part: String): Either[ParseFailure, String] =
    Either
      .catchNonFatal(java.net.URLDecoder.decode(part, StandardCharsets.UTF_8))
      .leftMap(_ => ParseFailure("ClientCredentials", "not url encoded"))
}

final case class RegistrationToken private (value: String)

object RegistrationToken {
  def from(raw: String): Either[ParseFailure, RegistrationToken] =
    Text.printable("RegistrationToken", raw).map(new RegistrationToken(_))
}

final case class RegistrationTokenHash private (value: String)

object RegistrationTokenHash {

  def of(token: RegistrationToken): RegistrationTokenHash =
    new RegistrationTokenHash(Digests.sha256Hex(token.value))

  def verify(hash: RegistrationTokenHash, token: RegistrationToken): Boolean =
    Digests.equal(hash.value, Digests.sha256Hex(token.value))

  def fromStored(raw: String): Either[ParseFailure, RegistrationTokenHash] =
    Either.cond(
      TokenHashes.isSha256Hex(raw),
      new RegistrationTokenHash(raw),
      TokenHashes.malformed("RegistrationTokenHash")
    )
}
