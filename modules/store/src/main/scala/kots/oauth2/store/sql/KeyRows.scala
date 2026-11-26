package kots.oauth2.store.sql

import cats.syntax.all._

import kots.data.Decoder
import kots.oauth2.core.KeyId
import kots.oauth2.core.ParseFailure
import kots.oauth2.jose.Alg
import kots.oauth2.jose.Jwk
import kots.oauth2.jose.Kty

private[sql] object KeyRows {

  val Row: Decoder[(String, String, String)] = (Decoder[String], Decoder[String], Decoder[String]).tupled

  def encode(key: Jwk): String = DetailRows.encodeFields(key.parameters)

  def parsed(row: (String, String, String)): Either[ParseFailure, Jwk] =
    row match {
      case (kid, alg, joined) =>
        val params = DetailRows.decodeFields(joined)
        def param(name: String): Either[ParseFailure, String] =
          params.get(name).toRight(ParseFailure("Jwk", s"no $name parameter"))
        for {
          identifier <- KeyId.from(kid)
          algorithm <- Alg.from(alg)
          key <- algorithm.kty match {
            case Kty.Rsa =>
              (param("n"), param("e")).tupled.flatMap { case (n, e) => Jwk.rsa(identifier, algorithm, n, e) }
            case Kty.Ec =>
              (param("crv"), param("x"), param("y")).tupled.flatMap { case (crv, x, y) =>
                Jwk.ec(identifier, algorithm, crv, x, y)
              }
            case Kty.Okp =>
              (param("crv"), param("x")).tupled.flatMap { case (crv, x) =>
                Jwk.okp(identifier, algorithm, crv, x)
              }
          }
        } yield key
    }
}
