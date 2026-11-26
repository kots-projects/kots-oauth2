package kots.oauth2.store.sql

import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

import cats.Applicative
import cats.MonadThrow
import cats.syntax.all._

import kots.data.Decoder
import kots.data.Fragment
import kots.data.Session

import kots.oauth2.core.Action
import kots.oauth2.core.AuthorizationDetail
import kots.oauth2.core.AuthorizationDetailType
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.Location
import kots.oauth2.core.ParseFailure
import kots.oauth2.store.sql.Sql._

private[sql] object DetailRows {

  private val Row: Decoder[(String, String, String, String)] =
    (Decoder[String], Decoder[String], Decoder[String], Decoder[String]).tupled

  def insert[F[_]: Applicative](
      session: Session[F],
      table: String,
      keyColumn: String,
      key: String,
      details: AuthorizationDetails
  ): F[Unit] = {
    val columns = Fragment.sql(s"$table($keyColumn, ord, detail_type, locations, actions, fields)")
    details.value.zipWithIndex.traverse_ { case (detail, index) =>
      session.execute(
        sql"INSERT INTO $columns ${values(
            param(key),
            param(index),
            param(detail.detailType.value),
            param(detail.locations.map(_.value).mkString(" ")),
            param(detail.actions.map(_.value).mkString(" ")),
            param(encodeFields(detail.fields))
          )}"
      )
    }
  }

  def read[F[_]: MonadThrow](
      session: Session[F],
      table: String,
      keyColumn: String,
      key: String
  ): F[AuthorizationDetails] = {
    val source = Fragment.sql(s"$table WHERE $keyColumn")
    session
      .query(sql"SELECT detail_type, locations, actions, fields FROM $source = ${param(key)} ORDER BY ord")(
        Row
      )
      .flatMap(rows => Sql.required[F, List[AuthorizationDetail]](rows.traverse(detail)))
      .map(AuthorizationDetails.of(_))
  }

  private def detail(row: (String, String, String, String)): Either[ParseFailure, AuthorizationDetail] =
    row match {
      case (detailType, locations, actions, fields) =>
        for {
          kind <- AuthorizationDetailType.from(detailType)
          places <- split(locations).traverse(Location.from)
          verbs <- split(actions).traverse(Action.from)
        } yield AuthorizationDetail.of(kind, places, verbs, decodeFields(fields))
    }

  private def split(joined: String): List[String] =
    joined.split(' ').toList.filter(_.nonEmpty)

  private[sql] def encodeFields(fields: Map[String, String]): String =
    fields.toList.sorted
      .map { case (name, value) =>
        URLEncoder.encode(name, StandardCharsets.UTF_8.name) + "=" +
          URLEncoder.encode(value, StandardCharsets.UTF_8.name)
      }
      .mkString("&")

  private[sql] def decodeFields(joined: String): Map[String, String] =
    joined
      .split('&')
      .toList
      .filter(_.nonEmpty)
      .map { pair =>
        pair.split('=') match {
          case Array(name, value) =>
            URLDecoder.decode(name, StandardCharsets.UTF_8.name) ->
              URLDecoder.decode(value, StandardCharsets.UTF_8.name)
          case _ => URLDecoder.decode(pair, StandardCharsets.UTF_8.name) -> ""
        }
      }
      .toMap
}
