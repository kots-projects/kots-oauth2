package kots.oauth2.store.sql

import cats.effect.kernel.MonadCancelThrow
import cats.syntax.all._

import kots.data.Database
import kots.data.Decoder
import kots.data.Fragment
import kots.data.Session
import kots.oauth2.core.CertificateSubject
import kots.oauth2.core.CertificateThumbprint
import kots.oauth2.core.ClientAuthMethod
import kots.oauth2.core.ClientId
import kots.oauth2.core.ClientSecret
import kots.oauth2.core.ClientSecretHash
import kots.oauth2.core.GrantType
import kots.oauth2.core.ParseFailure
import kots.oauth2.core.RedirectUri
import kots.oauth2.core.RegistrationTokenHash
import kots.oauth2.core.Scopes
import kots.oauth2.core.Wire
import kots.oauth2.jose.Jwks
import kots.oauth2.store.Client
import kots.oauth2.store.ClientStore
import kots.oauth2.store.sql.Sql._

final class SqlClientStore[F[_]: MonadCancelThrow] private (database: Database[F]) extends ClientStore[F] {

  def find(id: ClientId): F[Option[Client]] = database.session.use { session =>
    session
      .query(sql"SELECT ${SqlClientStore.Columns} FROM clients WHERE client_id = ${param(id.value)}")(
        SqlClientStore.Row
      )
      .flatMap(_.headOption.traverse { row =>
        keysOf(session, row._1).flatMap(keys => required(SqlClientStore.client(row, keys)))
      })
  }

  def save(client: Client): F[Unit] = database.transaction.use { transaction =>
    remove(transaction, client.id) *>
      transaction.execute(
        sql"INSERT INTO clients(${SqlClientStore.Columns}) ${values(
            param(client.id.value),
            param(client.redirectUris.map(_.value).toList.sorted.mkString(" ")),
            param(Wire[Scopes].encode(client.scopes)),
            param(client.authMethod.value),
            param(client.secretHash.map(_.value)),
            param(client.registrationTokenHash.map(_.value)),
            param(client.secret.map(_.value)),
            param(client.certificateSubject.map(_.value)),
            param(client.certificateThumbprint.map(_.value)),
            param(client.grantTypes.map(_.value).toList.sorted.mkString(" "))
          )}"
      ) *>
      client.keys.keys.zipWithIndex.traverse_ { case (key, index) =>
        transaction.execute(
          sql"INSERT INTO client_keys(client_id, ord, kid, alg, params) ${values(
              param(client.id.value),
              param(index),
              param(key.kid.value),
              param(key.alg.value),
              param(KeyRows.encode(key))
            )}"
        )
      }
  }

  def delete(id: ClientId): F[Unit] = database.transaction.use(remove(_, id))

  private def remove(session: Session[F], id: ClientId): F[Unit] =
    session.execute(sql"DELETE FROM client_keys WHERE client_id = ${param(id.value)}") *>
      session.execute(sql"DELETE FROM clients WHERE client_id = ${param(id.value)}").void

  private def keysOf(session: Session[F], clientId: String): F[Jwks] =
    session
      .query(sql"SELECT kid, alg, params FROM client_keys WHERE client_id = ${param(clientId)} ORDER BY ord")(
        KeyRows.Row
      )
      .flatMap(rows => required(rows.traverse(KeyRows.parsed)))
      .map(Jwks(_))
}

object SqlClientStore {

  private val Columns: Fragment = Fragment.sql(
    "client_id, redirect_uris, scopes, auth_method, secret_hash, registration_token_hash, secret, " +
      "certificate_subject, certificate_thumbprint, grant_types"
  )

  private type Row = (
      String,
      String,
      String,
      String,
      Option[String],
      Option[String],
      Option[String],
      Option[String],
      Option[String],
      Option[String]
  )

  private val Row: Decoder[Row] = (
    Decoder[String],
    Decoder[String],
    Decoder[String],
    Decoder[String],
    Decoder[Option[String]],
    Decoder[Option[String]],
    Decoder[Option[String]],
    Decoder[Option[String]],
    Decoder[Option[String]],
    Decoder[Option[String]]
  ).tupled

  private def split(joined: String): List[String] = joined.split(' ').toList.filter(_.nonEmpty)

  private def client(row: Row, keys: Jwks): Either[ParseFailure, Client] =
    row match {
      case (
            id,
            redirectUris,
            scopes,
            authMethod,
            secretHash,
            tokenHash,
            secret,
            subject,
            thumbprint,
            grants
          ) =>
        for {
          clientId <- ClientId.from(id)
          redirects <- split(redirectUris).traverse(RedirectUri.from)
          granted <- Wire[Scopes].decode(scopes)
          method <- ClientAuthMethod.from(authMethod)
          hash <- secretHash.traverse(ClientSecretHash.fromStored)
          registration <- tokenHash.traverse(RegistrationTokenHash.fromStored)
          plain <- secret.traverse(ClientSecret.from)
          certificate <- subject.traverse(CertificateSubject.from)
          print <- thumbprint.traverse(CertificateThumbprint.from)
          allowed <- grants.traverse(raw => split(raw).traverse(GrantType.from))
        } yield Client(
          clientId,
          redirects.toSet,
          granted,
          method,
          hash,
          keys,
          registration,
          plain,
          certificate,
          print,
          allowed.fold(GrantType.all.toSet)(_.toSet)
        )
    }

  def create[F[_]: MonadCancelThrow](database: Database[F]): Either[String, F[SqlClientStore[F]]] =
    Schema.applied(database, new SqlClientStore(database))
}
