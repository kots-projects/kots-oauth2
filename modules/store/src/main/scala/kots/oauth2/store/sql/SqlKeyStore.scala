package kots.oauth2.store.sql

import cats.effect.kernel.MonadCancelThrow
import cats.syntax.all._

import kots.data.Database
import kots.data.Fragment
import kots.data.Session
import kots.oauth2.core.KeyId
import kots.oauth2.jose.Jwk
import kots.oauth2.jose.Jwks
import kots.oauth2.store.KeyStore
import kots.oauth2.store.sql.Sql._

final class SqlKeyStore[F[_]: MonadCancelThrow] private (database: Database[F]) extends KeyStore[F] {

  def jwks: F[Jwks] = database.session.use(rows(_, sql"ORDER BY seq")).map(Jwks(_))

  def current: F[Option[Jwk]] =
    database.session.use(rows(_, sql"WHERE retired = FALSE ORDER BY seq DESC LIMIT 1")).map(_.headOption)

  def find(kid: KeyId): F[Option[Jwk]] =
    database.session.use(rows(_, sql"WHERE kid = ${param(kid.value)}")).map(_.headOption)

  def add(key: Jwk): F[Unit] = database.transaction.use { transaction =>
    transaction.execute(sql"DELETE FROM server_keys WHERE kid = ${param(key.kid.value)}") *>
      transaction
        .execute(
          sql"INSERT INTO server_keys(kid, alg, params, retired) ${values(
              param(key.kid.value),
              param(key.alg.value),
              param(KeyRows.encode(key)),
              param(false)
            )}"
        )
        .void
  }

  def retire(kid: KeyId): F[Unit] = database.session.use { session =>
    session.execute(sql"UPDATE server_keys SET retired = TRUE WHERE kid = ${param(kid.value)}").void
  }

  private def rows(session: Session[F], suffix: Fragment): F[List[Jwk]] =
    session
      .query(sql"SELECT kid, alg, params FROM server_keys $suffix")(KeyRows.Row)
      .flatMap(found => required(found.traverse(KeyRows.parsed)))
}

object SqlKeyStore {

  def create[F[_]: MonadCancelThrow](database: Database[F]): Either[String, F[SqlKeyStore[F]]] =
    Schema.applied(database, new SqlKeyStore(database))
}
