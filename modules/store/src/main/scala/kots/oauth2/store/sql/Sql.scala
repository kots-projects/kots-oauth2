package kots.oauth2.store.sql

import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.temporal.ChronoUnit

import cats.ApplicativeThrow
import cats.syntax.all._

import kots.data.Decoder
import kots.data.Encoder
import kots.data.Fragment
import kots.oauth2.core.ParseFailure

private[sql] object Sql {

  private val HalfMicrosecond = 500L

  /** Statement text with each interpolated fragment in its place. */
  implicit final class Interpolated(private val context: StringContext) extends AnyVal {
    def sql(fragments: Fragment*): Fragment =
      context.parts.toList
        .map(Fragment.sql)
        .zipAll(fragments.toList, Fragment.empty, Fragment.empty)
        .foldMap { case (text, fragment) => text |+| fragment }
  }

  /** The value as the parameters it is sent as. */
  def param[A](value: A)(implicit encoder: Encoder[A]): Fragment =
    encoder.encode(value).foldMap(Fragment.value)

  /** A VALUES clause of the fragments, in order. */
  def values(fragments: Fragment*): Fragment =
    Fragment.sql("VALUES(") |+| fragments.toList.intercalate(Fragment.sql(", ")) |+| Fragment.sql(")")

  /** A moment as the zoneless timestamp the columns hold. */
  def moment(instant: Instant): Fragment =
    param(
      LocalDateTime.ofInstant(
        instant.plusNanos(HalfMicrosecond).truncatedTo(ChronoUnit.MICROS),
        ZoneId.systemDefault()
      )
    )

  /** A moment, absent as NULL. */
  def moment(instant: Option[Instant]): Fragment = instant.fold(param(Option.empty[LocalDateTime]))(moment)

  /** Reads the zoneless timestamp of a column as a moment. */
  val instant: Decoder[Instant] =
    Decoder.decoderApplicative.map(Decoder[LocalDateTime])(_.atZone(ZoneId.systemDefault()).toInstant)

  /** The parsed value, or the failure of a row that cannot be one. */
  def required[F[_]: ApplicativeThrow, A](parsed: Either[ParseFailure, A]): F[A] =
    parsed.leftMap(failure => new IllegalStateException(failure.toString): Throwable).liftTo[F]
}
