package kots.oauth2.jose

import kots.oauth2.core.AuthorizationDetail
import kots.oauth2.core.AuthorizationDetailType
import kots.oauth2.core.AuthorizationDetails
import kots.oauth2.core.ParseFailure
import munit.FunSuite

class DetailsSpec extends FunSuite {

  private def decode(raw: String): Either[ParseFailure, AuthorizationDetails] =
    Details.decode(raw)

  test("a detail with string fields decodes") {
    val decoded =
      decode("""[{"type":"account","locations":["https://api.example"],"actions":["read"],"id":"1"}]""")
    assertEquals(
      decoded.map(_.value),
      Right(
        List(
          AuthorizationDetail.of(
            AuthorizationDetailType.from("account").toOption.get,
            List(kots.oauth2.core.Location.from("https://api.example").toOption.get),
            List(kots.oauth2.core.Action.from("read").toOption.get),
            Map("id" -> "1")
          )
        )
      )
    )
  }

  test("a detail with a non-string field is refused") {
    assert(decode("""[{"type":"account","id":1}]""").isLeft)
    assert(decode("""[{"type":"account","id":{"value":"1"}}]""").isLeft)
  }

  test("a detail with malformed constraints is refused") {
    assert(decode("""[{"type":"account","locations":"https://api.example"}]""").isLeft)
    assert(decode("""[{"type":"account","locations":[1]}]""").isLeft)
    assert(decode("""[{"type":"account","actions":["read",2]}]""").isLeft)
  }

  test("one malformed entry refuses the whole document") {
    assert(decode("""[{"type":"account"},{"type":"payment","id":null}]""").isLeft)
  }
}
