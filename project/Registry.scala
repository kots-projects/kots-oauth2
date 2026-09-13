import sbt.*

/** Private package registry of the organisation. */
object Registry {

  private val host = "maven.pkg.github.com"
  private val owner = "kots-projects"

  def publishing(repository: String): MavenRepository =
    "registry" at s"https://$host/$owner/$repository"

  def resolver(repository: String): MavenRepository =
    "siblings" at s"https://$host/$owner/$repository"

  val credentials: Seq[Credentials] =
    sys.env.get("REGISTRY_TOKEN").toSeq.map(Credentials("GitHub Package Registry", host, "_", _))
}
