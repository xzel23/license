@file:Suppress("UnstableApiUsage")

import org.gradle.internal.extensions.stdlib.toDefaultLowerCase

rootProject.name = "license"

fun versionCatalogVersion(alias: String): String {
    val catalog = file("gradle/libs.toml")
    val versions = catalog.readLines()
        .dropWhile { it.trim() != "[versions]" }
        .drop(1)
        .takeWhile { !it.trim().startsWith("[") }

    val versionDeclaration = Regex("""^\s*${Regex.escape(alias)}\s*=\s*"([^"]+)"\s*(?:#.*)?$""")
    return versions.firstNotNullOfOrNull { line ->
        versionDeclaration.matchEntire(line)?.groupValues?.get(1)
    } ?: throw GradleException("version '$alias' not found in ${catalog.path}")
}

val projectVersion = versionCatalogVersion("projectVersion")

gradle.projectsLoaded {
    rootProject.allprojects {
        version = projectVersion
    }
}

dependencyResolutionManagement {

    val isSnapshot = projectVersion.toDefaultLowerCase().contains("-snapshot")
    val isReleaseCandidate = !isSnapshot && projectVersion.toDefaultLowerCase().contains("-rc")

    versionCatalogs {
        create("libs") {
            from(files("gradle/libs.toml"))
        }
    }

    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {

        // Maven Central Repository
        mavenCentral()

        // Sonatype Releases
        maven {
            name = "central.sonatype.com-releases"
            url = java.net.URI("https://oss.sonatype.org/content/repositories/releases/")
            mavenContent {
                releasesOnly()
            }
        }

        // Apache releases
        maven {
            name = "apache-releases"
            url = java.net.URI("https://repository.apache.org/content/repositories/releases/")
            mavenContent {
                releasesOnly()
            }
        }

        if (isSnapshot) {
            println("snapshot version detected, adding Maven snapshot repositories")

            mavenLocal()

            // Sonatype Snapshots
            maven {
                name = "Central Portal Snapshots"
                url = java.net.URI("https://central.sonatype.com/repository/maven-snapshots/")
                mavenContent {
                    snapshotsOnly()
                }
            }

            // Apache snapshots
            maven {
                name = "apache-snapshots"
                url = java.net.URI("https://repository.apache.org/content/repositories/snapshots/")
                mavenContent {
                    snapshotsOnly()
                }
            }
        }

        if (isReleaseCandidate) {
            println("release candidate version detected, adding Maven staging repositories")

            // Apache staging
            maven {
                name = "apache-staging"
                url = java.net.URI("https://repository.apache.org/content/repositories/staging/")
                mavenContent {
                    releasesOnly()
                }
            }
        }
    }

}
