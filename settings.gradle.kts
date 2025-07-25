
@file:Suppress("UnstableApiUsage")

import org.gradle.internal.extensions.stdlib.toDefaultLowerCase

rootProject.name = "license"
val projectVersion = "0.1.0-beta3.1"

include("license-app")

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

dependencyResolutionManagement {

    val isSnapshot = projectVersion.toDefaultLowerCase().contains("-snapshot")
    val isReleaseCandidate = projectVersion.toDefaultLowerCase().contains("-rc")

    versionCatalogs {
        create("libs") {
            version("projectVersion", projectVersion)

            plugin("cabe", "com.dua3.cabe").version("3.3.0")
            plugin("forbiddenapis", "de.thetaphi.forbiddenapis").version("3.9")
            plugin("jreleaser", "org.jreleaser").version("1.19.0")
            plugin("sonar", "org.sonarqube").version("6.2.0.5505")
            plugin("spotbugs", "com.github.spotbugs").version("6.2.2")
            plugin("test-logger", "com.adarshr.test-logger").version("4.0.0")
            plugin("versions", "com.github.ben-manes.versions").version("0.52.0")

            version("dua3-utility", "20.0.0-beta4")
            version("jspecify", "1.0.0")
            version("log4j-bom", "2.25.1")
            version("spotbugs", "4.9.3")
            version("miglayout", "11.4.2")
            version("bouncycastle", "1.81")
            version("jackson", "2.19.2")

            library("dua3-utility-bom", "com.dua3.utility", "utility-bom").versionRef("dua3-utility")
            library("dua3-utility", "com.dua3.utility", "utility").withoutVersion()
            library("dua3-utility-logging", "com.dua3.utility", "utility-logging").withoutVersion()
            library("jspecify", "org.jspecify", "jspecify").versionRef("jspecify")
            library(
                "dua3-utility-logging-log4j",
                "com.dua3.utility",
                "utility-logging-log4j"
            ).withoutVersion()
            library("dua3-utility-swing", "com.dua3.utility", "utility-swing").withoutVersion()
            library("log4j-bom", "org.apache.logging.log4j", "log4j-bom").versionRef("log4j-bom")
            library("log4j-api", "org.apache.logging.log4j", "log4j-api").withoutVersion()
            library("log4j-core", "org.apache.logging.log4j", "log4j-core").withoutVersion()
            library("log4j-jul", "org.apache.logging.log4j", "log4j-jul").withoutVersion()

            library("miglayout-swing", "com.miglayout", "miglayout-swing").versionRef("miglayout")
            library("bouncycastle-provider", "org.bouncycastle", "bcprov-jdk18on").versionRef("bouncycastle")
            library("bouncycastle-pkix", "org.bouncycastle", "bcpkix-jdk18on").versionRef("bouncycastle")

            library("jackson-core", "com.fasterxml.jackson.core", "jackson-core").versionRef("jackson")
            library("jackson-databind", "com.fasterxml.jackson.core", "jackson-databind").versionRef("jackson")
            library("jackson-annotations", "com.fasterxml.jackson.core", "jackson-annotations").versionRef("jackson")
        }
    }

    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {

        // Maven Central Repository
        mavenCentral()

        // Sonatype Releases
        maven {
            name = "central.sonatype.com-releases"
            url = java.net.URI("https://central.sonatype.com/content/repositories/releases/")
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
