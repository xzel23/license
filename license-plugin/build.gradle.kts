plugins {
    `java-gradle-plugin`
    `maven-publish`
    id("com.gradle.plugin-publish") version "1.2.1"
}

description = "License Gradle Plugin"

dependencies {
    implementation(rootProject.libs.log4j.api) {
        exclude("com.github.spotbugs", "spotbugs-annotations")
    }
    implementation(rootProject.libs.dua3.utility)
    runtimeOnly(rootProject.libs.bouncycastle.pkix)
    
    // Test dependencies
    testImplementation(gradleTestKit())
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.9.2")
    testImplementation("org.junit.jupiter:junit-jupiter-engine:5.9.2")
    testImplementation("org.mockito:mockito-core:5.3.1")
}
