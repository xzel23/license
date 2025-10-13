description = "License Manager Swing Application"

plugins {
    alias(libs.plugins.javafx)
}

javafx {
    modules("javafx.controls")
}

dependencies {
    implementation(rootProject)

    implementation(rootProject.libs.dua3.utility.fx)
    implementation(rootProject.libs.dua3.utility.fx.controls)
    implementation(rootProject.libs.dua3.utility.swing)
    implementation(rootProject.libs.miglayout.swing)
    implementation(rootProject.libs.bouncycastle.provider)

    implementation(platform(rootProject.libs.jackson.bom))
    implementation(rootProject.libs.jackson.core)
    implementation(rootProject.libs.jackson.databind)
    implementation(rootProject.libs.jackson.annotations)

    runtimeOnly(rootProject.libs.bouncycastle.pkix)
    runtimeOnly(rootProject.libs.log4j.core)
}
