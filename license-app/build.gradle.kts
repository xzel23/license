description = "License Manager Swing Application"

dependencies {
    implementation(project(":"))
    implementation(rootProject.libs.dua3.utility)
    implementation(rootProject.libs.dua3.utility.swing)
    implementation(rootProject.libs.miglayout.swing)
    implementation(rootProject.libs.bouncycastle.provider)

    runtimeOnly(rootProject.libs.bouncycastle.pkix)
    runtimeOnly(rootProject.libs.log4j.core)
}
