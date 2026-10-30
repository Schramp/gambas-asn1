plugins {
    java
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

val genDir = providers.gradleProperty("asn1cppJavaGenDir")
    .orElse(provider { throw GradleException("run through ctest, or pass -Pasn1cppJavaGenDir=<build>/tests/gen_java") })

sourceSets {
    test {
        java.srcDir(genDir)
    }
}

dependencies {
    testImplementation("io.github.schramp.gambasasn1:gambasasn1-wire")
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

tasks.test {
    useJUnitPlatform()
    systemProperty("vectors.dir", layout.projectDirectory.dir("../vectors").asFile.absolutePath)
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
