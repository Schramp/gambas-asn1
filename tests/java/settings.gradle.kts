// Java legs of the codec tests: JUnit tests over compiler-generated Java,
// built against java-runtime/ as an included build. The generated sources
// come from ctest (-Pasn1cppJavaGenDir=...); see tests/CMakeLists.txt.
rootProject.name = "gambasasn1-java-legs"

includeBuild("../../java-runtime")

dependencyResolutionManagement {
    versionCatalogs {
        create("libs") {
            from(files("../../java-runtime/gradle/libs.versions.toml"))
        }
    }
}
