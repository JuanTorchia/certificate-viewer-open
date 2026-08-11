import org.jetbrains.intellij.platform.gradle.IntelliJPlatformType
import org.jetbrains.intellij.platform.gradle.TestFrameworkType
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("java")
    id("org.jetbrains.intellij.platform") version "2.18.1"
    id("org.jetbrains.kotlin.jvm") version "2.3.21"
}

group = "com.architect"
version = project.findProperty("pluginVersion")?.toString() ?: "1.0-SNAPSHOT"

sourceSets {
    create("integrationTest") {
        compileClasspath += sourceSets.main.get().output
        runtimeClasspath += sourceSets.main.get().output
    }
}

configurations.named("integrationTestImplementation") {
    extendsFrom(configurations.testImplementation.get())
}

repositories {
    mavenCentral()
    intellijPlatform {
        defaultRepositories()
    }
}

dependencies {
    intellijPlatform {
        intellijIdea("2026.1.3")
        testFramework(TestFrameworkType.Platform)
        testFramework(TestFrameworkType.Starter, configurationName = "integrationTestImplementation")
    }

    testImplementation("junit:junit:4.13.2")
    add("integrationTestImplementation", "org.junit.jupiter:junit-jupiter:6.1.3")
    add("integrationTestImplementation", "org.jetbrains.kotlin:kotlin-stdlib:2.4.0-RC2")
    add("integrationTestImplementation", "org.kodein.di:kodein-di-jvm:7.33.0")
    add("integrationTestImplementation", "org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.11.0")
    add("integrationTestRuntimeOnly", "org.junit.platform:junit-platform-launcher:6.1.3")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

tasks {
    withType<JavaCompile>().configureEach {
        sourceCompatibility = "21"
        targetCompatibility = "21"
    }

    withType<KotlinCompile>().configureEach {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
        }
    }
}

intellijPlatformTesting.testIdeUi.register("integrationTest") {
    task {
        val integrationTestSourceSet = sourceSets.getByName("integrationTest")
        testClassesDirs = integrationTestSourceSet.output.classesDirs
        classpath = integrationTestSourceSet.runtimeClasspath
        useJUnitPlatform()
    }
}

tasks.named("integrationTest") {
    doFirst {
        delete(layout.projectDirectory.dir("out/ide-tests/tests"))
    }
}

tasks.register("verifyIdePluginLogs") {
    group = "verification"
    description = "Fails when IntelliJ sandbox logs report errors blamed on this plugin."
    dependsOn("integrationTest")

    doLast {
        val ideTestLogs = layout.projectDirectory.dir("out/ide-tests/tests").asFile
        if (!ideTestLogs.exists()) {
            logger.lifecycle("No IntelliJ sandbox logs found under ${ideTestLogs.path}; skipping plugin log verification.")
            return@doLast
        }

        val pluginErrorPatterns = listOf(
            "Plugin to blame: CertView X.509",
            "Plugin to blame: X.509 Certificate Viewer",
            "[Plugin: com.architect.certviewer]",
            "SEVERE - #com.architect.certviewer",
        )
        val failures = ideTestLogs
            .walkTopDown()
            .filter { it.isFile && it.name == "idea.log" }
            .flatMap { logFile ->
                logFile.readLines()
                    .filter { line -> pluginErrorPatterns.any(line::contains) }
                    .map { line -> "${logFile.relativeTo(projectDir)}: $line" }
            }
            .toList()

        if (failures.isNotEmpty()) {
            throw GradleException(
                buildString {
                    appendLine("IntelliJ sandbox logs contain errors blamed on this plugin:")
                    failures.take(20).forEach { appendLine(it) }
                    if (failures.size > 20) {
                        appendLine("...and ${failures.size - 20} more plugin log error(s).")
                    }
                },
            )
        }
    }
}

tasks.register("validateFunctional") {
    group = "verification"
    description = "Runs parser tests, IntelliJ UI integration tests, IDE plugin log checks, and the plugin build."
    dependsOn("test", "verifyIdePluginLogs", "build")
}

intellijPlatform {
    buildSearchableOptions = false

    pluginConfiguration {
        ideaVersion {
            sinceBuild = "261"
            untilBuild = "261.*"
        }
    }

    pluginVerification {
        ides {
            create(IntelliJPlatformType.IntellijIdeaUltimate, "2026.1.4")
        }
    }

    signing {
        certificateChain = System.getenv("CERTIFICATE_CHAIN")
        privateKey = System.getenv("PRIVATE_KEY")
        password = System.getenv("PRIVATE_KEY_PASSWORD")
    }

    publishing {
        token = System.getenv("PUBLISH_TOKEN")
    }
}
