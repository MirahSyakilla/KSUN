import com.android.build.api.dsl.ApplicationDefaultConfig
import com.android.build.api.dsl.CommonExtension
import com.android.build.gradle.api.AndroidBasePlugin
import java.io.ByteArrayOutputStream
import java.io.File

plugins {
    alias(libs.plugins.agp.app) apply false
    alias(libs.plugins.agp.lib) apply false
    alias(libs.plugins.kotlin) apply false
    alias(libs.plugins.compose.compiler) apply false
    alias(libs.plugins.lsplugin.cmaker)
}

cmaker {
    default {
        arguments.addAll(
            arrayOf(
                "-DANDROID_STL=none",
            )
        )
        abiFilters("arm64-v8a", "x86_64")
    }
    buildTypes {
        if (it.name == "release") {
            arguments += "-DDEBUG_SYMBOLS_PATH=${layout.buildDirectory.asFile.get().absolutePath}/symbols"
        }
    }
}

val androidMinSdkVersion = 26
val androidTargetSdkVersion = 36
val androidCompileSdkVersion = 36
val androidBuildToolsVersion = "36.1.0"
val androidCompileNdkVersion by extra(libs.versions.ndk.get())
val androidSourceCompatibility = JavaVersion.VERSION_21
val androidTargetCompatibility = JavaVersion.VERSION_21
fun parseVersionFile(file: File): Pair<Int, String>? {
    if (!file.isFile) return null
    val lines = file.readLines().map(String::trim)
    if (lines.none { '=' in it } && lines.size >= 2) {
        return lines[0].toIntOrNull()?.let { it to lines[1] }
    }
    val values = lines.mapNotNull { line ->
        line.split('=', limit = 2).takeIf { it.size == 2 }?.let { it[0] to it[1].trim() }
    }.toMap()
    val code = values["KSU_VERSION_CODE"]?.toIntOrNull() ?: return null
    val tag = values["KSU_VERSION_TAG"]?.takeIf { it.isNotEmpty() } ?: return null
    return code to tag
}

fun runGit(vararg args: String): String? {
    return runCatching {
        val process = ProcessBuilder(listOf("git") + args.toList())
            .directory(rootProject.projectDir)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().use { it.readText().trim() }
        if (process.waitFor() == 0 && output.isNotEmpty()) output else null
    }.getOrNull()
}

fun getVersion(): Pair<Int, String> {
    val overrideCode = System.getenv("KSU_VERSION_OVERRIDE")
    val overrideTag = System.getenv("KSU_VERSION_TAG_OVERRIDE")
    if (!overrideCode.isNullOrBlank() && !overrideTag.isNullOrBlank()) {
        overrideCode.toIntOrNull()?.let { return it to overrideTag }
    }
    val projectRoot = rootProject.projectDir.parentFile.canonicalFile
    val gitRoot = runGit("rev-parse", "--show-toplevel")?.let { File(it).canonicalFile }
    val count = gitRoot
        ?.takeIf { it == projectRoot }
        ?.let { runGit("rev-list", "--count", "HEAD")?.toIntOrNull() }
    val describe = gitRoot?.takeIf { it == projectRoot }?.let {
        runGit("describe", "--tags", "--always")
    }
    if (count != null && describe != null) return (30000 + count) to describe
    parseVersionFile(rootProject.file("kernel/VERSION"))?.let { return it }
    parseVersionFile(rootProject.file("kernel/.ksu_git_version"))?.let { return (30000 + it.first) to it.second }
    logger.warn("KernelSU-Next version metadata unavailable, using unknown build marker")
    return 1 to "v0.0.0"
}

val managerVersion by extra(getVersion())
val managerVersionCode by extra(managerVersion.first)
val managerVersionName by extra(managerVersion.second)

subprojects {
    plugins.withType(AndroidBasePlugin::class.java) {
        extensions.configure(CommonExtension::class.java) {
            compileSdk = androidCompileSdkVersion
            ndkVersion = androidCompileNdkVersion

            defaultConfig {
                minSdk = androidMinSdkVersion
                if (this is ApplicationDefaultConfig) {
                    targetSdk = androidTargetSdkVersion
                    versionCode = managerVersionCode
                    versionName = managerVersionName
                }
                ndk {
                    abiFilters += listOf("arm64-v8a", "x86_64")
                }
            }

            lint {
                abortOnError = true
                checkReleaseBuilds = false
            }

            compileOptions {
                sourceCompatibility = androidSourceCompatibility
                targetCompatibility = androidTargetCompatibility
            }
        }
    }
}
