import org.apache.tools.ant.taskdefs.condition.Os
import org.gradle.api.DefaultTask
import org.gradle.api.file.FileCollection
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecResult

class GoLib extends DefaultTask {

    @Input
    String baseName

    @Input
    String mainFile

    @InputFiles
    FileCollection sources

    @Internal
    File outputDir

    @OutputFile
    File outputLib

    @OutputFile
    File outputHeader

    void sources(Object... sources) {
        if (this.sources == null) {
            this.sources = project.files(sources)
        } else {
            this.sources += project.files(sources)
        }
    }

    void baseName(String baseName) {
        this.baseName = baseName

        String libName
        if (Os.isFamily(Os.FAMILY_WINDOWS)) {
            libName = "lib${baseName}.dll"
        } else if (Os.isFamily(Os.FAMILY_MAC)) {
            libName = "lib${baseName}.dylib"
        } else {
            libName = "lib${baseName}.so"
        }

        // Updated paths for outputs
        outputDir = project.layout.buildDirectory.dir("libs").get().asFile
        outputLib = new File(outputDir, libName)
        outputHeader = new File(outputDir, "lib${baseName}.h")
    }

    void mainFile(String mainFile) {
        this.mainFile = mainFile
    }

    @TaskAction
    void exec() {

        def cmd = [
            'go', 'build',
            '-o', outputLib,
            '-buildmode=c-shared',
            "${mainFile}"
        ]

        ExecResult execResult = project.exec {
            commandLine cmd
            environment("CGO_ENABLED", "1")
        }
        if (execResult.exitValue != 0) {
            println "\nGo build failed: '${cmd}'"
        }
        execResult.assertNormalExitValue()
    }

}
