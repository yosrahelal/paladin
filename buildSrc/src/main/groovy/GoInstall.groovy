
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecResult

class GoInstall extends DefaultTask {

    @Input
    String tool

    @Input
    String toolVersion

    @TaskAction
    void exec() {
        List<String> cmd = ["go", "install", "${tool}@${toolVersion}"]
        ExecResult execResult = project.exec { commandLine cmd }
        if (execResult.exitValue != 0) {
            println "\nGo install failed: '${cmd}'"
        }
        execResult.assertNormalExitValue()
    }

}
