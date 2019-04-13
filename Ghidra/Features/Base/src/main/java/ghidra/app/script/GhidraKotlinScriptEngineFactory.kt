package ghidra.app.script

import org.jetbrains.kotlin.cli.common.repl.KotlinJsr223JvmScriptEngineFactoryBase
import org.jetbrains.kotlin.cli.common.repl.ScriptArgsWithTypes
import org.jetbrains.kotlin.script.jsr223.KotlinJsr223JvmLocalScriptEngine
import org.jetbrains.kotlin.script.jsr223.KotlinStandardJsr223ScriptTemplate
import javax.script.Bindings
import javax.script.ScriptContext
import javax.script.ScriptEngine
import kotlin.script.experimental.jvm.util.scriptCompilationClasspathFromContextOrStdlib

class GhidraKotlinScriptEngineFactory: KotlinJsr223JvmScriptEngineFactoryBase() {
    override fun getScriptEngine(): ScriptEngine =
        KotlinJsr223JvmLocalScriptEngine(
                this,
                scriptCompilationClasspathFromContextOrStdlib("kotlin-script-util.jar", wholeClasspath = true),
                KotlinStandardJsr223ScriptTemplate::class.qualifiedName!!,
                { ctx, types -> ScriptArgsWithTypes(arrayOf(ctx.getBindings(ScriptContext.ENGINE_SCOPE)), types ?: emptyArray()) },
                arrayOf(Bindings::class)
        )
}
