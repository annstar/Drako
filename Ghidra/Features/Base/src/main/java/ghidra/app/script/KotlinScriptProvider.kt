package ghidra.app.script

import generic.io.NullPrintWriter
import generic.jar.ResourceFile
import java.io.*
import kotlin.reflect.KClass
import kotlin.reflect.full.createInstance

class KotlinScriptProvider: GhidraScriptProvider() {
    override fun getDescription(): String {
        return "Kotlin"
    }

    override fun getExtension(): String {
        return ".kts"
    }

    override fun createNewScript(newScript: ResourceFile?, category: String?) {
        val scriptName = newScript!!.name
        var className = scriptName
        val dotpos = scriptName.lastIndexOf('.')
        if (dotpos >= 0) {
            className = scriptName.substring(0, dotpos)
        }

        val writer = PrintWriter(FileWriter(newScript.getFile(false)))
        writeHeader(writer, category)

        for (pkg in Package.getPackages()) {
            if (pkg.name.startsWith("ghidra.program.model.")) {
                writer.println("import ${pkg.name}.*")
            }
        }

        writer.println("")
        writer.println("class $className: GhidraScript() {")
        writer.println("")
        writer.println("    override fun run() {")
        writeBody(writer)
        writer.println("    }")
        writer.println("")
        writer.println("}")
        writer.close()
    }

    override fun getCommentCharacter(): String {
        return "//"
    }

    override fun getScriptInstance(sourceFile: ResourceFile?, writer: PrintWriter?): GhidraScript? {
        val engine = GhidraKotlinScriptEngineFactory().scriptEngine
        val writer = writer ?: NullPrintWriter()
        val className = GhidraScriptUtil.getBaseName(sourceFile)
        val file = sourceFile!!.getFile(false)
        try {
            val clazz = engine.eval(file.readText() + "\n${className}::class")
            return (clazz as KClass<GhidraScript>).createInstance()
        } catch (e: Exception) {
            val exceptionWriter = StringWriter()
            e.printStackTrace(PrintWriter(exceptionWriter))
            writer.println(exceptionWriter.toString())
        }

        return null
    }
}
