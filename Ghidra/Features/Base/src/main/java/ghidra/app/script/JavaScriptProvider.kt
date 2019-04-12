/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.script

import java.io.*
import java.util.*

import javax.tools.*
import javax.tools.JavaFileObject.Kind

import generic.io.NullPrintWriter
import generic.jar.*
import ghidra.app.util.headless.HeadlessScript
import ghidra.util.Msg

open class JavaScriptProvider : GhidraScriptProvider() {

    private var loader = JavaScriptClassLoader()

    private val sourcePath: String
        get() {
            var classpath = System.getProperty("java.class.path")
            val dirs = GhidraScriptUtil.getScriptSourceDirectories()
            for (dir in dirs) {
                classpath += System.getProperty("path.separator") + dir.absolutePath
            }
            return classpath
        }

    private val classPath: String
        get() {
            var classpath = System.getProperty("java.class.path")
            val dirs = GhidraScriptUtil.getScriptBinDirectories()
            for (dir in dirs) {
                classpath += System.getProperty("path.separator") + dir.absolutePath
            }
            return classpath
        }

    override fun getDescription(): String {
        return "Java"
    }

    override fun getExtension(): String {
        return ".java"
    }

    override fun deleteScript(scriptSource: ResourceFile): Boolean {
        // Assuming script is in default java package, so using script's base name as class name.
        val clazzFile = getClassFile(scriptSource, GhidraScriptUtil.getBaseName(scriptSource))
        clazzFile.delete()
        return super.deleteScript(scriptSource)
    }

    @Throws(ClassNotFoundException::class, InstantiationException::class, IllegalAccessException::class)
    override fun getScriptInstance(sourceFile: ResourceFile, writer: PrintWriter?): GhidraScript? {
        var writer = writer

        if (writer == null) {
            writer = NullPrintWriter()
        }

        // Assuming script is in default java package, so using script's base name as class name.
        val clazzFile = getClassFile(sourceFile, GhidraScriptUtil.getBaseName(sourceFile))
        if (needsCompile(sourceFile, clazzFile)) {
            compile(sourceFile, writer) // may throw an exception
        } else if (scriptCompiledExternally(clazzFile)) {
            forceClassReload()
        }

        val clazzName = GhidraScriptUtil.getBaseName(sourceFile)

        var clazz: Class<*>? = null
        try {
            clazz = Class.forName(clazzName, true, loader)
        } catch (e: GhidraScriptUnsupportedClassVersionError) {
            // Unusual Code Alert!: This implies the script was compiled in a newer
            // version of Java.  So, just delete the class file and try again.
            val classFile = e.classFile
            classFile.delete()
            return getScriptInstance(sourceFile, writer)
        }

        val `object` = clazz!!.newInstance()
        if (`object` is GhidraScript) {
            `object`.setSourceFile(sourceFile)
            return `object`
        }

        val message = "Not a valid Ghidra script: " + sourceFile.name
        writer.println(message)
        Msg.error(this, message) // the writer may not be the same as Msg, so log it too
        return null // class is not a script
    }

    private fun forceClassReload() {
        loader = JavaScriptClassLoader() // this forces the script class to be reloaded
    }

    /**
     * Gets the class file corresponding to the given source file and class name.
     * If the class is in a package, the class name should include the full
     * package name.
     *
     * @param sourceFile The class's source file.
     * @param className The class's name (including package if applicable).
     * @return The class file corresponding to the given source file and class name.
     */
    protected fun getClassFile(sourceFile: ResourceFile, className: String): File {
        val resourceFile = GhidraScriptUtil.getClassFileByResourceFile(sourceFile, className)

        return resourceFile.getFile(false)
    }

    protected fun needsCompile(sourceFile: ResourceFile, classFile: File): Boolean {

        // Need to compile if there is no class file.
        if (!classFile.exists()) {
            return true
        }

        // Need to compile if the script's source file is newer than its corresponding class file.
        return if (sourceFile.lastModified() > classFile.lastModified()) {
            true
        } else !areAllParentClassesUpToDate(sourceFile)

        // Need to compile if parent classes are not up to date.
    }

    protected fun scriptCompiledExternally(classFile: File): Boolean {

        val modifiedTimeWhenLoaded = loader.lastModified(classFile)
                ?: // never been loaded, so doesn't matter
                return false

        return if (classFile.lastModified() > modifiedTimeWhenLoaded) {
            true
        } else false

    }

    private fun areAllParentClassesUpToDate(sourceFile: ResourceFile): Boolean {

        val parentClasses = getParentClasses(sourceFile)
                ?: // some class is missing!
                return false

        if (parentClasses.isEmpty()) {
            // nothing to do--no parent class to re-compile
            return true
        }

        // check each parent for modification
        for (clazz in parentClasses) {
            val parentFile = getSourceFile(clazz)
                    ?: continue // not sure if this can happen (inner-class, maybe?)

            // Parent class might have a non-default java package, so use class's full name.
            val clazzFile = getClassFile(parentFile, clazz.name)

            if (parentFile.lastModified() > clazzFile.lastModified()) {
                return false
            }
        }

        return true
    }

    @Throws(ClassNotFoundException::class)
    protected fun compile(sourceFile: ResourceFile, writer: PrintWriter): Boolean {

        val info = GhidraScriptUtil.getScriptInfo(sourceFile)
        info.isCompileErrors = true

        if (!doCompile(sourceFile, writer)) {
            writer.flush() // force any error messages out
            throw ClassNotFoundException("Unable to compile class: " + sourceFile.name)
        }

        compileParentClasses(sourceFile, writer)

        forceClassReload()

        info.isCompileErrors = false
        writer.println("Successfully compiled: " + sourceFile.name)

        return true
    }

    private fun doCompile(sourceFile: ResourceFile, writer: PrintWriter): Boolean {

        val javaCompiler = ToolProvider.getSystemJavaCompiler()
        if (javaCompiler == null) {
            val message = "Compile failed: java compiler provider not found (you must be using a JDK " + "to compile scripts)!"
            writer.println(message)
            Msg.error(this, message) // the writer may not be the same as Msg, so log it too
            return false
        }

        val fileManager = ResourceFileJavaFileManager(GhidraScriptUtil.getScriptSourceDirectories())

        val list = ArrayList<ResourceFileJavaFileObject>()
        list.add(
                ResourceFileJavaFileObject(sourceFile.parentFile!!, sourceFile, Kind.SOURCE))

        val outputDirectory = GhidraScriptUtil.getScriptCompileOutputDirectory(sourceFile).absolutePath
        Msg.trace(this, "Compiling script $sourceFile to dir $outputDirectory")

        val options = ArrayList<String>()
        options.add("-g")
        options.add("-d")
        options.add(outputDirectory)
        options.add("-sourcepath")
        options.add(sourcePath)
        options.add("-classpath")
        options.add(classPath)
        options.add("-proc:none") // Prevents warning when script imports something that will get compiled

        val task = javaCompiler.getTask(writer, fileManager, null, options, null, list)
        return task.call()!!
    }

    private fun getParentClasses(scriptSourceFile: ResourceFile): MutableList<Class<*>>? {

        val scriptClass = getScriptClass(scriptSourceFile)
                ?: return null // special signal that there was a problem

        val parentClasses = ArrayList<Class<*>>()
        var superClass: Class<*>? = scriptClass.superclass
        while (superClass != null) {
            if (superClass == GhidraScript::class.java) {
                break // not interested in the built-in classes
            } else if (superClass == HeadlessScript::class.java) {
                break // not interested in the built-in classes
            }
            parentClasses.add(superClass)
            superClass = superClass.superclass
        }
        return parentClasses
    }

    private fun getScriptClass(scriptSourceFile: ResourceFile): Class<*>? {
        val clazzName = GhidraScriptUtil.getBaseName(scriptSourceFile)
        try {
            return Class.forName(clazzName, true, JavaScriptClassLoader())
        } catch (e: NoClassDefFoundError) {
            Msg.error(this, "Unable to find class file for script file: $scriptSourceFile", e)
        } catch (e: ClassNotFoundException) {
            Msg.error(this, "Unable to find class file for script file: $scriptSourceFile", e)
        } catch (e: GhidraScriptUnsupportedClassVersionError) {
            // Unusual Code Alert!: This implies the script was compiled in a newer
            // version of Java.  So, just delete the class file and try again.
            val classFile = e.classFile
            classFile.delete()
            return null // trigger re-compile
        }

        return null
    }

    private fun compileParentClasses(sourceFile: ResourceFile, writer: PrintWriter) {

        val parentClasses = getParentClasses(sourceFile)
                ?: // this shouldn't happen, as this method is called after the child class is
                // re-compiled and thus, all parent classes should still be there.
                return

        if (parentClasses.isEmpty()) {
            // nothing to do--no parent class to re-compile
            return
        }

        //
        // re-compile each class's source file
        //

        // first, reverse the order, so that we compile the highest-level classes first,
        // and then on down, all the way to the script class
        Collections.reverse(parentClasses)

        // next, add back to the list the script that was just compiled, as it may need
        // to be re-compiled after the parent classes are re-compiled
        val scriptClass = getScriptClass(sourceFile)
                ?: // shouldn't happen
                return
        parentClasses.add(scriptClass)

        for (parentClass in parentClasses) {
            val parentFile = getSourceFile(parentClass)
                    ?: continue // not sure if this can happen (inner-class, maybe?)

            if (!doCompile(parentFile, writer)) {
                Msg.error(this, "Failed to re-compile parent class: $parentClass")
                return
            }
        }
    }

    private fun getSourceFile(c: Class<*>): ResourceFile? {
        // check all script paths for a dir named
        val classname = c.name
        val filename = classname.replace('.', '/') + ".java"

        val scriptDirs = GhidraScriptUtil.getScriptSourceDirectories()
        for (dir in scriptDirs) {
            val possibleFile = ResourceFile(dir, filename)
            if (possibleFile.exists()) {
                return possibleFile
            }
        }

        return null
    }

    @Throws(IOException::class)
    override fun createNewScript(newScript: ResourceFile, category: String?) {
        val scriptName = newScript.name
        var className = scriptName
        val dotpos = scriptName.lastIndexOf('.')
        if (dotpos >= 0) {
            className = scriptName.substring(0, dotpos)
        }
        val writer = PrintWriter(FileWriter(newScript.getFile(false)))

        writeHeader(writer, category)

        writer.println("import ghidra.app.script.GhidraScript;")

        for (pkg in Package.getPackages()) {
            if (pkg.name.startsWith("ghidra.program.model.")) {
                writer.println("import " + pkg.name + ".*;")
            }
        }

        writer.println("")

        writer.println("public class $className extends GhidraScript {")
        writer.println("")

        writer.println("    public void run() throws Exception {")

        writeBody(writer)

        writer.println("    }")
        writer.println("")
        writer.println("}")
        writer.close()
    }

    override fun getCommentCharacter(): String {
        return "//"
    }
}
