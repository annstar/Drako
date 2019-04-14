package ghidra.app.plugin.core.symboltree.actions

import docking.action.MenuData
import ghidra.app.context.ProgramSymbolActionContext
import ghidra.app.context.ProgramSymbolContextAction
import ghidra.app.plugin.core.symboltree.SymbolTreePlugin
import resources.ResourceManager

class GoToAction(val plugin: SymbolTreePlugin) :
        ProgramSymbolContextAction("Go To Symbol Location", plugin.name) {

    init {
        this.popupMenuData = MenuData(arrayOf("Go to"), ResourceManager.loadImage("images/searchm_obj.gif"),
                "00Location")
    }

    override fun isEnabledForContext(context: ProgramSymbolActionContext): Boolean {
        if (context.symbolCount != 1) {
            return false
        }

        val symbol = context.firstSymbol ?: return false
        return !symbol.isExternal
    }

    override fun actionPerformed(context: ProgramSymbolActionContext) {
        val symbol = context.firstSymbol ?: return
        this.plugin.goTo(symbol)
    }
}

