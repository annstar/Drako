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
package ghidra.app.plugin.core.navigation

import java.awt.event.InputEvent
import java.awt.event.KeyEvent
import java.util.*

import docking.ActionContext
import docking.action.*
import docking.menu.MultiActionDockingAction
import ghidra.app.CorePluginPackage
import ghidra.app.context.*
import ghidra.app.nav.LocationMemento
import ghidra.app.nav.Navigatable
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.services.GoToService
import ghidra.app.services.NavigationHistoryService
import ghidra.app.util.HelpTopics
import ghidra.app.util.viewer.field.BrowserCodeUnitFormat
import ghidra.base.actions.HorizontalRuleAction
import ghidra.framework.plugintool.*
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.program.model.address.Address
import ghidra.program.model.listing.*
import ghidra.util.HelpLocation
import resources.ResourceManager

/**
 * <CODE>NextPrevAddressPlugin</CODE> allows the user to go back and forth in
 * the history list and to clear it.
 *
 */
//@formatter:off
@PluginInfo(status = PluginStatus.RELEASED, packageName = CorePluginPackage.NAME, category = PluginCategoryNames.NAVIGATION, shortDescription = "Navigates to previous locations", description = "Provides actions for returning to previously visited program locations.", servicesRequired = [NavigationHistoryService::class])
//@formatter:on
class NextPrevAddressPlugin
//////////////////////////////////////////////////////////////////////
//                                                                  //
// Constructor                                                      //
//                                                                  //
//////////////////////////////////////////////////////////////////////

/**
 * Creates a new instance of the plugin.
 * <P>
 * @param session the session the plugin will be operating in.
 * @param plugintool the tool the plugin will be operating in.
</P> */
(plugintool: PluginTool) : Plugin(plugintool) {

    private var historyService: NavigationHistoryService? = null
    private var nextAction: MultiActionDockingAction? = null
    private var previousAction: MultiActionDockingAction? = null
    private var nextFuncAction: MultiActionDockingAction? = null
    private var previousFuncAction: MultiActionDockingAction? = null
    private var clearAction: DockingAction? = null
    private var codeUnitFormatter: BrowserCodeUnitFormat? = null

    init {

        // no events produced
        // no services provided
        // will acquire history service in init()
        // no focused context
        createActions()
    }

    //////////////////////////////////////////////////////////////////////
    //                                                                  //
    // overridden Plugin methods										//
    //                                                                  //
    //////////////////////////////////////////////////////////////////////

    /**
     * Obtains a handle to the address history list service.
     */
    override fun init() {
        historyService = tool.getService(NavigationHistoryService::class.java)
        codeUnitFormatter = BrowserCodeUnitFormat(tool)
    }

    //////////////////////////////////////////////////////////////////////
    //                                                                  //
    // private methods                                                  //
    //                                                                  //
    //////////////////////////////////////////////////////////////////////

    private fun getPreviousActions(navigatable: Navigatable?): List<DockingActionIf> {
        var lastProgram: Program? = null
        val actionList = ArrayList<DockingActionIf>()
        val nextLocations = historyService!!.getPreviousLocations(navigatable!!)
        for (locationMomento in nextLocations) {
            val program = locationMomento.program

            // add an action to signal a change; don't make the first element a separator
            if (program !== lastProgram && actionList.size != 0) {
                // add an action that will trigger a separator to be added to the menu
                actionList.add(createHorizontalRule(lastProgram!!, program))
            }
            lastProgram = program
            actionList.add(NavigationAction(navigatable, locationMomento, false, historyService!!,
                    codeUnitFormatter!!))
        }
        return actionList
    }

    private fun getNextActions(navigatable: Navigatable?): List<DockingActionIf> {
        var lastProgram: Program? = null
        val actionList = ArrayList<DockingActionIf>()
        val nextLocations = historyService!!.getNextLocations(navigatable!!)
        for (locationMomento in nextLocations) {
            val program = locationMomento.program

            // add an action to signal a change; don't make the first element a separator
            if (program !== lastProgram && !actionList.isEmpty()) {
                // add an action that will trigger a separator to be added to the menu
                actionList.add(createHorizontalRule(lastProgram!!, program))
            }
            lastProgram = program

            actionList.add(NavigationAction(navigatable, locationMomento, true, historyService!!,
                    codeUnitFormatter!!))
        }
        return actionList
    }

    private fun createHorizontalRule(previousProgram: Program, nextProgram: Program): DockingActionIf {

        val previousDomainFile = previousProgram.domainFile
        val topName = previousDomainFile.name
        val nextDomainFile = nextProgram.domainFile
        val bottomName = nextDomainFile.name
        return HorizontalRuleAction(getName(), topName, bottomName)
    }

    /**
     * Creates this plugin's actions.
     */
    private fun createActions() {
        nextAction = NextPreviousAction(NEXT_ACTION_NAME, getName(), true)
        previousAction = NextPreviousAction(PREVIOUS_ACTION_NAME, getName(), false)
        nextFuncAction = NextPreviousFunctionAction(NEXT_FUNC_ACTION_NAME, getName(), true)
        previousFuncAction = NextPreviousFunctionAction(PREVIOUS_FUNC_ACTION_NAME, getName(), false)

        clearAction = object : DockingAction("Clear History Buffer", getName()) {
            override fun actionPerformed(context: ActionContext) {
                historyService!!.clear(getNavigatable(context)!!)
            }

            override fun shouldAddToWindow(isMainWindow: Boolean, contextTypes: Set<Class<*>>): Boolean {
                for (class1 in contextTypes) {
                    if (NavigationActionContext::class.java.isAssignableFrom(class1)) {
                        return true
                    }
                }
                return false
            }

            override fun isEnabledForContext(context: ActionContext): Boolean {
                if (context !is ProgramActionContext) {
                    return false
                }

                val navigatable = getNavigatable(context)
                return historyService!!.hasNext(navigatable!!) || historyService!!.hasPrevious(navigatable)
            }
        }
        clearAction!!.setHelpLocation(HelpLocation(HelpTopics.NAVIGATION, clearAction!!.name))
        val menuData = MenuData(CLEAR_MENUPATH, NAV_GROUP)
        menuData.menuSubGroup = "1" // first in menu!
        clearAction!!.menuBarData = menuData

        tool.addAction(previousAction)
        tool.addAction(nextAction)
        tool.addAction(previousFuncAction)
        tool.addAction(nextFuncAction)
        tool.addAction(clearAction)
    }

    private fun getNavigatable(context: ActionContext): Navigatable? {
        if (context is NavigatableActionContext) {
            val navigatable = context.navigatable
            if (!navigatable.isConnected) {
                return navigatable
            }
        }
        val service = tool.getService(GoToService::class.java)
        return service?.defaultNavigatable
    }

    //////////////////////////////////////////////////////////////////////
    //                                                                  //
    // Inner Classes                                                    //
    //                                                                  //
    //////////////////////////////////////////////////////////////////////

    private inner class NextPreviousAction internal constructor(name: String, owner: String, private val isNext: Boolean) : MultiActionDockingAction(name, owner) {

        init {
            toolBarData = ToolBarData(if (isNext) nextIcon else previousIcon, NAV_GROUP)
            setHelpLocation(HelpLocation(HelpTopics.NAVIGATION, name))
            val keycode = if (isNext) KeyEvent.VK_RIGHT else KeyEvent.VK_LEFT
            keyBindingData = KeyBindingData(keycode, InputEvent.ALT_DOWN_MASK)
            description = if (isNext) "Go to next location" else "Go to previous location"
        }

        override fun isValidContext(context: ActionContext): Boolean {
            return context is NavigatableActionContext
        }

        override fun isEnabledForContext(context: ActionContext): Boolean {
            val navigatable = getNavigatable(context) ?: return false
            return if (isNext) {
                historyService!!.hasNext(navigatable)
            } else historyService!!.hasPrevious(navigatable)
        }

        override fun actionPerformed(context: ActionContext) {
            val navigatable = getNavigatable(context)
            if (isNext) {
                historyService!!.next(navigatable!!)
            } else {
                historyService!!.previous(navigatable!!)
            }
        }

        override fun shouldAddToWindow(isMainWindow: Boolean, contextTypes: Set<Class<*>>): Boolean {
            for (class1 in contextTypes) {
                if (NavigationActionContext::class.java.isAssignableFrom(class1)) {
                    return true
                }
            }
            return false
        }

        override fun getActionList(context: ActionContext): List<DockingActionIf> {
            val navigatable = getNavigatable(context)
            return if (isNext) {
                getNextActions(navigatable)
            } else getPreviousActions(navigatable)
        }

    }

    private inner class NextPreviousFunctionAction internal constructor(name: String, owner: String, private val isNext: Boolean) : MultiActionDockingAction(name, owner) {

        init {
            //toolBarData = ToolBarData(if (isNext) nextIcon else previousIcon, NAV_GROUP)
            //setHelpLocation(HelpLocation(HelpTopics.NAVIGATION, name))
            if (isNext) {
                keyBindingData = KeyBindingData(KeyEvent.VK_RIGHT, InputEvent.ALT_DOWN_MASK or InputEvent.SHIFT_DOWN_MASK)
            } else {
                keyBindingData = KeyBindingData(KeyEvent.VK_ESCAPE, 0)
            }
            description = if (isNext) "Go to next function location" else "Go to previous function location"
        }

        override fun isValidContext(context: ActionContext): Boolean {
            return context is NavigatableActionContext
        }

        override fun isEnabledForContext(context: ActionContext): Boolean {
            val navigatable = getNavigatable(context) ?: return false
            return if (isNext) {
                historyService!!.hasNext(navigatable)
            } else historyService!!.hasPrevious(navigatable)
        }

        override fun actionPerformed(context: ActionContext) {
            val navigatable = getNavigatable(context)
            if (isNext) {
                historyService!!.nextFunction(navigatable!!)
            } else {
                historyService!!.previousFunction(navigatable!!)
            }
        }

        override fun shouldAddToWindow(isMainWindow: Boolean, contextTypes: Set<Class<*>>): Boolean {
            for (class1 in contextTypes) {
                if (NavigationActionContext::class.java.isAssignableFrom(class1)) {
                    return true
                }
            }
            return false
        }

        override fun getActionList(context: ActionContext): List<DockingActionIf> {
            val navigatable = getNavigatable(context)
            return if (isNext) {
                getNextActions(navigatable)
            } else getPreviousActions(navigatable)
        }

    }

    private inner class NavigationAction constructor(private val navigatable: Navigatable, private val location: LocationMemento, private val isNext: Boolean,
                                                             private val service: NavigationHistoryService, formatter: CodeUnitFormat) : DockingAction("NavigationAction: " + ++idCount, this@NextPrevAddressPlugin.getName(), false) {

        init {

            menuBarData = MenuData(arrayOf(buildActionName(location, formatter)),
                    navigatable.navigatableIcon)
            isEnabled = true
        }

        override fun actionPerformed(context: ActionContext) {
            if (isNext) {
                service.next(navigatable, location)
            } else {
                service.previous(navigatable, location)
            }
        }
    }

    companion object {
        private val NAV_GROUP = "GoTo"
        private val previousIcon = ResourceManager.loadImage("images/left.png")
        private val nextIcon = ResourceManager.loadImage("images/right.png")

        private val PREVIOUS_FUNC_ACTION_NAME = "Previous Function in History Buffer"
        private val NEXT_FUNC_ACTION_NAME = "Next Function in History Buffer"
        private val PREVIOUS_ACTION_NAME = "Previous in History Buffer"
        private val NEXT_ACTION_NAME = "Next in History Buffer"
        private val CLEAR_MENUPATH = arrayOf("Navigation", "Clear History")

        private fun truncateAsNecessary(value: String): String {
            var value = value
            val maxNameLength = 25 // I know, magic number...
            if (value.length > maxNameLength) {
                value = value.substring(0, maxNameLength - 2) + "..."
            }
            return value
        }

        private fun buildActionName(location: LocationMemento, formatter: CodeUnitFormat): String {
            val program = location.program
            val address = location.programLocation.address

            // Display Format: "Address\t(FunctionName+Offset)\tLabel|Instruction"
            // where each tab character is a delimiter to separate columns
            val buffy = StringBuffer()
            buffy.append(address.toString()).append('\t')

            // in a function?
            val functionManager = program.functionManager
            val function = functionManager.getFunctionContaining(address)
            if (function != null) {
                val entryPointAddress = function.entryPoint
                var offset: String? = null
                if (entryPointAddress != address) {
                    offset = java.lang.Long.toHexString(address.subtract(entryPointAddress))
                }

                buffy.append('(').append(truncateAsNecessary(function.name))
                if (offset != null) {
                    buffy.append("+0x").append(offset)
                }
                buffy.append(')')
            }
            buffy.append('\t')

            // label or instruction?
            val representation = getAddressRepresentation(program, address, formatter)
            if (representation != null) {
                buffy.append(representation)
            }

            // use tabs here so that the DockingMenuItemUI used elsewhere in rendering will display
            // the content in tabular form
            return buffy.toString()
        }

        private fun getAddressRepresentation(program: Program, address: Address,
                                             formatter: CodeUnitFormat): String? {
            val symbolTable = program.symbolTable
            val symbol = symbolTable.getPrimarySymbol(address)
            if (symbol != null) { // try label first
                return truncateAsNecessary(symbol.name)
            }

            val listing = program.listing
            val codeUnit = listing.getCodeUnitAt(address) ?: return null
            val displayString = formatter.getRepresentationString(codeUnit)
            return if (displayString != null) {
                truncateAsNecessary(displayString)
            } else null
        }

        private var idCount = 0
    }

}
