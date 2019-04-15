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

import java.util.*

import org.jdom.Element

import ghidra.app.CorePluginPackage
import ghidra.app.events.ProgramClosedPluginEvent
import ghidra.app.nav.*
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.services.*
import ghidra.framework.options.*
import ghidra.framework.plugintool.*
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.framework.plugintool.util.ToolConstants
import ghidra.program.model.listing.Program
import ghidra.util.Msg
import ghidra.util.bean.opteditor.OptionsVetoException

/**
 * <CODE>NavigationHistoryPlugin</CODE> is used in conjunction with other
 * plugins to cause program viewer plugins to change their focus to a certain
 * address. As viewer plugins are directed to one or more addresses it maintains
 * information about where the viewers have been to support ability for the
 * viewers to go back to a previous "focus" point.
 *
 * Services Provided: NavigationHistoryService
 * Events Consumed: ProgramLocationPluginEvent, ProgramPluginEvent
 * Event Produced: HistoryChangePluginEvent Actions: None.
 */
//@formatter:off
@PluginInfo(status = PluginStatus.RELEASED, packageName = CorePluginPackage.NAME, category = PluginCategoryNames.SUPPORT, shortDescription = "Tool State History", description = "This plugin maintains a history of tool states. "
        + "It is used in conjunction with other plugins "
        + "to cause program viewer plugins to change their focus to a certain address. "
        + "As viewer plugins are directed to one or more addresses, it maintains "
        + "information about where the viewers have been to support ability for the viewers "
        + "to go back to a previous \"focus\" point.", servicesRequired = [ProgramManager::class], servicesProvided = [NavigationHistoryService::class], eventsConsumed = [ProgramClosedPluginEvent::class])
//@formatter:on
class NavigationHistoryPlugin
/**
 * Creates a new instance of the <CODE>ToolStateHistoryPlugin</CODE>,
 * passing it the session and plugin tool that it is in.
 * <P>
</P> */
(plugintool: PluginTool) : Plugin(plugintool), NavigationHistoryService, NavigatableRemovalListener, OptionsChangeListener {

    private val historyListMap = HashMap<Navigatable, HistoryList>()
    private var maxHistorySize = MAX_HISTORY_SIZE

    private var dataSaveState: SaveState? = null

    init {

        plugintool.getOptions(ToolConstants.TOOL_OPTIONS)
    }

    override fun dispose() {
        val options = tool.getOptions(ToolConstants.TOOL_OPTIONS)
        options.removeOptionsChangeListener(this)

        super.dispose()
    }

    override fun init() {
        initOptions()
    }

    override fun readDataState(saveState: SaveState) {
        this.dataSaveState = saveState
    }

    override fun dataStateRestoreCompleted() {
        if (dataSaveState == null) {
            return
        }
        val pm = tool.getService(ProgramManager::class.java)
        val programs = pm.allOpenPrograms
        val count = dataSaveState!!.getInt(LIST_COUNT, 0)
        for (i in 0 until count) {
            val xmlElement = dataSaveState!!.getXmlElement(HISTORY_LIST + i)
            restoreHistoryList(xmlElement, programs)
        }
        dataSaveState = null
        notifyHistoryChange()
    }

    private fun initOptions() {
        val options = tool.getOptions(ToolConstants.TOOL_OPTIONS)

        options.registerOption(MAX_NAVIGATION_HISTORY_SIZE_OPTION_NAME, MAX_HISTORY_SIZE, null,
                "The maximum number of items to display in the tool's navigation history.")
        maxHistorySize = options.getInt(MAX_NAVIGATION_HISTORY_SIZE_OPTION_NAME, MAX_HISTORY_SIZE)

        options.addOptionsChangeListener(this)
    }

    override fun optionsChanged(options: ToolOptions, optionName: String, oldValue: Any?,
                                newValue: Any?) {
        if (MAX_NAVIGATION_HISTORY_SIZE_OPTION_NAME == optionName) {
            val newMaxHistorySize = options.getInt(MAX_NAVIGATION_HISTORY_SIZE_OPTION_NAME, MAX_HISTORY_SIZE)
            if (newMaxHistorySize > ABSOLUTE_MAX_HISTORY_SIZE) {
                throw OptionsVetoException(
                        "History size cannot be greater than $ABSOLUTE_MAX_HISTORY_SIZE")
            }
            if (newMaxHistorySize < ABSOLUTE_MIN_HISTORY_SIZE) {
                throw OptionsVetoException(
                        "History size cannot be less than $ABSOLUTE_MIN_HISTORY_SIZE")
            }
            maxHistorySize = newMaxHistorySize

            updateHistoryListMaxSize(maxHistorySize)
        }
    }

    private fun updateHistoryListMaxSize(maxLocations: Int) {
        val historyLists = historyListMap.values
        for (historyList in historyLists) {
            historyList.setMaxLocations(maxLocations)
        }
    }

    private fun restoreHistoryList(xmlElement: Element?, programs: Array<Program>) {
        val saveState = SaveState(xmlElement!!)
        val nav = NavigatableRegistry.getNavigatable(saveState.getLong(NAV_ID, 0)) ?: return
        nav.addNavigatableListener(this)
        val historyList = HistoryList(maxHistorySize)
        historyListMap[nav] = historyList

        val count = saveState.getInt(LOCATION_COUNT, 0)
        for (i in 0 until count) {
            val memento = restoreLocation(i, saveState, programs)
            if (memento != null) {
                historyList.addLocation(memento)
            }
        }
        val currentLocationIndex = saveState.getInt(CURRENT_LOCATION_INDEX, historyList.size())
        historyList.currentLocationIndex = currentLocationIndex
    }

    override fun writeDataState(saveState: SaveState) {
        var count = 0
        for (navigatable in historyListMap.keys) {
            val historyList = historyListMap[navigatable]!!
            val listSaveState = SaveState()
            writeDataState(listSaveState, navigatable, historyList)
            saveState.putXmlElement(HISTORY_LIST + count, listSaveState.saveToXml())
            count++
        }
        saveState.putInt(LIST_COUNT, count)
    }

    fun writeDataState(saveState: SaveState, navigatable: Navigatable,
                       historyList: HistoryList) {
        saveState.putLong(NAV_ID, navigatable.instanceID)
        saveState.putInt(LOCATION_COUNT, historyList.size())
        saveState.putInt(CURRENT_LOCATION_INDEX, historyList.currentLocationIndex)
        for (i in 0 until historyList.size()) {
            val location = historyList.getLocation(i)
            saveLocation(i, saveState, location)
        }
    }

    /**
     * Positions the "current" view to the next view in the history list and
     * generates a "HistoryChangedEvent". If there is no "next" view, the
     * history list remains unchanged.
     */
    override fun next(navigatable: Navigatable) {
        if (hasNext(navigatable)) {
            val historyList = historyListMap[navigatable]
            val nextLocation = historyList?.next()
            navigate(navigatable, nextLocation!!)
        }
    }

    /**
     * Positions the "current" view to the previous view in the history list and
     * generates a "HistoryChangeEvent". If there is no "previous" view,
     * the history list remains unchanged.
     */
    override fun previous(navigatable: Navigatable) {
        if (hasPrevious(navigatable)) {
            val historyList = historyListMap[navigatable]
            addCurrentLocationToHistoryIfAppropriate(navigatable, historyList?.getCurrentLocation() ?: return)

            val previousLocation = historyList.previous()
            navigate(navigatable, previousLocation!!)
        }
    }

    private fun addCurrentLocationToHistoryIfAppropriate(navigatable: Navigatable,
                                                         location: LocationMemento) {
        if (!hasNext(navigatable)) {
            val historyList = historyListMap[navigatable]
            val currentLocation = navigatable.memento
            if (currentLocation.isValid) {
                historyList?.addLocation(currentLocation)
            }
        }
    }

    override fun next(navigatable: Navigatable, location: LocationMemento) {
        while (hasNext(navigatable)) {
            val historyList = historyListMap[navigatable] ?: continue
            val nextLocation = historyList.next()
            if (nextLocation === location) {
                navigate(navigatable, nextLocation)
                break
            }
        }
    }

    private fun navigate(navigatable: Navigatable, memento: LocationMemento) {
        navigatable.goTo(memento.program, memento.programLocation)
        navigatable.memento = memento
        if (navigatable.isVisible) {
            navigatable.requestFocus()
        }
        tool.contextChanged(null)
    }

    override fun previous(navigatable: Navigatable, location: LocationMemento) {
        addCurrentLocationToHistoryIfAppropriate(navigatable, location)
        while (hasPrevious(navigatable)) {
            val historyList = historyListMap[navigatable]
            val previousLocation = historyList?.previous()
            if (previousLocation === location) {
                navigate(navigatable, previousLocation)
                break
            }
        }
    }

    override fun getNextLocations(navigatable: Navigatable): List<LocationMemento> {
        val historyList = historyListMap[navigatable]
        return historyList?.nextLocations ?: ArrayList()
    }

    override fun getPreviousLocations(navigatable: Navigatable): List<LocationMemento> {
        val historyList = historyListMap[navigatable] ?: return ArrayList()
        val previousLocations: MutableList<LocationMemento> = historyList.previousLocations.toMutableList()
        if (!hasNext(navigatable)) {
            val currentHistoryLocation = historyList.getCurrentLocation()
            val currentLocation = navigatable.memento
            if (currentLocation != currentHistoryLocation) {
                previousLocations.add(0, currentLocation)
            }
        }
        return previousLocations
    }

    /**
     * Returns true if there is a valid "next" function view in the history list, or there is "next" view and we are not
     * in any functions.
     */
    override fun hasNextFunction(navigatable: Navigatable): Boolean {
        return hasNextPreviousFunction(navigatable, true)
    }

    override fun hasPreviousFunction(navigatable: Navigatable): Boolean {
        return hasNextPreviousFunction(navigatable, false)
    }

    private fun hasNextPreviousFunction(navigatable: Navigatable, isNext: Boolean): Boolean {
        val historyList = historyListMap[navigatable] ?: return false
        val program = navigatable.program
        val currentLocation = navigatable.location
        val functionManager = program.functionManager
        val currentFunction = functionManager.getFunctionContaining(
                currentLocation.byteAddress) ?: return if (isNext) { historyList.hasNext() } else {
            historyList.hasPrevious()
        }
        val locationMementos = if (isNext) {
            historyList.nextLocations
        } else {
            historyList.previousLocations
        }
        for (locationMemento in locationMementos) {
            val location = locationMemento.programLocation
            val nextFunction= functionManager.getFunctionContaining(location.byteAddress) ?: return true
            if (nextFunction != currentFunction) {
                return true
            }
        }
        return false
    }

    override fun nextFunction(navigatable: Navigatable) {
        if (hasNextFunction(navigatable)) {
            nextPreviousFunction(navigatable, true)
        }
    }

    override fun previousFunction(navigatable: Navigatable) {
        if (hasPreviousFunction(navigatable)) {
            nextPreviousFunction(navigatable, false)
        }
    }

    /**
     * Forwards or backwards to next or previous function. If we are not at a function, just forward
     * of backward to the view.
     *
     * This requires the hasNextFunction or hasPreviousFunction test passed
     */
    private fun nextPreviousFunction(navigatable: Navigatable, isNext: Boolean) {
        val historyList = historyListMap[navigatable] ?: return
        val program = navigatable.program
        val currentLocation = navigatable.location
        val functionManager = program.functionManager
        val currentFunction = functionManager.getFunctionContaining(
                currentLocation.byteAddress
        ) ?: if (isNext) {
            val loc = historyList.next()!!
            navigate(navigatable, loc)
            return
        } else {
            val loc = historyList.previous()!!
            navigate(navigatable, loc)
            return
        }

        val locationMementos = if (isNext) {
            historyList.nextLocations
        } else {
            historyList.previousLocations
        }

        for (locationMemento in locationMementos) {
            val location = locationMemento.programLocation
            val possibleFunction = functionManager.getFunctionContaining(location.byteAddress) ?: if (isNext) {
                historyList.next()
                break
            } else {
                historyList.previous()
                break
            }
            if (possibleFunction == currentFunction) {
                if (isNext) {
                    historyList.next()
                } else {
                    historyList.previous()
                }
            } else if (isNext) {
                navigate(navigatable, historyList.next()!!)
                break
            } else {
                navigate(navigatable, historyList.previous()!!)
                break
            }
        }
    }

    /**
     * Returns true if there is a valid "next" view in the history list.
     */
    override fun hasNext(navigatable: Navigatable): Boolean {
        val historyList = historyListMap[navigatable]
        return historyList != null && historyList.hasNext()
    }

    /**
     * Returns true if there is a valid "previous" view in the history list.
     */
    override fun hasPrevious(navigatable: Navigatable): Boolean {
        val historyList = historyListMap[navigatable]
        return historyList != null && historyList.hasPrevious()
    }

    /**
     * Removes all views from the history list and fires a change event. If the
     * history list is already empty, then nothing happens.
     */
    override fun clear(navigatable: Navigatable) {
        historyListMap.remove(navigatable)
        notifyHistoryChange()
    }

    private fun clear(program: Program) {
        for (historyList in historyListMap.values) {
            clear(historyList, program)
        }
        notifyHistoryChange()
    }

    private fun clear(historyList: HistoryList, program: Program) {
        for (i in historyList.size() - 1 downTo 0) {
            val location = historyList.getLocation(i)
            if (location.program === program) {
                historyList.remove(location)
            }
        }
    }

    /**
     * Fires off a <CODE>HistoryChangePluginEvent</CODE>.
     * <P>
    </P> */
    private fun notifyHistoryChange() {
        tool.contextChanged(null)
    }

    override fun processEvent(event: PluginEvent) {
        if (event is ProgramClosedPluginEvent) {
            clear(event.program)
        }
    }

    override fun addNewLocation(navigatable: Navigatable) {
        var navigatable = navigatable
        navigatable = getHistoryNavigatable(navigatable) ?: return
        var historyList: HistoryList? = historyListMap[navigatable]
        if (historyList == null) {
            navigatable.addNavigatableListener(this)
            historyList = HistoryList(maxHistorySize)
            historyListMap[navigatable] = historyList
        }

        val memento = navigatable.memento
        if (memento.isValid) {
            historyList.addLocation(memento)
            notifyHistoryChange()
        }
    }

    private fun getHistoryNavigatable(navigatable: Navigatable): Navigatable? {
        if (!navigatable.isConnected) {
            return navigatable
        }

        val service = tool.getService(GoToService::class.java)
        return service?.defaultNavigatable
    }

    override fun navigatableRemoved(navigatable: Navigatable) {
        navigatable.removeNavigatableListener(this)
        clear(navigatable)
    }

    private fun saveLocation(index: Int, saveState: SaveState, memento: LocationMemento) {
        val mementoSaveState = SaveState()
        memento.saveState(mementoSaveState)
        val element = mementoSaveState.saveToXml()
        saveState.putString(MEMENTO_CLASS + index, memento.javaClass.name)
        saveState.putXmlElement(MEMENTO_DATA + index, element)
    }

    private fun restoreLocation(index: Int, saveState: SaveState, programs: Array<Program>): LocationMemento? {
        val mementoElement = saveState.getXmlElement(MEMENTO_DATA + index) ?: return null
        val mementoState = SaveState(mementoElement)
        var locationMemento: LocationMemento? = null
        try {
            locationMemento = LocationMemento.getLocationMemento(mementoState, programs)
        } catch (iae: IllegalArgumentException) {
            Msg.debug(this, "Unable to restore LocationMemento: " + iae.message)
        }

        return locationMemento
    }

    companion object {
        const val MAX_NAVIGATION_HISTORY_SIZE_OPTION_NAME = "Max Navigation History Size"
        const val HISTORY_LIST = "HISTORY_LIST_"
        const val LIST_COUNT = "LIST_COUNT"
        const val LOCATION_COUNT = "LOCATION_COUNT"
        const val NAV_ID = "NAV_ID"
        const val CURRENT_LOCATION_INDEX = "CURRENT_LOC_INDEX"
        const val MEMENTO_DATA = "MEMENTO_DATA"
        const val MEMENTO_CLASS = "MEMENTO_CLASS"
        const val ABSOLUTE_MAX_HISTORY_SIZE = 100
        const val ABSOLUTE_MIN_HISTORY_SIZE = 10
        const val MAX_HISTORY_SIZE = 30
    }

}
