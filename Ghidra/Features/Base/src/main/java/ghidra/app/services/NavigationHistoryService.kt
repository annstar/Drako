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
package ghidra.app.services

import ghidra.app.nav.LocationMemento
import ghidra.app.nav.Navigatable
import ghidra.app.plugin.core.navigation.NavigationHistoryPlugin
import ghidra.framework.plugintool.ServiceInfo

/**
 * The ToolStateHistoryService maintains a stack of locations that the user
 * has visited via a navigation plugin.
 * It provides methods querying and manipulating this list.
 */
@ServiceInfo(defaultProvider = [NavigationHistoryPlugin::class], description = "Maintains a history of tool states")
interface NavigationHistoryService {

    /**
     * Positions the "current" location to the next location in the history list.
     * Use function-wise location if it is possible. If current view cannot contain
     * any functions, just fallback to normal next(). If there is no "next" function
     * location the history list remains unchanged.
     */
    fun nextFunction(navigatable: Navigatable)

    /**
     * Positions the "current" location to the next location in the history list.
     * Use function-wise location if it is possible. If current view cannot contain
     * any functions, just fallback to normal next(). If there is no "previous" function
     * location the history list remains unchanged.
     */
    fun previousFunction(navigatable: Navigatable)

    /**
     * Positions the "current" location to the next location in the history list.
     * If there is no "next" location, the history list remains unchanged.
     */
    fun next(navigatable: Navigatable)

    /**
     * Positions the "current" location to the previous location in the history list.
     * If there is no "previous" location, the
     * history list remains unchanged.
     */
    fun previous(navigatable: Navigatable)

    /**
     * Navigates to the given location in the "next" list.  If the location is not in the list, then
     * nothing will happen.
     * @param location The location within the "next" list to which to go.
     */
    fun next(navigatable: Navigatable, location: LocationMemento)

    /**
     * Navigates to the given location in the "previous" list.  If the location is not in
     * the list, then nothing will happen.
     * @param location The location within the "previous" list to which to go.
     */
    fun previous(navigatable: Navigatable, location: LocationMemento)

    /**
     * Returns the LocationMemento objects in the "previous" list.
     * @return the LocationMemento objects in the "previous" list.
     */
    fun getPreviousLocations(navigatable: Navigatable): List<LocationMemento>

    /**
     * Returns the LocationMemento objects in the "next" list.
     * @return the LocationMemento objects in the "next" list.
     */
    fun getNextLocations(navigatable: Navigatable): List<LocationMemento>

    /**
     * Returns true if there is a valid "next" function location in the history list
     */
    fun hasNextFunction(navigatable: Navigatable): Boolean

    /**
     * Returns true if there is a valid "previous" function location in the history list
     */
    fun hasPreviousFunction(navigatable: Navigatable): Boolean

    /**
     * Returns true if there is a valid "next" location in the history list.
     */
    fun hasNext(navigatable: Navigatable): Boolean

    /**
     * Returns true if there is a valid "previous" location in the history list.
     */
    fun hasPrevious(navigatable: Navigatable): Boolean

    /**
     * Adds the given locationMomento to the list of previous locations.  Clears the list
     * of next locations.
     */
    fun addNewLocation(navigatable: Navigatable)

    /**
     * Removes all visited locations from the history list.
     */
    fun clear(navigatable: Navigatable)
}
