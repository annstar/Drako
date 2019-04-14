package ghidra.app.plugin.core.navigation

import ghidra.app.nav.LocationMemento

import java.util.ArrayList
import java.util.Collections

class HistoryList(private var maxLocations: Int) {
    private val list = ArrayList<LocationMemento>()
    private var currentLocation = 0

    var currentLocationIndex: Int
        get() = currentLocation
        internal set(index) {
            if (index >= 0 && index < list.size) {
                currentLocation = index
            }
        }

    internal val previousLocations: List<LocationMemento>
        get() {
            val previousLocations = ArrayList<LocationMemento>()
            for (i in 0 until currentLocation) {
                previousLocations.add(list[i])
            }
            Collections.reverse(previousLocations)
            return previousLocations
        }

    internal val nextLocations: List<LocationMemento>
        get() {
            val nextLocations = ArrayList<LocationMemento>()
            for (i in currentLocation + 1 until list.size) {
                nextLocations.add(list[i])
            }
            return nextLocations
        }

    internal fun clear() {
        list.clear()
        currentLocation = 0
    }

    fun size(): Int {
        return list.size
    }

    fun getLocation(index: Int): LocationMemento {
        return list[index]
    }

    fun getCurrentLocation(): LocationMemento {
        return list[currentLocation]
    }

    internal fun addLocation(newValue: LocationMemento) {
        if (list.isEmpty()) {
            list.add(newValue)
            currentLocation = 0
            return
        }
        while (list.size - 1 > currentLocation) {
            list.removeAt(list.size - 1)
        }

        val lastLocation = list[list.size - 1]
        if (newValue != lastLocation) {
            list.add(newValue) // new location, add it to list
        } else {
            // same location, but maybe different "extra" info replace equivalent location
            list[list.size - 1] = newValue
        }
        if (list.size > maxLocations) {
            list.removeAt(0)
        }
        currentLocation = list.size - 1

    }

    internal fun setMaxLocations(maxLocations: Int) {
        this.maxLocations = maxLocations
    }

    internal operator fun hasNext(): Boolean {
        return if (list.isEmpty()) {
            false
        } else currentLocation < list.size - 1
    }

    internal fun hasPrevious(): Boolean {
        return if (list.isEmpty()) {
            false
        } else currentLocation > 0
    }

    internal operator fun next(): LocationMemento? {
        if (hasNext()) {
            currentLocation++
            return list[currentLocation]
        }
        return null
    }

    internal fun previous(): LocationMemento? {
        if (hasPrevious()) {
            currentLocation--
            return list[currentLocation]
        }
        return null
    }

    internal fun remove(location: LocationMemento) {
        for (i in list.indices) {
            val loc = list[i]
            if (loc == location) {
                list.removeAt(i)
                if (currentLocation > 0 && currentLocation >= i) {
                    currentLocation--
                }
                return
            }
        }
    }
}
