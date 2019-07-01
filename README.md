# CScenarioPoint Patch

A patch for Grand Theft Auto V that increases the maximum number of scenario types and model sets (of both peds and vehicles) available to `CScenarioPoint`s, from 256 to around 65.000.

## How it works

The fields `iType` and `ModelSetId` of `CScenarioPoint` are defined as `uint8` which effectively limits the scenarios and model sets of `CScenarioPoint`s to the first 256 elements of their respective arrays (255 in the case of model sets since 0xFF is its invalid index value).

This patch saves in a map the correct scenarios and model sets indices as `uint32`s for each loaded `CScenarioPoint` and every location that accesses the original fields is patched to access our map instead. Due to other places where `uint16` is used, such as the scenarios and model sets arrays, they are still limited to ~65.000. Reaching this limit has not been tested so the actual limit may be somewhat lower but it has been tested with ~2000 extra entries of each: ped model sets (ambientpedmodelsets.meta), vehicle model sets (vehiclemodelsets.meta) and scenario infos (scenarios.meta)

See [NOTES](NOTES.md) for more specific information about each patch.

## Requirements

* ASI loader (for example, dinput8.dll included with [ScriptHookV](http://www.dev-c.com/gtav/scripthookv/)).

## Installation

* Download pre-built binaries from [GTA5-Mods.com](https://www.gta5-mods.com/scripts/cscenariopoint-patch).
* Place `CScenarioPoint-Patch.asi` in the root directory of your Grand Theft Auto V installation.
