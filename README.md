# CScenarioPoint Patch

A patch for Grand Theft Auto V that increases the maximum number of scenario types and model sets (of both peds and vehicles) available to `CScenarioPoint`s, from 256 to around 65.000.

## How it works

The fields `iType` and `ModelSetId` of `CScenarioPoint` are defined as `uint8` which effectively limits the scenarios and model sets of `CScenarioPoint`s to the first 256 elements of their respective arrays (255 in the case of model sets since 0xFF is its invalid index value). As of v1868, the bit 14 of the `RuntimeFlags` field is used to provide an additional bit to the `iType` field, extending its limit to 512.

This patch uses padding bytes of the `CScenarioPoint` structure to store the correct scenarios and model sets indices as `uint16`s and every location that accesses the original offsets is patched to access the new offsets. The `ModelSetId` value is now stored in 2 bytes at offset 0x22 and the `iType` value is stored at two different offsets, the lower 8 bits are stored at its original offset 0x15 and the higher 8 bits are stored at offset 0x1F.

## Requirements

* ASI loader (for example, dinput8.dll included with [ScriptHookV](http://www.dev-c.com/gtav/scripthookv/)).

## Installation

* Download pre-built binaries from [GTA5-Mods.com](https://www.gta5-mods.com/scripts/cscenariopoint-patch).
* Place `CScenarioPoint-Patch.asi` in the root directory of your Grand Theft Auto V installation.
