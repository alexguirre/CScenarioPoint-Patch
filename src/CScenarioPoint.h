#pragma once
#include <stdint.h>

class CScenarioPoint
{
public:
	void* Refs;
	void* OwnerEntity;
	uint16_t RuntimeFlags;
	uint16_t CargenIndex;
	uint8_t unk_14; // ?
	uint8_t iType;
	uint8_t ModelSetId;
	uint8_t iInterior;
	uint8_t iRequiredIMapId;
	uint8_t iProbability;
	uint8_t uAvailableInMpSp;
	uint8_t iTimeStartOverride;
	uint8_t iTimeEndOverride;
	uint8_t iRadius;
	uint8_t iTimeTillPedLeaves;
	uint8_t padding_1F;
	uint16_t iScenarioGroup;
	uint16_t padding_22;
	uint32_t Flags;
	uint64_t unk_28; // ?
	float vPositionAndDirection[4];
};

static_assert(sizeof(CScenarioPoint) == 0x40);
