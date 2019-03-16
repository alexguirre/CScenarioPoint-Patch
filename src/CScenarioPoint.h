#pragma once
#include <stdint.h>

class CScenarioPoint
{
public:
	char field_0[21];
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
	char field_1F;
	uint16_t iScenarioGroup;
	char field_22[2];
	uint32_t Flags;
	char field_28[8];
	float vPositionAndDirection[4];
};

static_assert(sizeof(CScenarioPoint) == 0x40);