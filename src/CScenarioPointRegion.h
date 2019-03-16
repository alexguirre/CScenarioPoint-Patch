#pragma once
#include <stdint.h>
#include "CScenarioPoint.h"
#include "atArray.h"

class CScenarioPointRegion
{
public:
	struct sPoints
	{
		atArray<char> LoadSavePoints;
		atArray<CScenarioPoint> MyPoints;
	};

	struct sLookUps
	{
		atArray<uint32_t> TypeNames;
		atArray<uint32_t> PedModelSetNames;
		atArray<uint32_t> VehicleModelSetNames;
		atArray<uint32_t> GroupNames;
		atArray<uint32_t> InteriorNames;
		atArray<uint32_t> RequiredIMapNames;
	};

	int32_t VersionNumber;
	char field_4[0x4];
	sPoints Points;
	char field_28[0xF0];
	sLookUps LookUps;

};

static_assert(sizeof(CScenarioPointRegion::sPoints) == 0x20);
static_assert(sizeof(CScenarioPointRegion::sLookUps) == 0x60);
static_assert(sizeof(CScenarioPointRegion) == 0x178);