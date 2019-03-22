#pragma once
#include "CScenarioInfo.h"
#include "atArray.h"

class CScenarioTypeGroupEntry
{
public:
	CScenarioInfo* ScenarioType;
	uint32_t ScenarioTypeIndex;
	float ProbabilityWeight;
};
static_assert(sizeof(CScenarioTypeGroupEntry) == 0x10);

class CScenarioTypeGroup
{
public:
	uint32_t Name;
	uint32_t pad;
	atArray<CScenarioTypeGroupEntry> Types;
};
static_assert(sizeof(CScenarioTypeGroup) == 0x18);