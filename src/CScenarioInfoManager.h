#pragma once
#include "atArray.h"
#include "CScenarioInfo.h"
#include "CScenarioTypeGroup.h"

class CScenarioInfoManager
{
public:
	void* vtable;
	atArray<CScenarioInfo*> Scenarios;
	atArray<CScenarioTypeGroup*> ScenarioTypeGroups;
	atArray<bool> ScenarioEnabledFlags;
	// ...
};