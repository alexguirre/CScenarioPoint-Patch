#pragma once
#include <stdint.h>

class CScenarioInfo
{
public:
	virtual bool GetIsClassId(uint32_t classId) = 0;
};