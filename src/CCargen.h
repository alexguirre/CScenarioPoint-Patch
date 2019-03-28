#pragma once
#include <stdint.h>

class CCargen
{
public:
	float Position[3];
	float Direction[2];
	char pad1[0x25];
	uint8_t ScenarioType;
	char pad2[0xE];
};

static_assert(sizeof(CCargen) == 0x48);