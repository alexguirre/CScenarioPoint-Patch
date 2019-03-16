#pragma once
#include <stdint.h>

template<typename T>
class atArray
{
public:
	T* Items;
	uint16_t Count;
	uint16_t Size;
	char pad[4];
};
