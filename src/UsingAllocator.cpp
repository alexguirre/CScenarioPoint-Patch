#include "UsingAllocator.h"
#include "Hooking.Patterns.h"
#include <intrin.h>

bool offsetsFound = false;
unsigned int tlsAllocatorOffset1, tlsAllocatorOffset2, tlsAllocatorOffset3;
void* allocator;

void FindOffsets()
{
	uintptr_t addr = (uintptr_t)hook::get_pattern("48 8B 14 C8 B8 ? ? ? ? 48 89 1C 10");
	tlsAllocatorOffset1 = *(unsigned int*)(addr + 23);
	tlsAllocatorOffset2 = *(unsigned int*)(addr + 14);
	tlsAllocatorOffset3 = *(unsigned int*)(addr + 5);

	addr = (uintptr_t)hook::get_pattern("48 8D 1D ? ? ? ? A8 08 75 1D 83 C8 08 48 8B CB 89 05", 3);
	addr = addr + *(int*)(addr) + 4;
	allocator = (void*)addr;

	offsetsFound = true;
}

UsingAllocator::UsingAllocator()
{
	if (!offsetsFound)
	{
		FindOffsets();
	}

	char* tls = *(char**)__readgsqword(0x58);
	m_Old1 = *(void**)(tls + tlsAllocatorOffset1);
	m_Old2 = *(void**)(tls + tlsAllocatorOffset2);
	m_Old3 = *(void**)(tls + tlsAllocatorOffset3);

	*(void**)(tls + tlsAllocatorOffset1) = allocator;
	*(void**)(tls + tlsAllocatorOffset2) = allocator;
	*(void**)(tls + tlsAllocatorOffset3) = allocator;
}


UsingAllocator::~UsingAllocator()
{
	char* tls = *(char**)__readgsqword(0x58);
	*(void**)(tls + tlsAllocatorOffset1) = m_Old1;
	*(void**)(tls + tlsAllocatorOffset2) = m_Old2;
	*(void**)(tls + tlsAllocatorOffset3) = m_Old3;
}