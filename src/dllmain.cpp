#include <Windows.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include "Hooking.Patterns.h"
#include "Hooking.h"
#include "CScenarioPoint.h"
#include "CScenarioPointRegion.h"
#include <MinHook.h>
#include <filesystem>
#include <iterator>
#include <chrono>

#if _DEBUG
static constexpr bool DefaultEnableLogging = true;
#else
static constexpr bool DefaultEnableLogging = false;
#endif

static bool LoggingEnabled()
{
	static bool b = []()
	{
		char iniFilePath[MAX_PATH];
		GetFullPathName("CScenarioPoint-Patch.ini", MAX_PATH, iniFilePath, nullptr);
		int v = GetPrivateProfileInt("Config", "Log", 0, iniFilePath);
		return v != 0;
	}();
	return DefaultEnableLogging || b;
}

using IsScenarioVehicleInfo_fn = bool(*)(uint32_t index);
using CAmbientModelSetsManager_FindIndexByHash_fn = uint32_t(*)(void* mgr, int type, uint32_t hash);
static IsScenarioVehicleInfo_fn IsScenarioVehicleInfo;
static CAmbientModelSetsManager_FindIndexByHash_fn CAmbientModelSetsManager_FindIndexByHash;

static void FindGameFunctions()
{
	IsScenarioVehicleInfo = (IsScenarioVehicleInfo_fn)hook::pattern("48 83 EC 28 48 8B 15 ? ? ? ? 0F B7 42 10 3B C8 7D 2A").get(1).get<void>();
	CAmbientModelSetsManager_FindIndexByHash = (CAmbientModelSetsManager_FindIndexByHash_fn)hook::get_pattern("44 89 44 24 ? 48 83 EC 28 48 63 C2 48 8D 14 80");
}

static void** g_AmbientModelSetsMgr;

static void FindGameVariables()
{
	g_AmbientModelSetsMgr = hook::get_address<void**>(hook::get_pattern("48 8B 0D ? ? ? ? E8 ? ? ? ? 83 F8 FF 75 07", 3));
}

template<int FramesToSkip = 1>
static void LogStackTrace()
{
	if (!LoggingEnabled())
	{
		return;
	}

	void* stack[32];
	USHORT frames = CaptureStackBackTrace(FramesToSkip, 32, stack, NULL);

	spdlog::warn("\tStack Trace:");
	for (int i = 0; i < frames; i++)
	{
		void* address = stack[i];
		HMODULE module = NULL;
		GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)address, &module);
		char moduleName[256];
		GetModuleFileName(module, moduleName, 256);

		spdlog::warn("\t\t{:16X} - {}+{:08X}", (uintptr_t)address, std::filesystem::path(moduleName).filename().string().c_str(), ((uintptr_t)address - (uintptr_t)module));
	}
}

/// The CScenarioPoint offset where we are going to store the ModelSetId as uint16,
/// 2 bytes (which previously were padding) instead of 1 byte.
constexpr ptrdiff_t Offset_ModelSetId{ offsetof(CScenarioPoint, padding_22) };
static_assert(Offset_ModelSetId < 0xFF);

constexpr uint16_t InvalidModelSetId{ 0xFFFF };

/// The CScenarioPoint offsets where we are going to store the iType as uint16,
/// the low byte in the original offset and the high byte in 1 byte of padding.
constexpr ptrdiff_t Offset_iTypeLo{ offsetof(CScenarioPoint, iType) };
constexpr ptrdiff_t Offset_iTypeHi{ offsetof(CScenarioPoint, padding_1F) };
static_assert(Offset_iTypeLo < 0xFF);
static_assert(Offset_iTypeHi < 0xFF);

constexpr uint16_t InvalidScenarioType{ 0xFFFF };

static void SetPointModelSet(CScenarioPoint* point, uint16_t modelSetId)
{
	*reinterpret_cast<uint16_t*>(reinterpret_cast<char*>(point)  + Offset_ModelSetId) = modelSetId;
}

static uint16_t GetPointModelSet(CScenarioPoint* point)
{
	return *reinterpret_cast<uint16_t*>(reinterpret_cast<char*>(point) + Offset_ModelSetId);
}

static void CheckPointModelSet(CScenarioPoint* point, uint32_t modelSetId)
{
	if (modelSetId > 0xFFFF)
	{
		spdlog::warn("Scenario Point (addr:{}; X:{:.2f},Y:{:.2f},Z:{:.2f}) with ModelSetId (ID:{}) > 0xFFFF",
			reinterpret_cast<void*>(point),
			point->vPositionAndDirection[0], point->vPositionAndDirection[1], point->vPositionAndDirection[2],
			modelSetId);
		LogStackTrace();
	}
}

static void SetPointScenarioType(CScenarioPoint* point, uint16_t type)
{
	*reinterpret_cast<uint8_t*>(reinterpret_cast<char*>(point) + Offset_iTypeLo) = type & 0xFF;
	*reinterpret_cast<uint8_t*>(reinterpret_cast<char*>(point) + Offset_iTypeHi) = type >> 8;
}

static uint16_t GetPointScenarioType(CScenarioPoint* point)
{
	const uint16_t lo = *reinterpret_cast<uint8_t*>(reinterpret_cast<char*>(point) + Offset_iTypeLo);
	const uint16_t hi = *reinterpret_cast<uint8_t*>(reinterpret_cast<char*>(point) + Offset_iTypeHi);
	return (hi << 8) | lo;
}

static void CheckPointScenarioType(CScenarioPoint* point, uint32_t type)
{
	if (type > 0xFFFF)
	{
		spdlog::warn("Scenario Point (addr:{}; X:{:.2f},Y:{:.2f},Z:{:.2f}) with iType (ID:{}) > 0xFFFF",
			reinterpret_cast<void*>(point),
			point->vPositionAndDirection[0], point->vPositionAndDirection[1], point->vPositionAndDirection[2],
			type);
		LogStackTrace();
	}
}

static void Patch1()
{
	spdlog::info(__func__);

	// CScenarioPointRegion::LookUps::ConvertHashesToIndices
	hook::put<uint32_t>(hook::get_pattern("41 BD ? ? ? ? 85 ED 7E 51 4C 8B F3", 2), InvalidModelSetId);
}

static void(*CScenarioPoint_TransformIdsToIndices_orig)(CScenarioPointRegion::sLookUps*, CScenarioPoint*);
static void CScenarioPoint_TransformIdsToIndices_detour(CScenarioPointRegion::sLookUps* indicesLookups, CScenarioPoint* point)
{
	const uint32_t scenarioIndex = indicesLookups->TypeNames.Items[point->iType];
	CheckPointScenarioType(point, scenarioIndex);

	const atArray<uint32_t>* modelSetNames = IsScenarioVehicleInfo(scenarioIndex) ?
		&indicesLookups->VehicleModelSetNames :
		&indicesLookups->PedModelSetNames;

	const uint32_t modelSet = modelSetNames->Items[point->ModelSetId];
	CheckPointModelSet(point, modelSet);

	CScenarioPoint_TransformIdsToIndices_orig(indicesLookups, point);

	SetPointScenarioType(point, scenarioIndex);
	SetPointModelSet(point, modelSet);
}

static void Patch2()
{
	spdlog::info(__func__);

	// CScenarioPoint::TransformIdsToIndices
	MH_CreateHook(hook::get_pattern("48 83 EC 20 44 0F B7 42 ? 0F B6 42 15", -0xB), CScenarioPoint_TransformIdsToIndices_detour, (void**)&CScenarioPoint_TransformIdsToIndices_orig);
}

static void Patch3()
{
	spdlog::info(__func__);

	// CScenarioInfoManager::IsValidModelSet
	hook::put(hook::get_pattern("81 FF ? ? ? ? 74 6F 48 8B 05", 2), InvalidModelSetId);
}

static void Patch4()
{
	spdlog::info(__func__);

	// CScenarioPoint::CanScenarioSpawn
	auto loc = hook::get_pattern<uint8_t>("0F B6 51 16 EB 05 BA");

	/*
	movzx   edx, byte ptr [rcx+16h]                 0F B6 51 16
		|
		v
	movzx   edx, word ptr [rcx+Offset_ModelSetId]    0F B7 51 offset
	*/
	hook::put<uint8_t>(loc + 1, 0xB7);
	hook::put<uint8_t>(loc + 3, Offset_ModelSetId);

	/*
	mov     edx, 0FFh                               BA FF 00 00 00
		|
		v
	mov     edx, InvalidModelSetId                  BA nn nn nn nn
	*/
	hook::put<uint32_t>(loc + 7, InvalidModelSetId);
}

static void Patch5()
{
	spdlog::info(__func__);

	// bool GetAndLoadScenarioPointModel(__int64 rcx0, signed int scenarioIndex, CScenarioPoint *point, __int64 a4, ...)
	
	auto loc = hook::get_pattern<uint8_t>("41 BF ? ? ? ? FF 10 84 C0 75 05 45 0F B6 7E ?");

	/*
	mov     r15d, 0FFh                              41 BF FF 00 00 00
		|
		v
	mov     r15d, InvalidModelSetId                 41 BF nn nn nn nn
	*/
	hook::put<uint32_t>(loc + 2, InvalidModelSetId);

	/*
	movzx   r15d, byte ptr [r14+16h]                45 0F B6 7E 16
		|
		v
	movzx   r15d, word ptr [r14+Offset_ModelSetId]   45 0F B7 7E offset
	*/
	hook::put<uint8_t>(loc + 12 + 2, 0xB7);
	hook::put<uint8_t>(loc + 12 + 4, Offset_ModelSetId);

	/*
	cmp     r15d, 0FFh                              41 81 FF FF 00 00 00
		|
		v
	cmp     r15d, InvalidModelSetId                 41 81 FF nn nn nn nn
	*/
	hook::put<uint32_t>(loc + 0x5F + 3, InvalidModelSetId);
}

static void Patch7()
{
	spdlog::info(__func__);

	auto loc = hook::get_pattern<uint8_t>("0F B6 47 16 3D ? ? ? ? 74 13 8B D0 48 8B 05");

	/*
	movzx   eax, byte ptr [rdi+16h]                 0F B6 47 16
		|
		v
	movzx   eax, word ptr [rdi+Offset_ModelSetId]    0F B7 47 offset
	*/
	hook::put<uint8_t>(loc + 1, 0xB7);
	hook::put<uint8_t>(loc + 3, Offset_ModelSetId);

	/*
	cmp     eax, 0FFh                               3D FF 00 00 00
		|
		v
	cmp     eax, InvalidModelSetId                  3D nn nn nn nn
	*/
	hook::put<uint32_t>(loc + 4 + 1, InvalidModelSetId);
}

static uint32_t GetFinalModelSetHash(uint32_t hash)
{
	constexpr uint32_t any_hash = 0xDF3407B5;
	constexpr uint32_t usepopulation_hash = 0xA7548A2;

	return hash == any_hash ? usepopulation_hash : hash;
}

static bool(*CScenarioPoint_SetModelSet_orig)(CScenarioPoint* This, const uint32_t* modelSetHash, bool isVehicle);
static bool CScenarioPoint_SetModelSet_detour(CScenarioPoint* This, const uint32_t* modelSetHash, bool isVehicle)
{
	constexpr uint32_t usepopulation_hash = 0xA7548A2;

	bool result = true;
	uint16_t modelSetId = InvalidModelSetId;

	if (*modelSetHash != usepopulation_hash)
	{
		const uint32_t modelSetIndex = CAmbientModelSetsManager_FindIndexByHash(*g_AmbientModelSetsMgr, isVehicle ? 2 : 0, *modelSetHash);
		if (modelSetIndex == 0xFFFFFFFF)
		{
			result = false;
		}
		else
		{
			CheckPointModelSet(This, modelSetIndex);
			modelSetId = static_cast<uint16_t>(modelSetIndex);
		}
	}

	This->ModelSetId = static_cast<uint8_t>(modelSetId);
	SetPointModelSet(This, modelSetId);

	return result;
}

static void Patch8()
{
	spdlog::info(__func__);

	// CScenarioPoint::SetModelSet
	MH_CreateHook(hook::get_pattern("48 89 5C 24 ? 57 48 83 EC 20 C6 41 16 ?"), CScenarioPoint_SetModelSet_detour, (void**)&CScenarioPoint_SetModelSet_orig);
}

static void Patch24()
{
	spdlog::info(__func__);

	// CScenarioPoint::TryCreateCargen + sub_C1C6E8
	hook::pattern pattern("0F B6 53 16 48 8B CE E8 ? ? ? ?");
	pattern.count(2);
	pattern.for_each_result([](const hook::pattern_match& match)
	{
		auto loc = match.get<uint8_t>();

		/*
		movzx   edx, byte ptr [rbx+16h]                 0F B6 53 16
			|
			v
		movzx   edx, word ptr [rbx+Offset_ModelSetId]    0F B7 53 offset
		*/
		hook::put<uint8_t>(loc + 1, 0xB7);
		hook::put<uint8_t>(loc + 3, Offset_ModelSetId);
	});
}

static void Patch25()
{
	spdlog::info(__func__);

	hook::pattern pattern("81 FA ? ? ? ? 74 14 48 8B 05");
	pattern.count(2);
	pattern.for_each_result([](const hook::pattern_match& match)
	{
		auto loc = match.get<uint8_t>();

		/*
		cmp     edx, 0FFh                               81 FA FF 00 00 00
			|
			v
		cmp     edx, InvalidModelSetId                  81 FA nn nn nn nn
		*/
		hook::put<uint32_t>(loc + 2, InvalidModelSetId);
	});
}

static void Patch33()
{
	spdlog::info(__func__);

	// sub_C110EC
	auto loc = hook::get_pattern<uint8_t>("41 0F B6 45 ? 4C 89 65 AF 3D ? ? ? ?");

	/*
	movzx   eax, byte ptr [r13+16h]                 41 0F B6 45 16
		|
		v
	movzx   eax, word ptr [r13+Offset_ModelSetId]    41 0F B7 45 offset
	*/
	hook::put<uint8_t>(loc + 2, 0xB7);
	hook::put<uint8_t>(loc + 4, Offset_ModelSetId);

	/*
	cmp     eax, 0FFh                               3D FF 00 00 00
		|
		v
	cmp     eax, InvalidModelSetId                  3D nn nn nn nn
	*/
	hook::put<uint32_t>(loc + 9 + 1, InvalidModelSetId);
}

static void Patch49()
{
	spdlog::info(__func__);
	
	// sub_BF38F4
	auto loc = hook::get_pattern<uint8_t>("41 80 7E ? ? 45 0F B6 E4 B8 ? ? ? ?");
	
	/*
	cmp     byte ptr [r14+16h], 0FFh                   41 80 7E 16 FF
	movzx   r12d, r12b                                 45 0F B6 E4    ; this instruction seems redundant as afterwards only r12b is read,
	                                                                  ; so we can overwrite it and nop the remaining bytes
		|
		v
	cmp     word ptr [r14+Offset_ModelSetId], 0FFFFh   66 41 83 7E offset FF
	nop                                                90
	nop                                                90
	nop                                                90
	*/
	const uint8_t patch[9]
	{
		0x66, 0x41, 0x83, 0x7E, Offset_ModelSetId, 0xFF,
		0x90, 0x90, 0x90
	};
	memcpy(loc, patch, std::size(patch));
}

static void Patch50()
{
	spdlog::info(__func__);

	// CScenarioPoint::GetScenarioType
	auto loc = hook::get_pattern<uint8_t>("0F B7 41 10 0F B6 49 15 C1 E8 0E");

	/*
	movzx   eax, word ptr [rcx+10h]                    0F B7 41 10
	movzx   ecx, byte ptr [rcx+15h]                    0F B6 49 15
	shr     eax, 0Eh                                   C1 E8 0E
	and     eax, 1                                     83 E0 01
	shl     eax, 8                                     C1 E0 08
	or      eax, ecx                                   0B C1
	retn                                               C3
		|
		v
	movzx   eax, byte ptr [rcx+Offset_iTypeLo]         0F B6 41 offset
	movzx   ecx, byte ptr [rcx+Offset_iTypeHi]         0F B6 49 offset
	shl     ecx, 8                                     C1 E1 08
	or      eax, ecx                                   0B C1
	retn                                               C3
	*/
	const uint8_t patch[14]
	{
		0x0F, 0xB6, 0x41, Offset_iTypeLo,
		0x0F, 0xB6, 0x49, Offset_iTypeHi,
		0xC1, 0xE1, 0x08,
		0x0B, 0xC1,
		0xC3,
	};
	memcpy(loc, patch, std::size(patch));
}

static void Patch51()
{
	spdlog::info(__func__);

	// CScenarioPoint::InitFromSpawnPointDef
	auto loc = hook::get_pattern<uint8_t>("8B C6 40 88 73 15 C1 E8 08");

	/*
	esi = scenario type index
	rbx = CScenarioPoint*

	mov     eax, esi                                   8B C6
	mov     [rbx+15h], sil                             40 88 73 15
	shr     eax, 8                                     C1 E8 08
	and     ax, 1                                      66 83 E0 01
	shl     ax, 0Eh                                    66 C1 E0 0E
	or      [rbx+10h], ax                              66 09 43 10
		|
		v
	mov     [rbx+Offset_iTypeLo], sil                  40 88 73 offset
	shr     esi, 8                                     C1 EE 08
	mov     [rbx+Offset_iTypeHi], sil                  40 88 73 offset
	*/
	const uint8_t patch[11]
	{
		0x40, 0x88, 0x73, Offset_iTypeLo,
		0xC1, 0xEE, 0x08,
		0x40, 0x88, 0x73, Offset_iTypeHi,
	};
	hook::patch_and_nop_remaining<21>(loc, patch);
}

static void Patch52()
{
	spdlog::info(__func__);

	// CSpawnPointOverrideExtension::OverrideScenarioPoint

	/*
	eax = scenario type index
	rbx = CScenarioPoint*

	mov     ecx, eax                                   8B C8      
	mov     [rbx+15h], al                              88 43 15   
	shr     ecx, 8                                     C1 E9 08   
	and     cx, bp                                     66 23 CD   
	shl     cx, 0Eh                                    66 C1 E1 0E
	or      [rbx+10h], cx                              66 09 4B 10
		|
		v
	mov     [rbx+Offset_iTypeLo], al                   88 43 offset
	shr     eax, 8                                     C1 E8 08
	mov     [rbx+Offset_iTypeHi], al                   88 43 offset
	*/
	{
		auto loc = hook::get_pattern<uint8_t>("8B C8 88 43 15 C1 E9 08");
		const uint8_t patch[9]
		{
			0x88, 0x43, Offset_iTypeLo,
			0xC1, 0xE8, 0x08,
			0x88, 0x43, Offset_iTypeHi,
		};
		hook::patch_and_nop_remaining<19>(loc, patch);
	}

	/*
	movzx   ecx, word ptr [rbx+10h]                    0F B7 4B 10
	movzx   edx, byte ptr [rbx+15h]                    0F B6 53 15
	shr     ecx, 0Eh                                   C1 E9 0E
	mov     [rsp+28h+a2], eax                          89 44 24 30
	and     ecx, ebp                                   23 CD
	shl     ecx, 8                                     C1 E1 08
	or      ecx, edx                                   0B CA
		|
		v
	movzx   ecx, byte ptr [rbx+Offset_iTypeLo]         0F B6 4B offset
	movzx   edx, byte ptr [rbx+Offset_iTypeHi]         0F B6 53 offset
	shl     edx, 8                                     C1 E2 08
	or      ecx, edx                                   0B CA
	mov     [rsp+28h+a2], eax                          89 44 24 30
	*/
	{
		auto loc = hook::get_pattern<uint8_t>("0F B7 4B 10 0F B6 53 15 C1 E9 0E");
		const uint8_t patch[17]
		{
			0x0F, 0xB6, 0x4B, Offset_iTypeLo,
			0x0F, 0xB6, 0x53, Offset_iTypeHi,
			0xC1, 0xE2, 0x08,
			0x0B, 0xCA,
			0x89, 0x44, 0x24, 0x30,
		};
		hook::patch_and_nop_remaining<22>(loc, patch);
	}
}

static void Patch53()
{
	spdlog::info(__func__);

	// CScenarioPoint::ctorWithEntity
	auto loc = hook::get_pattern<uint8_t>("81 E1 ? ? ? ? 88 4B 15 8B C1");

	/*
	ecx = scenario type index
	rbx = CScenarioPoint*

	and     ecx, 1FFh                                  81 E1 FF 01 00 00
	mov     [rbx+15h], cl                              88 4B 15
	mov     eax, ecx                                   8B C1
	shr     eax, 8                                     C1 E8 08
	shl     ax, 0Eh                                    66 C1 E0 0E
	xor     ax, dx                                     66 33 C2
	and     ax, r8w                                    66 41 23 C0
	xor     ax, dx                                     66 33 C2
	mov     [rbx+10h], ax                              66 89 43 10
		|
		v
	mov     [rbx+Offset_iTypeLo], cl                   88 4B offset
	shr     ecx, 8                                     C1 E9 08
	mov     [rbx+Offset_iTypeHi], cl                   88 4B offset
	*/
	const uint8_t patch[9]
	{
		0x88, 0x4B, Offset_iTypeLo,
		0xC1, 0xE9, 0x08,
		0x88, 0x4B, Offset_iTypeHi,
	};
	hook::patch_and_nop_remaining<32>(loc, patch);
}

static void Patch54()
{
	spdlog::info(__func__);

	// CSpawnPoint::InitFromDef
	auto loc = hook::get_pattern<uint8_t>("66 21 4F 24 B9 ? ? ? ? 66 23 C1");

	/*
	eax = scenario type index
	rdi = CSpawnPoint*

	and     [rdi+24h], cx                              66 21 4F 24   
	mov     ecx, 1FFh                                  B9 FF 01 00 00
	and     ax, cx                                     66 23 C1      
	or      [rdi+24h], ax                              66 09 47 24   
		|
		v
	mov     [rdi+24h], ax                              66 89 47 24
	*/
	const uint8_t patch[4]
	{
		0x66, 0x89, 0x47, 0x24,
	};
	hook::patch_and_nop_remaining<16>(loc, patch);
}

static void Patch55()
{
	spdlog::info(__func__);

	// CCargen::Initialize
	auto loc = hook::get_pattern<uint8_t>("66 21 43 3A 0F B7 85 ? ? ? ?");

	/*
	and     [rbx+3Ah], ax                              66 21 43 3A
	movzx   eax, [rbp+arg_88]                          0F B7 85 A8 00 00 00
	and     ax, cx                                     66 23 C1
	or      [rbx+3Ah], ax                              66 09 43 3A
		|
		v
	movzx   eax, [rbp+arg_88]                          0F B7 85 A8 00 00 00
	mov     [rbx+3Ah], ax                              66 89 43 3A
	*/
	const uint8_t patch[11]
	{
		0x0F, 0xB7, 0x85, 0xA8, 0x00, 0x00, 0x00,
		0x66, 0x89, 0x43, 0x3A,
	};
	hook::patch_and_nop_remaining<18>(loc, patch);
}

static void Patch56()
{
	spdlog::info(__func__);

	// CreateCargen
	auto loc = hook::get_pattern<uint8_t>("81 FD ? ? ? ? 41 0F 95 C6 45 84 F6");

	/*
	cmp     ebp, 0FFh                                  81 FD FF 00 00 00
		|
		v
	cmp     ebp, InvalidScenarioType                   81 FD nn nn nn nn
	*/
	hook::put<uint32_t>(loc + 2, InvalidScenarioType);
}

static void Patch57()
{
	spdlog::info(__func__);

	// call to CreateCargen with invalid scenario type
	auto loc = hook::get_pattern<uint8_t>("C7 84 24 ? ? ? ? ? ? ? ? 83 A4 24 ? ? ? ? ? C6 44 24 ? ?");

	/*
	mov     [rsp+128h+var_A0], 0FFh                    C7 84 24 88 00 00 00 FF 00 00 00
		|
		v
	mov     [rsp+128h+var_A0], InvalidScenarioType     C7 84 24 88 00 00 00 nn nn nn nn
	*/
	hook::put<uint32_t>(loc + 7, InvalidScenarioType);
}

static void Patch58()
{
	spdlog::info(__func__);

	// call to CreateCargen with invalid scenario type
	auto loc = hook::get_pattern<uint8_t>("C7 84 24 ? ? ? ? ? ? ? ? C1 E9 1C 89 8C 24 ? ? ? ?");

	/*
	mov     [rsp+0D8h+var_50], 0FFh                    C7 84 24 88 00 00 00 FF 00 00 00
		|
		v
	mov     [rsp+0D8h+var_50], InvalidScenarioType     C7 84 24 88 00 00 00 nn nn nn nn
	*/
	hook::put<uint32_t>(loc + 7, InvalidScenarioType);
}

static void Patch59()
{
	spdlog::info(__func__);

	// access to CCargen::ScenarioType
	auto loc = hook::get_pattern<uint8_t>("81 E6 ? ? ? ? 8B CE");

	/*
	and     esi, 1FFh                                  81 E6 FF 01 00 00
		|
		v
	and     esi, FFFFh                                 81 E6 FF FF 00 00
	*/
	hook::put<uint8_t>(loc + 3, 0xFF);
}

static void Patch60()
{
	spdlog::info(__func__);

	// access to CCargen::ScenarioType
	auto loc = hook::get_pattern<uint8_t>("81 E7 ? ? ? ? E8 ? ? ? ? 84 C0");

	/*
	and     edi, 1FFh                                  81 E7 FF 01 00 00
		|
		v
	and     edi, FFFFh                                 81 E7 FF FF 00 00
	*/
	hook::put<uint8_t>(loc + 3, 0xFF);
}

static void Patch61()
{
	spdlog::info(__func__);

	// access to CCargen::ScenarioType
	auto loc = hook::get_pattern<uint8_t>("41 81 E5 ? ? ? ? 41 8B CD 44 89 6D D7");

	/*
	and     r13d, 1FFh                                 41 81 E5 FF 01 00 00
		|
		v
	and     r13d, FFFFh                                41 81 E5 FF FF 00 00
	*/
	hook::put<uint8_t>(loc + 4, 0xFF);
}

static void Patch62()
{
	spdlog::info(__func__);

	// access to CCargen::ScenarioType
	auto loc = hook::get_pattern<uint8_t>("41 81 E1 ? ? ? ? 7C 1B 4C 8B 15");

	/*
	and     r9d, 1FFh                                  41 81 E1 FF 01 00 00
		|
		v
	and     r9d, FFFFh                                 41 81 E1 FF FF 00 00
	*/
	hook::put<uint8_t>(loc + 4, 0xFF);
}

static void Patch63()
{
	spdlog::info(__func__);

	// access to CCargen::ScenarioType
	hook::pattern pattern("41 B8 ? ? ? ? 0F B7 42 3A 66 41 23 C0 41 B8 ? ? ? ?");
	pattern.count(2).for_each_result([](const hook::pattern_match& match)
	{
		auto loc = match.get<uint8_t>();

		/*
		mov     r8d, 1FFh                              41 B8 FF 01 00 00
		movzx   eax, word ptr [rdx+3Ah]                0F B7 42 3A
		and     ax, r8w                                66 41 23 C0
		mov     r8d, 0FFh                              41 B8 FF 00 00 00
			|
			v
		mov     r8d, FFFFh                             41 B8 FF FF 00 00
		movzx   eax, word ptr [rdx+3Ah]                0F B7 42 3A
		and     ax, r8w                                66 41 23 C0
		mov     r8d, InvalidScenarioType               41 B8 nn nn nn nn
		*/
		hook::put<uint8_t>(loc + 3, 0xFF);
		hook::put<uint32_t>(loc + 14 + 2, InvalidScenarioType);
	});
}

static void Patch64()
{
	spdlog::info(__func__);

	// access to CCargen::ScenarioType
	hook::pattern pattern("B9 FF 01 00 00 66 23 C1 B9 FF 00 00 00");
	pattern.count(10).for_each_result([](const hook::pattern_match& match)
	{
		auto loc = match.get<uint8_t>();

		/*
		mov     ecx, 1FFh                              B9 FF 01 00 00
		and     ax, cx                                 66 23 C1
		mov     ecx, 0FFh                              B9 FF 00 00 00
			|
			v
		mov     ecx, FFFFh                             B9 FF FF 00 00
		and     ax, cx                                 66 23 C1
		mov     ecx, InvalidScenarioType               B9 nn nn nn nn
		*/
		hook::put<uint8_t>(loc + 2, 0xFF);
		hook::put<uint32_t>(loc + 8 + 1, InvalidScenarioType);
	});
}

static void Patch65()
{
	spdlog::info(__func__);

	// access to CCargen::ScenarioType
	hook::pattern pattern("BA FF 01 00 00 0F B7 41 3A 66 23 C2 BA FF 00 00 00");
	pattern.count(2).for_each_result([](const hook::pattern_match& match)
	{
		auto loc = match.get<uint8_t>();

		/*
		mov     edx, 1FFh                              BA FF 01 00 00
		movzx   eax, word ptr [rcx+3Ah]                0F B7 41 3A
		and     ax, dx                                 66 23 C2
		mov     edx, 0FFh                              BA FF 00 00 00
			|
			v
		mov     edx, FFFFh                             BA FF FF 00 00
		movzx   eax, word ptr [rcx+3Ah]                0F B7 41 3A
		and     ax, dx                                 66 23 C2
		mov     edx, InvalidScenarioType               BA nn nn nn nn
		*/
		hook::put<uint8_t>(loc + 2, 0xFF);
		hook::put<uint32_t>(loc + 12 + 1, InvalidScenarioType);
	});
}

static void Patch66()
{
	spdlog::info(__func__);

	// access to CCargen::ScenarioType
	hook::pattern pattern("BA FF 01 00 00 66 23 C2 BA FF 00 00 00");
	pattern.count(4).for_each_result([](const hook::pattern_match& match)
	{
		auto loc = match.get<uint8_t>();

		/*
		mov     edx, 1FFh                              BA FF 01 00 00
		and     ax, dx                                 66 23 C2
		mov     edx, 0FFh                              BA FF 00 00 00
			|
			v
		mov     edx, FFFFh                             BA FF FF 00 00
		and     ax, dx                                 66 23 C2
		mov     edx, InvalidScenarioType               BA nn nn nn nn
		*/
		hook::put<uint8_t>(loc + 2, 0xFF);
		hook::put<uint32_t>(loc + 8 + 1, InvalidScenarioType);
	});
}

static void Patch67()
{
	spdlog::info(__func__);

	// access to CCargen::ScenarioType
	auto loc = hook::get_pattern<uint8_t>("B9 FF 01 00 00 F3 0F 10 47 ? F3 0F 10 4F ?");

	/*
	mov     ecx, 1FFh                                  B9 FF 01 00 00
	      ... +0x86 bytes
	and     ax, cx                                     66 23 C1
	mov     ecx, 0FFh                                  B9 FF 00 00 00
		|
		v
	mov     ecx, FFFFh                                 B9 FF FF 00 00
	      ... +0x86 bytes
	and     ax, cx                                     66 23 C1
	mov     ecx, InvalidScenarioType                   B9 nn nn nn nn
	*/
	hook::put<uint8_t>(loc + 2, 0xFF);
	hook::put<uint32_t>(loc + 5 + 0x86 + 3 + 1, InvalidScenarioType);
}

static void Patch68()
{
	spdlog::info(__func__);

	// three accesses to CCargen::ScenarioType

	auto loc1 = hook::get_pattern<uint8_t>("41 B9 FF 01 00 00 BA FF 00 00 00 75 6E");
	/*
	mov     r9d, 1FFh                                  41 B9 FF 01 00 00
	mov     edx, 0FFh                                  BA FF 00 00 00
		|
		v
	mov     r9d, FFFFh                                 41 B9 FF FF 00 00
	mov     edx, InvalidScenarioType                   BA nn nn nn nn
	*/
	hook::put<uint8_t>(loc1 + 3, 0xFF);
	hook::put<uint32_t>(loc1 + 6 + 1, InvalidScenarioType);

	auto loc2 = hook::get_pattern<uint8_t>("41 BE FF 00 00 00 48 8B CF E8 ? ? ? ?");
	/*
	mov     r14d, 0FFh                                 41 BE FF 00 00 00
		|
		v
	mov     r14d, InvalidScenarioType                  41 BE nn nn nn nn
	*/
	hook::put<uint32_t>(loc2 + 2, InvalidScenarioType);

	auto loc3 = hook::get_pattern<uint8_t>("B9 FF 01 00 00 66 23 C1 66 41 3B C6 ");
	/*
	mov     ecx, 1FFh                                  B9 FF 01 00 00
		|
		v
	mov     ecx, FFFFh                                 B9 FF FF 00 00
	*/
	hook::put<uint8_t>(loc3 + 2, 0xFF);
}

static void Patch69()
{
	spdlog::info(__func__);

	// access to CCargen::ScenarioType
	auto loc = hook::get_pattern<uint8_t>("81 E1 FF 01 00 00 7D 04 33 C0");

	/*
	and     ecx, 1FFh                                  81 E1 FF 01 00 00
		|
		v
	and     ecx, FFFFh                                 81 E1 FF FF 00 00
	*/
	hook::put<uint8_t>(loc + 3, 0xFF);
}

static void Patch70()
{
	spdlog::info(__func__);

	// two accesses to CCargen::ScenarioType

	auto loc1 = hook::get_pattern<uint8_t>("B9 FF 01 00 00 4C 8B F2 41 8B DD 66 23 C1 B9 FF 00 00 00");
	/*
	mov     ecx, 1FFh                                  B9 FF 01 00 00
	mov     r14, rdx                                   4C 8B F2
	mov     ebx, r13d                                  41 8B DD
	and     ax, cx                                     66 23 C1
	mov     ecx, 0FFh                                  B9 FF 00 00 00
		|
		v
	mov     ecx, FFFFh                                 B9 FF FF 00 00
	mov     r14, rdx                                   4C 8B F2
	mov     ebx, r13d                                  41 8B DD
	and     ax, cx                                     66 23 C1
	mov     ecx, InvalidScenarioType                   B9 nn nn nn nn
	*/
	hook::put<uint8_t>(loc1 + 2, 0xFF);
	hook::put<uint32_t>(loc1 + 14 + 1, InvalidScenarioType);

	auto loc2 = hook::get_pattern<uint8_t>("B8 FF 01 00 00 66 23 C8 B8 FF 00 00 00");
	/*
	mov     eax, 1FFh                                  B8 FF 01 00 00
	and     cx, ax                                     66 23 C8      
	mov     eax, 0FFh                                  B8 FF 00 00 00
		|
		v
	mov     eax, FFFFh                                 B8 FF FF 00 00
	and     cx, ax                                     66 23 C8      
	mov     eax, InvalidScenarioType                   B8 nn nn nn nn
	*/
	hook::put<uint8_t>(loc2 + 2, 0xFF);
	hook::put<uint32_t>(loc2 + 8 + 1, InvalidScenarioType);
}

static void Patch71()
{
	spdlog::info(__func__);

	// two accesses to CCargen::ScenarioType

	auto loc1 = hook::get_pattern<uint8_t>("B8 FF 01 00 00 4C 89 6D E7 66 23 C8 B8 FF 00 00 00");
	/*
	mov     eax, 1FFh                                  B8 FF 01 00 00
	mov     [rbp+8Fh+var_A8], r13                      4C 89 6D E7
	and     cx, ax                                     66 23 C8
	mov     eax, 0FFh                                  B8 FF 00 00 00
		|
		v
	mov     eax, FFFFh                                 B8 FF FF 00 00
	mov     [rbp+8Fh+var_A8], r13                      4C 89 6D E7
	and     cx, ax                                     66 23 C8
	mov     eax, InvalidScenarioType                   B8 nn nn nn nn
	*/
	hook::put<uint8_t>(loc1 + 2, 0xFF);
	hook::put<uint32_t>(loc1 + 12 + 1, InvalidScenarioType);

	auto loc2 = hook::get_pattern<uint8_t>("BF FF 00 00 00 49 8B 46 48 F3 0F 10 00");
	/*
	mov     edi, 0FFh                                  BF FF 00 00 00
		|
		v
	mov     edi, InvalidScenarioType                   BF nn nn nn nn
	*/
	hook::put<uint32_t>(loc2 + 1, InvalidScenarioType);

	auto loc3 = hook::get_pattern<uint8_t>("B9 FF 01 00 00 0F B7 42 3A 66 23 C1");
	/*
	mov     ecx, 1FFh                                  B9 FF 01 00 00
		|
		v
	mov     ecx, FFFFh                                 B9 FF FF 00 00
	*/
	hook::put<uint8_t>(loc3 + 2, 0xFF);
}

static void Patch72()
{
	spdlog::info(__func__);

	// three accesses to CCargen::ScenarioType

	auto loc1 = hook::get_pattern<uint8_t>("B9 FF 01 00 00 BA FF 00 00 00 74 28");
	/*
	mov     ecx, 1FFh                                  B9 FF 01 00 00
	mov     edx, 0FFh                                  BA FF 00 00 00
		|
		v
	mov     ecx, FFFFh                                 B9 FF FF 00 00
	mov     edx, InvalidScenarioType                   BA nn nn nn nn
	*/
	hook::put<uint8_t>(loc1 + 2, 0xFF);
	hook::put<uint32_t>(loc1 + 5 + 1, InvalidScenarioType);

	auto loc2 = hook::get_pattern<uint8_t>("B9 FF 01 00 00 BA FF 00 00 00 66 23 C1");
	/*
	mov     ecx, 1FFh                                  B9 FF 01 00 00
	mov     edx, 0FFh                                  BA FF 00 00 00
		|
		v
	mov     ecx, FFFFh                                 B9 FF FF 00 00
	mov     edx, InvalidScenarioType                   BA nn nn nn nn
	*/
	hook::put<uint8_t>(loc2 + 2, 0xFF);
	hook::put<uint32_t>(loc2 + 5 + 1, InvalidScenarioType);
}

static void Patch73()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType
	auto loc = hook::get_pattern<uint8_t>("0F B6 43 15 0F B7 4B 10 48 8B 15 ? ? ? ?");

	/*
	movzx   eax, byte ptr [rbx+15h]       0F B6 43 15
	movzx   ecx, word ptr [rbx+10h]       0F B7 4B 10
	mov     rdx, cs:g_ScenarioInfoMgr     48 8B 15 ?? ?? ?? ??
	shr     ecx, 0Eh                      C1 E9 0E
	and     ecx, 1                        83 E1 01
	shl     ecx, 8                        C1 E1 08
	or      ecx, eax                      0B C8
		|
		v
	movzx   ecx, byte ptr [rbx+Offset_iTypeLo]         0F B6 4B offset
	movzx   eax, byte ptr [rbx+Offset_iTypeHi]         0F B6 43 offset
	mov     rdx, cs:g_ScenarioInfoMgr                  48 8B 15 ?? ?? ?? ??
	shl     eax, 8                                     C1 E0 08
	or      ecx, eax                                   09 C1
	*/
	const uint8_t patch1[8]
	{
		0x0F, 0xB6, 0x48, Offset_iTypeLo,
		0x0F, 0xB6, 0x40, Offset_iTypeHi,
	};
	hook::patch_and_nop_remaining<8>(loc, patch1);

	const uint8_t patch2[5]
	{
		0xC1, 0xE0, 0x08,
		0x09, 0xC1,
	};
	hook::patch_and_nop_remaining<11>(loc + 8 + 7, patch2);
}

static void Patch74()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType
	hook::pattern pattern("0F B6 ? 15 0F B7 ? 10 C1 E9 0E 83 E1 01 C1 E1 08 0B C8");
	pattern.count(2).for_each_result([](const hook::pattern_match& match)
	{
		auto loc = match.get<uint8_t>();

		/*
		movzx   eax, byte ptr [rdx/rsi+15h]                0F B6 42/46 15
		movzx   ecx, word ptr [rdx/rsi+10h]                0F B7 4A/4E 10
		shr     ecx, 0Eh                                   C1 E9 0E
		and     ecx, 1                                     83 E1 01
		shl     ecx, 8                                     C1 E1 08
		or      ecx, eax                                   0B C8
			|
			v
		movzx   eax, byte ptr [rdx/rsi+Offset_iTypeLo]     0F B6 42/46 offset
		movzx   ecx, byte ptr [rdx/rsi+Offset_iTypeHi]     0F B6 4A/4E offset
		shl     ecx, 8                                     C1 E1 08
		or      ecx, eax                                   0B C8
		*/
		const uint8_t patch[13]
		{
			0x0F, 0xB6, *(loc + 2), Offset_iTypeLo,
			0x0F, 0xB6, *(loc + 6), Offset_iTypeHi,
			0xC1, 0xE1, 0x08,
			0x0B, 0xC8,
		};
		hook::patch_and_nop_remaining<19>(loc, patch);
	});
}

static void Patch75()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType
	hook::pattern pattern("0F B7 ? 10 0F B6 ? 15 C1 E9 0E 83 E1 01 C1 E1 08 0B C8");
	pattern.count(4).for_each_result([](const hook::pattern_match& match)
	{
		auto loc = match.get<uint8_t>();

		/*
		movzx   ecx, word ptr [rax/rdx/rbx+10h]                0F B7 48/4A/4B 10
		movzx   eax, byte ptr [rax/rdx/rbx+15h]                0F B6 40/42/43 15
		shr     ecx, 0Eh                                       C1 E9 0E
		and     ecx, 1                                         83 E1 01
		shl     ecx, 8                                         C1 E1 08
		or      ecx, eax                                       0B C8
			|
			v
		movzx   ecx, byte ptr [rax/rdx/rbx+Offset_iTypeLo]     0F B6 48/4A/4B offset
		movzx   eax, byte ptr [rax/rdx/rbx+Offset_iTypeHi]     0F B6 40/42/43 offset
		shl     eax, 8                                         C1 E0 08
		or      ecx, eax                                       0B C8
		*/
		const uint8_t patch[13]
		{
			0x0F, 0xB6, *(loc + 2), Offset_iTypeLo,
			0x0F, 0xB6, *(loc + 6), Offset_iTypeHi,
			0xC1, 0xE0, 0x08,
			0x0B, 0xC8,
		};
		hook::patch_and_nop_remaining<19>(loc, patch);
	});
}

static void Patch76()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType
	hook::pattern pattern("0F B6 41 15 C1 EA 0E 83 E2 01 C1 E2 08 0B D0");
	pattern.count(2).for_each_result([](const hook::pattern_match& match)
	{
		auto loc = match.get<uint8_t>();

		/*
		movzx   eax, byte ptr [rcx+15h]                0F B6 41 15
		shr     edx, 0Eh                               C1 EA 0E
		and     edx, 1                                 83 E2 01
		shl     edx, 8                                 C1 E2 08
		or      edx, eax                               0B D0
			|
			v
		movzx   edx, byte ptr [rcx+Offset_iTypeLo]     0F B6 51 offset
		movzx   eax, byte ptr [rcx+Offset_iTypeHi]     0F B6 41 offset
		shl     eax, 8                                 C1 E0 08
		or      edx, eax                               0B D0
		*/
		const uint8_t patch[13]
		{
			0x0F, 0xB6, 0x51, Offset_iTypeLo,
			0x0F, 0xB6, 0x41, Offset_iTypeHi,
			0xC1, 0xE0, 0x08,
			0x0B, 0xD0,
		};
		hook::patch_and_nop_remaining<15>(loc, patch);
	});
}

static void Patch77()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType
	auto loc = hook::get_pattern<uint8_t>("0F B6 47 15 0F B7 5F 10 C1 EB 0E 83 E3 01");

	/*
	movzx   eax, byte ptr [rdi+15h]                    0F B6 47 15
	movzx   ebx, word ptr [rdi+10h]                    0F B7 5F 10
	shr     ebx, 0Eh                                   C1 EB 0E
	and     ebx, 1                                     83 E3 01
	shl     ebx, 8                                     C1 E3 08
	or      ebx, eax                                   0B D8
		|
		v
	movzx   ebx, byte ptr [rdi+Offset_iTypeLo]         0F B6 5F offset
	movzx   eax, byte ptr [rdi+Offset_iTypeHi]         0F B6 47 offset
	shl     eax, 8                                     C1 E0 08
	or      ebx, eax                                   0B D8
	*/
	const uint8_t patch[13]
	{
		0x0F, 0xB6, 0x5F, Offset_iTypeLo,
		0x0F, 0xB6, 0x47, Offset_iTypeHi,
		0xC1, 0xE0, 0x08,
		0x0B, 0xD8,
	};
	hook::patch_and_nop_remaining<19>(loc, patch);
}

static void Patch78()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType
	auto loc = hook::get_pattern<uint8_t>("0F B6 41 15 C1 EF 0E 83 E7 01");

	/*
	movzx   eax, byte ptr [rcx+15h]      0F B6 41 15
	shr     edi, 0Eh                     C1 EF 0E
	and     edi, 1                       83 E7 01
	shl     edi, 8                       C1 E7 08
	or      edi, eax                     0B F8
		|
		v
	movzx   edi, byte ptr [rcx+Offset_iTypeLo]         0F B6 79 offset
	movzx   eax, byte ptr [rcx+Offset_iTypeHi]         0F B6 41 offset
	shl     eax, 8                                     C1 E0 08
	or      edi, eax                                   0B F8
	*/
	const uint8_t patch[13]
	{
		0x0F, 0xB6, 0x79, Offset_iTypeLo,
		0x0F, 0xB6, 0x41, Offset_iTypeHi,
		0xC1, 0xE0, 0x08,
		0x0B, 0xF8,
	};
	hook::patch_and_nop_remaining<15>(loc, patch);
}

static void Patch79()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType
	auto loc = hook::get_pattern<uint8_t>("0F B6 41 15 44 0F B7 41 10 4C 8B 0D ? ? ? ? 41 C1 E8 0E");

	/*
	movzx   eax, byte ptr [rcx+15h]                    0F B6 41 15
	movzx   r8d, word ptr [rcx+10h]                    44 0F B7 41 10
	mov     r9, cs:g_ScenarioInfoMgr                   4C 8B 0D ?? ?? ?? ??
	shr     r8d, 0Eh                                   41 C1 E8 0E
	and     r8d, 1                                     41 83 E0 01
	shl     r8d, 8                                     41 C1 E0 08
	or      r8d, eax                                   44 0B C0
		|
		v
	movzx   r8d, byte ptr [rcx+Offset_iTypeLo]         44 0F B6 41 offset
	movzx   eax, byte ptr [rcx+Offset_iTypeHi]         0F B6 41 offset
	mov     r9, cs:g_ScenarioInfoMgr                   4C 8B 0D ?? ?? ?? ??
	shl     eax, 8                                     C1 E0 08
	or      r8d, eax                                   44 0B C0
	*/
	const uint8_t patch1[9]
	{
		0x44, 0x0F, 0xB6, 0x41, Offset_iTypeLo,
		0x0F, 0xB6, 0x41, Offset_iTypeHi,
	};
	hook::patch_and_nop_remaining<9>(loc, patch1);

	const uint8_t patch2[6]
	{
		0xC1, 0xE0, 0x08,
		0x44, 0x0B, 0xC0,
	};
	hook::patch_and_nop_remaining<15>(loc + 9 + 7, patch2);
}

static void Patch80()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType, CScenarioPoint::GetScenarioTypeIndex
	auto loc = hook::get_pattern<uint8_t>("0F B6 41 15 44 0F B7 41 10 41 C1 E8 0E");

	/*
	movzx   eax, byte ptr [rcx+15h]        0F B6 41 15
	movzx   r8d, word ptr [rcx+10h]        44 0F B7 41 10
	shr     r8d, 0Eh                       41 C1 E8 0E
	and     r8d, 1                         41 83 E0 01
	shl     r8d, 8                         41 C1 E0 08
	or      r8d, eax                       44 0B C0
		|
		v
	movzx   r8d, byte ptr [rcx+Offset_iTypeLo]         44 0F B6 41 offset
	movzx   eax, byte ptr [rcx+Offset_iTypeHi]         0F B6 41 offset
	shl     eax, 8                                     C1 E0 08
	or      r8d, eax                                   44 0B C0
	*/
	const uint8_t patch[15]
	{
		0x44, 0x0F, 0xB6, 0x41, Offset_iTypeLo,
		0x0F, 0xB6, 0x41, Offset_iTypeHi,
		0xC1, 0xE0, 0x08,
		0x44, 0x0B, 0xC0,
	};
	hook::patch_and_nop_remaining<24>(loc, patch);
}

static void Patch81()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType
	auto loc = hook::get_pattern<uint8_t>("41 0F B6 46 15 41 C1 E9 0E 41 83 E1 01");

	/*
	movzx   eax, byte ptr [r14+15h]                    41 0F B6 46 15
	shr     r9d, 0Eh                                   41 C1 E9 0E
	and     r9d, 1                                     41 83 E1 01
	shl     r9d, 8                                     41 C1 E1 08
	or      r9d, eax                                   44 0B C8
		|
		v
	movzx   r9d, byte ptr [r14+Offset_iTypeLo]         45 0F B6 4E offset
	movzx   eax, byte ptr [r14+Offset_iTypeHi]         41 0F B6 46 offset
	shl     eax, 8                                     C1 E0 08
	or      r9d, eax                                   44 0B C8
	*/
	const uint8_t patch[16]
	{
		0x45, 0x0F, 0xB6, 0x4E, Offset_iTypeLo,
		0x41, 0x0F, 0xB6, 0x46, Offset_iTypeHi,
		0xC1, 0xE0, 0x08,
		0x44, 0x0B, 0xC8,
	};
	hook::patch_and_nop_remaining<20>(loc, patch);
}

static void Patch82()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType
	auto loc = hook::get_pattern<uint8_t>("0F B6 45 95 44 8B 65 90 41 C1 EC 0E");

	/*
	movzx   eax, [rbp+0A8h+a1.iType]                              0F B6 45 95
	mov     r12d, dword ptr [rbp+0A8h+a1.RuntimeFlags]            44 8B 65 90
	shr     r12d, 0Eh                                             41 C1 EC 0E
	and     r12d, 1                                               41 83 E4 01
	shl     r12d, 8                                               41 C1 E4 08
	or      r12d, eax                                             44 0B E0
		|
		v
	movzx   r12d, byte ptr [r14+0A8h-128h+Offset_iTypeLo]         44 0F B6 65 80h+offset
	movzx   eax, byte ptr [r14+0A8h-128h+Offset_iTypeHi]          0F B6 45 80h+offset
	shl     eax, 8                                                C1 E0 08
	or      r12d, eax                                             44 0B E0
	*/
	const uint8_t patch[15]
	{
		0x44, 0x0F, 0xB6, 0x65, 0x80 + Offset_iTypeLo,
		0x0F, 0xB6, 0x45, 0x80 + Offset_iTypeHi,
		0xC1, 0xE0, 0x08,
		0x44, 0x0B, 0xE0,
	};
	hook::patch_and_nop_remaining<23>(loc, patch);
}

static void Patch83()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType
	auto loc = hook::get_pattern<uint8_t>("0F B6 47 15 0F B7 4A 10 41 C1 EE 0E");

	/*
	movzx   eax, byte ptr [rdi+15h]                    0F B6 47 15
	movzx   ecx, word ptr [rdx+10h]                    0F B7 4A 10
	shr     r14d, 0Eh                                  41 C1 EE 0E
	and     r14d, 1                                    41 83 E6 01
	shl     r14d, 8                                    41 C1 E6 08
	or      r14d, eax                                  44 0B F0
		|
		v
	movzx   ecx, word ptr [rdx+10h]                    0F B7 4A 10
	movzx   r14d, byte ptr [rdi+Offset_iTypeLo]        44 0F B6 77 offset
	movzx   eax, byte ptr [rdi+Offset_iTypeHi]         0F B6 47 offset
	shl     eax, 8                                     C1 E0 08
	or      r14d, eax                                  44 0B F0
	*/
	const uint8_t patch[19]
	{
		0x0F, 0xB7, 0x4A, 0x10,
		0x44, 0x0F, 0xB6, 0x77, Offset_iTypeLo,
		0x0F, 0xB6, 0x47, Offset_iTypeHi,
		0xC1, 0xE0, 0x08,
		0x44, 0x0B, 0xF0,
	};
	hook::patch_and_nop_remaining<23>(loc, patch);
}

static void Patch84()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType
	auto loc = hook::get_pattern<uint8_t>("0F B6 45 FC 44 8B 7D F7 41 C1 EF 0E");

	/*
	movzx   eax, [rbp+57h+a1.iType]                               0F B6 45 FC
	mov     r15d, dword ptr [rbp+57h+a1.RuntimeFlags]             44 8B 7D F7
	shr     r15d, 0Eh                                             41 C1 EF 0E
	and     r15d, 1                                               41 83 E7 01
	shl     r15d, 8                                               41 C1 E7 08
	or      r15d, eax                                             44 0B F8
		|
		v
	movzx   r15d, byte ptr [rbp+57h-70h+Offset_iTypeLo]           44 0F B6 7D E7h+offset
	movzx   eax, byte ptr [rbp+57h-70h+Offset_iTypeHi]            0F B6 45 E7h+offset
	shl     eax, 8                                                C1 E0 08
	or      r15d, eax                                             44 0B F8
	*/
	const uint8_t patch[15]
	{
		0x44, 0x0F, 0xB6, 0x7D, 0xE7 + Offset_iTypeLo,
		0x0F, 0xB6, 0x45, static_cast<uint8_t>(0xE7 + Offset_iTypeHi),
		0xC1, 0xE0, 0x08,
		0x44, 0x0B, 0xF8,
	};
	hook::patch_and_nop_remaining<23>(loc, patch);
}

static void Patch85()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType
	auto loc = hook::get_pattern<uint8_t>("0F B6 43 15 0F B7 7B 10 C1 EF 0E");

	/*
	movzx   eax, byte ptr [rbx+15h]                    0F B6 43 15
	movzx   edi, word ptr [rbx+10h]                    0F B7 7B 10
	shr     edi, 0Eh                                   C1 EF 0E
	and     edi, esi                                   23 FE
	shl     edi, 8                                     C1 E7 08
	or      edi, eax                                   0B F8
		|
		v
	movzx   edi, byte ptr [rbx+Offset_iTypeLo]         0F B6 7B offset
	movzx   eax, byte ptr [rbx+Offset_iTypeHi]         0F B6 43 offset
	shl     eax, 8                                     C1 E0 08
	or      edi, eax                                   0B F8
	*/
	const uint8_t patch[13]
	{
		0x0F, 0xB6, 0x7B, Offset_iTypeLo,
		0x0F, 0xB6, 0x43, Offset_iTypeHi,
		0xC1, 0xE0, 0x08,
		0x0B, 0xF8,
	};
	hook::patch_and_nop_remaining<18>(loc, patch);
}

static void Patch86()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType
	auto loc = hook::get_pattern<uint8_t>("44 0F B7 41 ? 0F B6 41 15 40 8A EA");

	/*
	movzx   r8d, word ptr [rcx+10h]                    44 0F B7 41 10
	movzx   eax, byte ptr [rcx+15h]                    0F B6 41 15
	mov     bpl, dl                                    40 8A EA
	shr     r8d, 0Eh                                   41 C1 E8 0E
	mov     rbx, rcx                                   48 8B D9
	and     r8d, 1                                     41 83 E0 01
	shl     r8d, 8                                     41 C1 E0 08
	or      r8d, eax                                   44 0B C0
		|
		v
	movzx   r8d, byte ptr [rcx+Offset_iTypeLo]         44 0F B6 41 offset
	movzx   eax, byte ptr [rcx+Offset_iTypeHi]         0F B6 41 offset
	shl     eax, 8                                     C1 E0 08
	or      r8d, eax                                   44 0B C0
	mov     bpl, dl                                    40 8A EA
	mov     rbx, rcx                                   48 8B D9
	*/
	const uint8_t patch[21]
	{
		0x44, 0x0F, 0xB6, 0x41, Offset_iTypeLo,
		0x0F, 0xB6, 0x41, Offset_iTypeHi,
		0xC1, 0xE0, 0x08,
		0x44, 0x0B, 0xC0,
		0x40, 0x8A, 0xEA,
		0x48, 0x8B, 0xD9,
	};
	hook::patch_and_nop_remaining<30>(loc, patch);
}

static void Patch87()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType
	auto loc = hook::get_pattern<uint8_t>("45 0F B7 4F ? 41 0F B6 47 ? 41 C1 E9 0E");

	/*
	movzx   r9d, word ptr [r15+10h]                    45 0F B7 4F 10
	movzx   eax, byte ptr [r15+15h]                    41 0F B6 47 15
	shr     r9d, 0Eh                                   41 C1 E9 0E
		|
		v
	movzx   r9d, byte ptr [r15+Offset_iTypeLo]         45 0F B6 4F offset
	movzx   eax, byte ptr [r15+Offset_iTypeHi]         41 0F B6 47 offset
	shl     eax, 8                                     C1 E0 08
		...
	or      r9d, eax  ; this instruction is already in the original code
	*/
	const uint8_t patch[13]
	{
		0x45, 0x0F, 0xB6, 0x4F, Offset_iTypeLo,
		0x41, 0x0F, 0xB6, 0x47, Offset_iTypeHi,
		0xC1, 0xE0, 0x08,
	};
	hook::patch_and_nop_remaining<14>(loc, patch);

	/*
	and     r9d, esi                          44 23 CE
	*/
	hook::nop(loc + 0x1A, 3);


	/*
	shl     r9d, 8                            41 C1 E1 08
	*/
	hook::nop(loc + 0x23, 4);
}

static void Patch88()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType
	auto loc = hook::get_pattern<uint8_t>("0F B6 40 15 41 C1 E9 0E 48 8D 0D ? ? ? ?");

	/*
	movzx   eax, byte ptr [rax+15h]         0F B6 40 15
	shr     r9d, 0Eh                        41 C1 E9 0E
	lea     rcx, unk_2607510                48 8D 0D 4C 81 9A 01
	and     r9d, 1                          41 83 E1 01
	mov     rdx, rdi                        48 8B D7
	mov     [rsp+38h+var_18], rbx           48 89 5C 24 20
	shl     r9d, 8                          41 C1 E1 08
	or      r9d, eax                        44 0B C8
		|
		v
	movzx   r9d, byte ptr [rax+Offset_iTypeHi]         44 0F B6 48 offset
	nop                                                90
	nop                                                90
	nop                                                90
	lea     rcx, unk_2607510                           48 8D 0D 4C 81 9A 01
	movzx   eax, byte ptr [rcx+Offset_iTypeLo]         0F B6 41 offset
	mov     rdx, rdi                                   48 8B D7
	mov     [rsp+38h+var_18], rbx                      48 89 5C 24 20
	shl     r9d, 8                                     41 C1 E1 08
	or      r9d, eax                                   44 0B C8
	*/
	const uint8_t patch1[5]
	{
		0x44, 0x0F, 0xB6, 0x48, Offset_iTypeHi,
	};
	hook::patch_and_nop_remaining<8>(loc, patch1);

	const uint8_t patch2[4]
	{
		0x0F, 0xB6, 0x41, Offset_iTypeLo,
	};
	hook::patch_and_nop_remaining<4>(loc + 8 + 7, patch2);
}

static void Patch89()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::iType
	auto loc = hook::get_pattern<uint8_t>("0F B7 4D 10 0F B6 45 15 4C 8B AB ? ? ? ?");

	/*
	movzx   ecx, word ptr [rbp+10h]                    0F B7 4D 10
	movzx   eax, byte ptr [rbp+15h]                    0F B6 45 15
	mov     r13, [rbx+10B0h]                           4C 8B AB B0 10 00 00
	shr     ecx, 0Eh                                   C1 E9 0E
	mov     rdx, rbx                                   48 8B D3
	and     ecx, 1                                     83 E1 01
	shl     ecx, 8                                     C1 E1 08
	or      ecx, eax                                   0B C8
		|
		v
	movzx   ecx, byte ptr [rbp+Offset_iTypeHi]         0F B6 4D offset
	movzx   eax, byte ptr [rbp+Offset_iTypeLo]         0F B6 45 offset
	mov     r13, [rbx+10B0h]                           4C 8B AB B0 10 00 00
	nop                                                90
	nop                                                90
	nop                                                90
	mov     rdx, rbx                                   48 8B D3
	nop                                                90
	nop                                                90
	nop                                                90
	shl     ecx, 8                                     C1 E1 08
	or      ecx, eax                                   0B C8
	*/
	const uint8_t patch[8]
	{
		0x0F, 0xB6, 0x4D, Offset_iTypeHi,
		0x0F, 0xB6, 0x45, Offset_iTypeLo,
	};
	hook::patch_and_nop_remaining<8>(loc, patch);

	hook::nop(loc + 8 + 7, 3);

	hook::nop(loc + 8 + 7 + 3 + 3, 3);
}

static void Patch90()
{
	spdlog::info(__func__);

	// access to CScenarioPoint::ModelSetId
	auto loc = hook::get_pattern<uint8_t>("41 0F B6 46 16 3D FF 00 00 00 74 1B");

	/*
	movzx   eax, byte ptr [r14+16h]                    41 0F B6 46 16
	cmp     eax, 0FFh                                  3D FF 00 00 00
		|
		v
	movzx   eax, word ptr [r14+Offset_ModelSetId]      41 0F B7 46 offset
	cmp     eax, InvalidModelSetId                     3D nn nn nn nn
	*/
	hook::put<uint8_t>(loc + 2, 0xB7);
	hook::put<uint8_t>(loc + 4, Offset_ModelSetId);
	hook::put<uint32_t>(loc + 5 + 1, InvalidModelSetId);
}

static void Patch91()
{
	spdlog::info(__func__);

	// access to CCargen::ScenarioType
	auto loc = hook::get_pattern<uint8_t>("41 B9 FF 01 00 00 41 B8 FF 00 00 00");

	/*
	mov     r9d, 1FFh                                  41 B9 FF 01 00 00
	mov     r8d, 0FFh                                  41 B8 FF 00 00 00
		|
		v
	mov     r9d, FFFFh                                 41 B9 FF FF 00 00
	mov     r8d, InvalidScenarioType                   41 B8 nn nn nn nn
	*/
	hook::put<uint8_t>(loc + 3, 0xFF);
	hook::put<uint32_t>(loc + 6 + 2, InvalidScenarioType);
}

static void Patch92()
{
	spdlog::info(__func__);

	// access to CCargen::ScenarioType
	auto loc = hook::get_pattern<uint8_t>("BA FF 01 00 00 66 23 CA BA FF 00 00 00");

	/*
	mov     edx, 1FFh                                  BA FF 01 00 00
	and     cx, dx                                     66 23 CA
	mov     edx, 0FFh                                  BA FF 00 00 00
		|
		v
	mov     edx, FFFFh                                  BA FF FF 00 00
	and     cx, dx                                      66 23 CA
	mov     edx, InvalidScenarioType                    BA nn nn nn nn
	*/
	hook::put<uint8_t>(loc + 2, 0xFF);
	hook::put<uint32_t>(loc + 5 + 3 + 1, InvalidScenarioType);
}

static void Patch93()
{
	spdlog::info(__func__);

	// access to CCargen::ScenarioType
	auto loc = hook::get_pattern<uint8_t>("B9 FF 01 00 00 41 BE FF 00 00 00");

	/*
	mov     ecx, 1FFh                                   B9 FF 01 00 00
	mov     r14d, 0FFh                                  41 BE FF 00 00 00
		|
		v
	mov     ecx, FFFFh                                  B9 FF FF 00 00
	mov     r14d, InvalidScenarioType                   41 BE nn nn nn nn
	*/
	hook::put<uint8_t>(loc + 2, 0xFF);
	hook::put<uint32_t>(loc + 5 + 2, InvalidScenarioType);
}

static DWORD WINAPI Main()
{
	if (LoggingEnabled())
	{
		spdlog::set_default_logger(spdlog::basic_logger_mt("file_logger", "CScenarioPoint-Patch.log"));
		spdlog::flush_every(std::chrono::seconds(5));
	}
	else
	{
		spdlog::set_level(spdlog::level::off);
	}


	spdlog::info("Initializing...");

	const auto startTime = std::chrono::steady_clock::now();
	
	MH_Initialize();

	FindGameFunctions();
	FindGameVariables();

	Patch1();
	Patch2();
	Patch3();
	Patch4();
	Patch5();
	Patch7();
	Patch8();
	Patch24();
	Patch25();
	Patch33();
	Patch49();
	Patch50();
	Patch51();
	Patch52();
	Patch53();
	Patch54();
	Patch55();
	Patch56();
	Patch57();
	Patch58();
	Patch59();
	Patch60();
	Patch61();
	Patch62();
	Patch63();
	Patch64();
	Patch65();
	Patch66();
	Patch67();
	Patch68();
	Patch69();
	Patch70();
	Patch71();
	Patch72();
	Patch74();
	Patch75();
	Patch76();
	Patch77();
	Patch78();
	Patch79();
	Patch80();
	Patch81();
	Patch82();
	Patch83();
	Patch84();
	Patch85();
	Patch86();
	Patch87();
	Patch88();
	Patch89();
	Patch90();
	Patch91();
	Patch92();
	Patch93();

	MH_EnableHook(MH_ALL_HOOKS);

	const auto endTime = std::chrono::steady_clock::now();

	spdlog::info("Initialization finished - Took {} ms", std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());
	return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		CloseHandle(CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Main, NULL, NULL, NULL));
	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH)
	{
		spdlog::shutdown();
	}

	return TRUE;
}
