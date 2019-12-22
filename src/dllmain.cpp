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

	spdlog::info("Initializing MinHook...");
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

	MH_EnableHook(MH_ALL_HOOKS);

	spdlog::info("Initialization finished");
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
