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

/// The CScenarioPoint offset where we are going to store the ModelSetId,
/// 2 bytes (which previously were padding) instead of 1 byte.
constexpr ptrdiff_t ModelSetIdOffset{ offsetof(CScenarioPoint, padding_22) };
static_assert(ModelSetIdOffset < 0xFF);

constexpr uint16_t InvalidModelSetId{ 0xFFFF };

static void SetPointModelSet(CScenarioPoint* point, uint16_t modelSetId)
{
	// use 2 bytes of padding to store the model set
	*reinterpret_cast<uint16_t*>(reinterpret_cast<char*>(point)  + ModelSetIdOffset) = modelSetId;
}

static uint16_t GetPointModelSet(CScenarioPoint* point)
{
	return *reinterpret_cast<uint16_t*>(reinterpret_cast<char*>(point) + ModelSetIdOffset);
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
	const atArray<uint32_t>* modelSetNames = IsScenarioVehicleInfo(scenarioIndex) ?
		&indicesLookups->VehicleModelSetNames :
		&indicesLookups->PedModelSetNames;

	const uint32_t modelSet = modelSetNames->Items[point->ModelSetId];
	if (modelSet > 0xFFFF)
	{
		spdlog::warn("point ({}) with modelset ({}) > 0xFFFF", reinterpret_cast<void*>(point), modelSet);
		LogStackTrace();
	}

	CScenarioPoint_TransformIdsToIndices_orig(indicesLookups, point);

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
	movzx   edx, word ptr [rcx+ModelSetIdOffset]    0F B7 51 offset
	*/
	hook::put<uint8_t>(loc + 1, 0xB7);
	hook::put<uint8_t>(loc + 3, ModelSetIdOffset);

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
	movzx   r15d, word ptr [r14+ModelSetIdOffset]   45 0F B7 7E offset
	*/
	hook::put<uint8_t>(loc + 12 + 2, 0xB7);
	hook::put<uint8_t>(loc + 12 + 4, ModelSetIdOffset);

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
	movzx   eax, word ptr [rdi+ModelSetIdOffset]    0F B7 47 offset
	*/
	hook::put<uint8_t>(loc + 1, 0xB7);
	hook::put<uint8_t>(loc + 3, ModelSetIdOffset);

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

bool(*CScenarioPoint_SetModelSet_orig)(CScenarioPoint* This, const uint32_t* modelSetHash, bool isVehicle);
bool CScenarioPoint_SetModelSet_detour(CScenarioPoint* This, const uint32_t* modelSetHash, bool isVehicle)
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
			modelSetId = static_cast<uint16_t>(modelSetIndex);
		}
	}

	if (modelSetId > 0xFFFF)
	{
		spdlog::warn("point ({}) with modelset ({}) > 0xFFFF", reinterpret_cast<void*>(This), modelSetId);
		LogStackTrace();
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
		movzx   edx, word ptr [rbx+ModelSetIdOffset]    0F B7 53 offset
		*/
		hook::put<uint8_t>(loc + 1, 0xB7);
		hook::put<uint8_t>(loc + 3, ModelSetIdOffset);
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
	movzx   eax, word ptr [r13+ModelSetIdOffset]    41 0F B7 45 offset
	*/
	hook::put<uint8_t>(loc + 2, 0xB7);
	hook::put<uint8_t>(loc + 4, ModelSetIdOffset);

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
	cmp     word ptr [r14+ModelSetIdOffset], 0FFFFh    66 41 83 7E offset FF
	nop                                                90
	nop                                                90
	nop                                                90
	*/
	const uint8_t patch[9]
	{
		0x66, 0x41, 0x83, 0x7E, ModelSetIdOffset, 0xFF,
		0x90, 0x90, 0x90
	};
	memcpy(loc, patch, std::size(patch));
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
