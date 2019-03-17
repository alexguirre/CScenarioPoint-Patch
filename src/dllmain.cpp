#include <Windows.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include "Hooking.Patterns.h"
#include "Hooking.h"
#include "CScenarioInfo.h"
#include "CScenarioPoint.h"
#include "CScenarioPointRegion.h"
#include <unordered_map>
#include <MinHook.h>
#include <jitasm.h>

constexpr bool EnableLogging = true;

void WaitForWindow()
{
	spdlog::info("Waiting for window...");
	while (!FindWindow("grcWindow", NULL))
	{
		Sleep(100);
	}
}

void WaitForIntroToFinish()
{
	uintptr_t addr = (uintptr_t)hook::get_pattern("44 39 3D ? ? ? ? 75 09 83 BB ? ? ? ? ? 7D 24");
	addr = addr + *(int*)(addr + 3) + 7;
	unsigned int* gameState = (unsigned int*)addr;

	spdlog::info("Waiting for intro to finish...");
	while (*gameState == 0 || *gameState == 1)
	{
		Sleep(100);
	}
}

void Patch1()
{
	// CScenarioPointRegion::LookUps::ConvertHashesToIndices
	hook::put(hook::get_pattern("41 BD ? ? ? ? 85 ED 7E 51 4C 8B F3", 2), 0xFFFFFFFF);
}

using IsScenarioVehicleInfo_fn = bool(*)(uint32_t index);
IsScenarioVehicleInfo_fn IsScenarioVehicleInfo;

struct ExtendedScenarioPoint
{
	uint32_t ModelSetId;
};
std::unordered_map<CScenarioPoint*, ExtendedScenarioPoint> g_Points;

void(*CScenarioPoint_TransformIdsToIndices_orig)(CScenarioPointRegion::sLookUps*, CScenarioPoint*);
void CScenarioPoint_TransformIdsToIndices_detour(CScenarioPointRegion::sLookUps* indicesLookups, CScenarioPoint* point)
{
	uint32_t scenarioIndex = indicesLookups->TypeNames.Items[point->iType];
	ExtendedScenarioPoint p;
	//p.iType = scenarioIndex;

	atArray<uint32_t>* modelSetNames = IsScenarioVehicleInfo(scenarioIndex) ?
										&indicesLookups->VehicleModelSetNames :
										&indicesLookups->PedModelSetNames;
	p.ModelSetId = modelSetNames->Items[point->ModelSetId];

	g_Points.insert({ point, p });

	CScenarioPoint_TransformIdsToIndices_orig(indicesLookups, point);

	//spdlog::info(" TransformIdsToIndices:: OrigIndex -> {} | FinalIndex -> {}  (Total: {})", p.ModelSetId, point->ModelSetId, g_Points.size());
}

void Patch2()
{
	IsScenarioVehicleInfo = (IsScenarioVehicleInfo_fn)hook::pattern("48 83 EC 28 48 8B 15 ? ? ? ? 0F B7 42 10 3B C8 7D 2A").get(1).get<void>();

	// CScenarioPoint::TransformIdsToIndices
	MH_CreateHook(hook::get_pattern("48 8B 01 44 0F B6 42 ? 0F B6 72 16", -0xF), CScenarioPoint_TransformIdsToIndices_detour, (void**)&CScenarioPoint_TransformIdsToIndices_orig);
}

void Patch3()
{
	// CScenarioInfoManager::IsValidModelSet
	hook::put(hook::get_pattern("81 FF ? ? ? ? 74 6F 48 8B 05", 2), 0xFFFFFFFF);
}

void Patch4()
{
	// CScenarioPoint::CanSpawn
	static struct : jitasm::Frontend
	{
		static int GetModelSetIndex(CScenarioPoint* point)
		{
			if (!point)
			{
				return 0xFFFFFFFF;
			}

			auto p = g_Points.find(point);
			if (p != g_Points.end())
			{
				return p->second.ModelSetId;
			}
			else
			{
				return point->ModelSetId;
			}
		}

		void InternalMain() override
		{
			push(rcx);
			sub(rsp, 0x10);

			mov(rcx, rdi);
			mov(rax, (uintptr_t)GetModelSetIndex);
			call(rax);

			add(rsp, 0x10);
			pop(rcx);

			mov(edx, eax);
			ret();
		}
	} getModelSetIndexStub;

	auto location = hook::get_pattern("48 85 C9 74 06 0F B6 51 16 EB 05");
	hook::nop(location, 0x10);
	hook::call(location, getModelSetIndexStub.GetCode());
}

void Patch5()
{
	// bool GetAndLoadScenarioPointModel(__int64 rcx0, signed int scenarioIndex, CScenarioPoint *point, __int64 a4, ...)
	static struct : jitasm::Frontend
	{
		static int GetModelSetIndex(CScenarioInfo* scenario, CScenarioPoint* point)
		{
			constexpr uint32_t CScenarioVehicleInfo_ClassId = 0xFB9AD9D7;


			int result = 0xFFFFFFFF;
			if (scenario->GetIsClassId(CScenarioVehicleInfo_ClassId))
			{
				//return 0xFFFFFFFF;
			}

			auto p = g_Points.find(point);
			if (p != g_Points.end())
			{
				result = p->second.ModelSetId;
			}
			else
			{
				result = point->ModelSetId;
			}

	/*		spdlog::info("GetModelSetIndex({}, {}) -> {}", (void*)scenario, (void*)point, result);
			spdlog::default_logger()->flush();*/
			return result;
		}

		void InternalMain() override
		{
			push(rcx);
			push(rdx);
			sub(rsp, 0x18);

			mov(rcx, rdi); // first param: CScenarioInfo*
			mov(rdx, r14); // second param: CScenarioPoint*
			mov(rax, (uintptr_t)GetModelSetIndex);
			call(rax);

			add(rsp, 0x18);
			pop(rdx);
			pop(rcx);

			mov(r15d, eax);
			ret();
		}
	} getModelSetIndexStub;

	auto location = hook::get_pattern("48 8B CF 41 BF ? ? ? ? FF 10 84 C0");
	hook::nop(location, 0x14);
	hook::call(location, getModelSetIndexStub.GetCode());

	// cmp against 0xFFFFFFF
	hook::put(hook::get_pattern("41 81 FF ? ? ? ? 0F 85 ? ? ? ? B9", 3), 0xFFFFFFFF);
}

DWORD WINAPI Main()
{
	if (EnableLogging)
	{
		spdlog::set_default_logger(spdlog::basic_logger_mt("file_logger", "CScenarioPoint-Patch.log"));
		spdlog::flush_every(std::chrono::seconds(5));
	}
	else
	{
		spdlog::set_level(spdlog::level::off);
	}

	spdlog::info("Main");

	MH_Initialize();
	
	// TODO: after some time it crashes

	Patch1();
	Patch2();
	Patch3();
	Patch4();
	Patch5();

	MH_EnableHook(MH_ALL_HOOKS);

	//WaitForWindow();
	//WaitForIntroToFinish();

	spdlog::info("End");
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
