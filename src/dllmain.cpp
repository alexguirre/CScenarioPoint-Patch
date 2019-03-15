#include <Windows.h>
#include "Hooking.Patterns.h"
#include "Hooking.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>

constexpr bool EnableLogging = false;

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
	//  replace default index of PedModelSetNames, VehicleModelSetNames and RequiredIMapNames from 0xFF to 0xFFFFFFFF
	hook::put(hook::get_pattern("41 BD ? ? ? ? 85 ED 7E 51 4C 8B F3", 2), 0xFFFFFFFF);
}


void Patch2()
{
	// CScenarioPoint::TransformIdsToIndices(CScenarioPointRegion::LookUps *indicesLookups, CScenarioPoint *point)
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

	Patch1();

	WaitForWindow();
	WaitForIntroToFinish();

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
