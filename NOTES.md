# Notes

These notes were taken during the development of the patch for future reference. May not be fully correct.

Addresses shown here are from v1011 retail.

## Patches

* void CScenarioPointRegion::LookUps::ConvertHashesToIndices(CScenarioPointRegion::LookUps *dst, CScenarioPointRegion::LookUps *src) | Patch1
  * sets default index of PedModelSetNames, VehicleModelSetNames and RequiredIMapNames from 0xFF -> should be 0xFFFFFFFF

* void CScenarioPoint::TransformIdsToIndices(CScenarioPointRegion::LookUps *indicesLookups, CScenarioPoint *point) | Patch2
  * can be hooked to store the proper model set indices in our extended struct, then original method can be called
  * and for the scenario type too

* bool CScenarioInfoManager::IsValidPedModelSet(signed int scenarioIndex, unsigned int modelSetIndex) | Patch3
  * checks if modelSetIndex is 0xFF -> should check 0xFFFFFFFF

* bool CScenarioPoint::CanScenarioSpawn(CScenarioPoint *this, unsigned int scenarioIndex, bool a3, bool a4) | Patch4
  * sets default modelSetIndex to 0xFF -> should be 0xFFFFFFFF
  * accesses CScenarioPoint::ModelSetId -> should access our 16-bit index
    * 0xBEE16D - 0xBEE15D = 0x10 bytes available
    * should be stored in `edx`
    * `rdi`/`rcx` contains CScenarioPoint*
    * `rcx` can be reused

* bool GetAndLoadScenarioPointModel_Guess(__int64 rcx0, signed int scenarioIndex, CScenarioPoint *point, __int64 a4, ...) | Patch5
  * sets default modelSetIndex to 0xFF -> should be 0xFFFFFFFF
  * accesses CScenarioPoint::ModelSetId -> should access our 16-bit index
    * 0xC192D8 - 0xC192C4 = 0x14 bytes available
    * should be stored in `r15d`
    * `rdi` contains CScenarioInfo*
    * `r14` contains CScenarioPoint*
  * compares modelSetIndex against 0xFF -> should be 0xFFFFFFFF

* void CScenarioPoint::Delete(CScenarioPoint *a1) | Patch6
  * can be used to remove CScenarioPoints from our map

* sub_BEA384 && sub_BF99BC | Patch7
  * accesses CScenarioPoint::ModelSetid, both in the same way
    * 0xBEA6E0 - 0xBEA6D7 = 0x9
    * 0xBFA20A - 0xBFA201 = 0x9
    * `rdi` contains CScenarioPoint*
    * `eax` should contain the ModelSetId
    * cmp eax, 0FFh -> cmp eax 0FFFFFFFFh
  * accesses CScenarioPoint::iType, both in the same way
    * 0xBEA43A - 0xBEA432 = 0x8
    * 0xBF9E86 - 0xBF9E7E = 0x8
    * `rdi` contains CScenarioPoint*
    * `ebx` should contain the scenario type
    * should do `movzx   ecx, word ptr [rax+10h]`
  * accesses CScenarioPoint::iType, only in sub_BF99BC
    * 0xBF9DC0 - 0xBF9DBB = 0x5
    * `rdi` contains CScenarioPoint*
    * `r14d` should contain the scenario type
    * save `rdx`

* void CScenarioPoint::InitFromSpawnPointDef(CScenarioPoint *this, CExtensionDefSpawnPoint *a2) | Patch8
  * sets CScenarioPoint::iType, should set ours too
    * 0xC06A6A - 0xC06A58 = 0x12 bytes available
    * `rdx` contains CExtensionDefSpawnPoint*
    * `rcx` contains CScenarioInfoManager*
    * `rbx` contains CScenarioPoint*
    * `eax` should have the scenario type index returned by CScenarioInfoManager::GetScenarioTypeByHash
  * calls CScenarioPoint::SetModelSet

* CScenarioPoint* CScenarioPoint::ctorWithEntity(CScenarioPoint *this, CSpawnPoint *spawnPoint, CEntity *a3) | Patch9
  * sets CScenarioPoint::iType, should set ours too
    * spawnPoint already stores the scenario type as an uint8 so probably need to store CSpawnPoints hooking CSpawnPoint::InitFromDef to know the original int32 index
    * 0xBE1289 - 0xBE1284 = 0x5 bytes available
    * `rdi` contains CSpawnPoint*
    * `rbx` contains CScenarioPoint*
    * `eax` should the return value of GetFinalModelSetHash(CSpawnPoint->pedTypeHash)
  * calls CScenarioPoint::SetModelSet

* void CSpawnPointOverrideExtension::OverrideScenarioPoint(CSpawnPointOverrideExtension *a1, CScenarioPoint *point) | Patch10
  * sets CScenarioPoint::iType, should set ours too
  * calls CScenarioPoint::SetModelSet

* unsigned __int8 CScenarioPoint::GetScenarioType(CScenarioPoint *a1) | Patch11
  * too small to hook and the callers access the 8bit register, need to patch each call individually
  * at 0x680AA6:
    * 0x680AAF - 0x680AA6 = 0x9 bytes available
    * `rcx` contains CScenarioPoint*
    * `r14d` should contain the scenario type
  * at 0x6B3D9E:
    * 0x6B3DA6 - 0x6B3D9E = 0x8 bytes available
    * `rcx` contains CScenarioPoint*
    * `ebx` should contain the scenario type
  * at 0x6BBDEA:
    * 0x6BBDEF - 0x6BBDEA = 0x5 bytes available
    * `rcx` contains CScenarioPoint*
    * `ebx` should contain the scenario type
    * instruction `movzx   ebx, al` at 0x6BBDFB should be nopped
  * at 0xA68F3D:
    * 0xA68F42 - 0xA68F3D = 0x5 bytes available
    * `rcx` contains CScenarioPoint*
    * `ebx` should contain the scenario type
    * instruction `movzx   ebx, al` at 0xA68F4D should be nopped
  * at 0xA7E5CF:
    * 0xA7E5D7 - 0xA7E5CF = 0x8 bytes available
    * `rcx` contains CScenarioPoint*
    * `ecx` should contain the scenario type
  * at 0xCD114F:
    * 0xCD1154 - 0xCD114F = 0x5 bytes available
    * `rcx` contains CScenarioPoint*
    * `esi` should contain the scenario type
    * instruction `movzx   esi, al` at 0xCD115E should be nopped
  * at 0xCEF122:
    * 0xCEF127 - 0xCEF122 = 0x5 bytes available
    * `rcx` contains CScenarioPoint*
    * `ecx` should contain the scenario type
    * instruction `movzx   ecx, al` at 0xCEF12A should be nopped
  * at 0xCEF314:
    * 0xCEF319 - 0xCEF314 = 0x5 bytes available
    * `rcx` contains CScenarioPoint*
    * `ecx` should contain the scenario type
    * instruction `movzx   ecx, al` at 0xCEF31C should be nopped

* bool CScenarioPoint::IsScenarioTypeEnabled(CScenarioPoint *a1, unsigned int subType) | Patch12
  * accesses CScenarioPoint::iType
    * small enough to rewrite

* unsigned int CScenarioPoint::GetScenarioTypeIndex(CScenarioPoint *a1, unsigned int subType) | Patch12
  * accesses CScenarioPoint::iType
    * small enough to rewrite

* bool CScenarioPoint::CanSpawn(CScenarioPoint *a1, bool a2, bool a3, unsigned int subType) | Patch13
  * accesses CScenarioPoint::iType
    * small enough to rewrite

* sub_C23FD4 | Patch14
  * accesses CScenarioPoint::iType
    * 0xC23FEF - 0xC23FE8 = 0x7 bytes available
    * `rcx` contains CScenarioPoint*
    * `ecx` should contain the scenario type
    * should do instruction `mov     rbx, rcx`

* sub_BE690C && sub_C0D2B8 | Patch15
  * accesses CScenarioPoint::iType
    * 0xBE6922 - 0xBE691C = 0x6 bytes available
    * 0xC0D2DE - 0xC0D2D8 = 0x6 bytes available
    * `rcx` contains CScenarioPoint*
    * `ecx` should contain the scenario type
    * should do instruction `test    ecx, ecx`

* CTaskUseScenario::ctor | Patch16
  * accesses CScenarioPoint::iType
    * 0xBE2A4E - 0xBE2A44 = 0xA bytes available
    * `rax` contains CScenarioPoint*
    * `eax` should contain the scenario type
    * should do instruction `mov     [rdi+18Ch], eax`

* sub_C14520 | Patch17
  * accesses CScenarioPoint::iType
    * 0xC145AB - 0xC145A6 = 0x5 bytes available
    * `rdx` contains CScenarioPoint array
    * `rdi` contains point offset
    * `ecx` should contain the scenario type

* sub_BF1694 | Patch18
  * accesses CScenarioPoint::iType
    * 0xBF16B3 - 0xBF16AA = 0x9
    * `rdx` contains CScenarioPoint*
    * `ecx` should contain the scenario type
    * should do `call    CScenarioInfoManager__IsScenarioVehicleInfo`

* sub_BED234 | Patch19
  * accesses CScenarioPoint::iType
    * 0xBED26E - 0xBED263 = 0xB
    * `rdx` contains CScenarioPoint*
    * `eax` should contain the scenario type
    * `rdx` should contain g_ScenarioInfoMgr

* sub_BFC4FC | Patch20
  * accesses CScenarioPoint::iType
    * 0xBFC581 - 0xBFC578 = 0x9 bytes available
    * `rsi` contains CScenarioPoint*
    * `ecx` should contain the scenario type
    * should do `movzx   eax, word ptr [r8+10h]`

* sub_BF44B8 | Patch21
  * accesses CScenarioPoint::iType
    * 0xBF46C3 - 0xBF46BE = 0x5 bytes available
    * `rsi` contains CScenarioPoint*
    * `r9d` should contain the scenario type

* sub_C22F4C | Patch22
  * accesses CScenarioPoint::iType
    * 0xC22FA9 - 0xC22FA4 = 0x5 bytes available
    * `r14` contains CScenarioPoint*
    * `ecx` should contain the scenario type

* sub_C0CDF4 | Patch23
  * accesses CScenarioPoint::iType
    * 0xC0CE5A - 0xC0CE50 = 0xA bytes available
    * `rdx` contains CScenarioPoint*
    * `eax` should contain the scenario type
    * should do `cmp     eax, [rbx+18Ch]`

* void CScenarioPoint::TryCreateCargen(CScenarioPoint *point) | Patch24
  * accesses CScenarioPoint::iType
    * 0xC0CFFB - 0xC0CFF5 = 0x6 bytes available
    * `rcx` contains CScenarioPoint*
    * `esi` should contain the scenario type
    * should do `test    esi, esi`
  * access CScenarioPoint::ModelSetid -> should access our 16-bit index
    * 0xC0D075 - 0xC0D06E = 0x7
    * `rbx` contains CScenarioPoint*
    * `edx` should contain ModelSetId
    * should do `mov     rcx, rdi`

* sub_C002DC && sub_C058E8 | Patch25
  * compares ModelSetId against 0xFF -> should be 0xFFFFFFFF

* CreateCargen | Patch26
  * checks the scenario type against 0xFF -> should be 0xFFFFFFFF

* CCargen::Initialize | Patch27
  * can be used to store CCargens and their ScenarioType

* DeleteCargenFromPool | Patch28
  * can be used to remove CCargens from our map

* CREATE_SCRIPT_VEHICLE_GENERATOR | Patch29
  * passes 0xFF to CreateCargen -> should 0xFFFFFFFF

* sub_8C131C | Patch30
  * passes 0xFF to CreateCargen -> should 0xFFFFFFFF

* sub_C1C6E8 | Patch31
  * accesses CScenarioPoint::ModelSetId
    * 0xC1C7C6 - 0xC1C7BF = 0x7 bytes available
    * `rbx` contains CScenarioPoint*
    * `edx` should contain the ModelSetId
    * should do `mov     rcx, rsi`

* sub_BEA838 | Patch32
  * accesses CCargen::ScenarioType
    * 0xBEA93C - 0xBEA933 = 0x9
    * `rsi` contains CCargen*
    * `esi` should contain the ScenarioType
    * shoud do `lea     rdx, [rsp+30h]`

* sub_C110EC | Patch33
  * accesses CCargen::ScenarioType
    * 0xC11176 - 0xC1116F = 0x7
    * `rbx` contains CCargen*
    * `edi` should contain the ScenarioType
    * shoud do `xor     r9d, r9d`
  * accesses CScenarioPoint::ModelSetId and compares ModelSetId against 0xFF -> should be 0xFFFFFFFF
    * 0xC112BE - 0xC112B9 = 0x5
    * `r13` contains CScenarioPoint*
    * `eax` should contain the ModelSetId

* sub_BEA9A4 | Patch34
  * accesses CCargen::ScenarioType
    * 0xBEA9E0 - 0xBEA9DB = 0x5
    * `r15` contains CCargen*
    * `r12d` should contain the ScenarioType
    * should use call_rcx
    * save `rax` register

* sub_BED3B8 | Patch35
  * accesses CScenarioPoint::iType
    * `rbp + 0x57 - 0x70` contains the CScenarioPoint, i.e. `lea(rcx, qword_ptr[rbp + 0x57 - 0x70]);`
    * `r12d` should contain the iType
    * should use call_rcx
    * save `rax` register

* sub_C15C74 | Patch36
  * accesses CCargen::ScenarioType
    * 0xC15C83 - 0xC15C7E = 0x5
    * `rdx` contains CCargen*
    * `r9d` should contain the ScenarioType
    * save `rcx` register
  * accesses CScenarioPoint::iType
    * 0xC15CD9 - 0xC15CD4 = 0x5
    * `rax` contains CScenarioPoint*
    * `r9d` should contain the iType

* sub_E700E0 | Patch37
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xE701B0 - 0xE701A8 = 0x8
    * `[rbx+48h]` contains CCargen*
    * `rdx` should contain CCargen*
    * save `rcx` register
    * compare ScenarioType against 0xFFFFFFFF

* sub_EAEB34 | Patch38
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xEAEBEF - 0xEAEBE9 = 0x6
    * `rbx` contains CCargen*
    * should compare ScenarioType against 0xFFFFFFFF and do `jz      short loc_EAEC32`

* sub_E4E3F8 | Patch39
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xE4E66E - 0xE4E666 = 0x8
    * `rbx` contains CCargen*
    * should compare ScenarioType against 0xFFFFFFFF
    * should do `movaps  xmm8, xmm0`

* sub_E4E86C | Patch40
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xE4E953 - 0xE4E94D = 0x6
    * `rbx` contains CCargen*
    * should compare ScenarioType against 0xFFFFFFFF and do `jz      short loc_E4E9CF`

* sub_E78FAC | Patch41.1
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xE7908C - 0xE79082 = 0xA
    * `rcx` contains CCargen*
    * save `rcx`
    * should compare ScenarioType against 0xFFFFFFFF and do `jz      loc_E79142`

* sub_E7C1E0 | Patch41.2
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xE7C24C - 0xE7C246 = 0x6
    * `rcx` contains CCargen*
    * save `rcx`
    * should compare ScenarioType against 0xFFFFFFFF and do `jz      short loc_E7C27A`

* sub_E93834 | Patch42.1
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xE93ACE - 0xE93AC8 = 0x6
    * `rdi` contains CCargen*
    * should compare ScenarioType against 0xFFFFFFFF and do `jz      short loc_E93B2C`

* sub_E985FC | Patch41.3
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xE9860A - 0xE98604 = 0x6
    * `rcx` contains CCargen*
    * save `rcx`
    * should compare ScenarioType against 0xFFFFFFFF and do `jnz     short loc_E9860E`

* sub_EA4D08 | Patch43
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xEA4F28 - 0xEA4F22 = 0x6
    * `rbx` contains CCargen*
    * should compare ScenarioType against 0xFFFFFFFF and do `jz      short loc_EA4F43`

* sub_F0B1D4 | Patch41.4
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xF0B1DE - 0xF0B1D8 = 0x6
    * `rcx` contains CCargen*
    * save `rcx`
    * should compare ScenarioType against 0xFFFFFFFF and do `jz      short loc_F0B1FA`

* sub_E4889C | Patch42.2
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xE48968 - 0xE48962 = 0x6
    * `rdi` contains CCargen*
    * should compare ScenarioType against 0xFFFFFFFF and do `jz      short loc_E48975`

* sub_E4ED24 | Patch44
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xE4ED61 - 0xE4ED57 = 0xA
    * `rbx` contains CCargen*
    * should compare ScenarioType against 0xFFFFFFFF and do `jnz     loc_E4EE54`
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xE4EDCC - 0xE4EDC6 = 0x6
    * `rbx` contains CCargen*
    * should compare ScenarioType against 0xFFFFFFFF and do `jnz     short loc_E4EDD3`

* sub_EA13FC | Patch45
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xEA14B3 - 0xEA14AD = 0x6
    * `rbx` contains CCargen*
    * should compare ScenarioType against 0xFFFFFFFF and do `jz      short loc_EA14DC`
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xEA1525 - 0xEA151B = 0xA
    * `rbx` contains CCargen*
    * should compare ScenarioType against 0xFFFFFFFF and do `jz      loc_EA1681`
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xEA1582 - 0xEA157C = 0x6
    * `rbx` contains CCargen*
    * should compare ScenarioType against 0xFFFFFFFF and do `jz      short loc_EA1591`
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xEA1656 - 0xEA164D = 0x9
    * `rbx` contains CCargen*
    * should do `mov     [rbx+20h], eax`
    * save `rax`
    * should compare ScenarioType against 0xFFFFFFFF and do `jnz     short loc_EA1660`

* sub_C00AE4 | Patch46
  * accesses CCargen::ScenarioType
    * 0xC00AF0 - 0xC00AEA = 0x6
    * `rcx` contains CCargen*
    * `ecx` should contain ScenarioType
    * should do `test    ecx, ecx`

* sub_E4EAD4 | Patch47
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xE4EAF5 - 0xE4EAEE = 0x7
    * `rcx` contains CCargen*
    * save `rcx`
    * should compare ScenarioType against 0xFFFFFFFF
    * should do `mov     r14, rdx`
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xE4EBE6 - 0xE4EBE0 = 0x6
    * `rdi` contains CCargen*
    * should compare ScenarioType against 0xFFFFFFFF and do `jz      short loc_E4EC64`

* sub_C1DAF8 | Patch48
  * accesses CScenarioPoint::iType
    * 0xC1DB69 - 0xC1DB64 = 0x5
    * `r15` contains CScenarioPoint*
    * `edx` should contain iType
    * save `rcx`

* sub_BF38F4 | Patch49
  * accesses CScenarioPoint::ModelSetId and compares it against 0xFF
    * 0xBF3DDC - 0xBF3DD7 = 0x5
    * `r14` contains CScenarioPoint*
    * should compare ModelSetId against 0xFFFFFFFF

* sub_C1D4C8 | Patch50
  * accesses CScenarioPoint::iType
    * 0xC1D643 - 0xC1D63D = 0x6
    * `[rbp-80h]` contains CScenarioPoint*
    * `eax` and `ecx` should contain iType

* sub_E4E300 | Patch51
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xE4E355 - 0xE4E34D = 0x8
    * `rbx` contains CCargen*
    * should compare ScenarioType against 0xFFFFFFFF and do `setnz   sil`

* sub_E93BF0 | Patch41.5
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xE93C4F - 0xE93C45 = 0xA
    * `rcx` contains CCargen*
    * save `rcx`
    * should compare ScenarioType against 0xFFFFFFFF and do `jnz     loc_E94046`

* sub_E98868 | Patch41.6
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xE98872 - 0xE9886C = 0xA
    * `rcx` contains CCargen*
    * save `rcx`
    * should compare ScenarioType against 0xFFFFFFFF and do `jz      short loc_E9888B`

* sub_EA6DAC | Patch52
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xEA709D - 0xEA7095 = 0x8
    * `rax`  contains CCargen*
    * save `rax`
    * use call_rcx
    * should compare ScenarioType against 0xFFFFFFFF
    * should do `mov     [rbp-19h], r13`
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xEA783B - 0xEA7833 = 0x8
    * should do `mov     rdx, [r14+48h]`
    * `rdx`  contains CCargen*
    * should compare ScenarioType against 0xFFFFFFFF

* sub_EFF584 | Patch53
  * accesses CCargen::ScenarioType and compares it against 0xFF
    * 0xEFF6B9 - 0xEFF6B2 = 0x7
    * 0xEFF6DB - 0xEFF6D4 = 0x7
    * 0xEFF767 - 0xEFF760 = 0x7
    * `r14` contains CCargen*

* sub_BE9A74 | Patch54
  * accesses CScenarioPoint::iType
    * 0xBE9A9C - 0xBE9A94 = 0x8
    * `rbx` contains CScenarioPoint*
    * `ecx` should contain iType
    * save `rax` and `rdx`
    * should do `movzx   eax, word ptr [rdx+10h]`

* sub_C18278 | Patch55
  * accesses CScenarioPoint::iType
    * 0xC18352 - 0xC1834D = 0x5
    * `r10` contains CScenarioPoint*
    * `r12d` should contain iType
    * save `rdx`

* sub_C08BA0 | Patch56
  * accesses CScenarioPoint::iType
    * 0xC08BBC - 0xC08BB3 = 0x9
    * `rbx` contains CScenarioPoint*
    * should call `IsScenarioVehicleInfo`

* sub_BF2C94 | Patch57
  * accesses CScenarioPoint::iType
    * 0xBF2D7F - 0xBF2D78 = 0x7
    * `rdi` contains CScenarioPoint*
    * `ecx` should contain iType
    * should do `mov     rdx, r15`

* sub_C222A8 | Patch58
  * accesses CScenarioPoint::iType
    * 0xC2232F - 0xC22324 = 0xB
    * `rbp` contains CScenarioPoint*
    * `ecx` should contain iType
    * should do `mov     r13, [rbx+10B0h]`

* sub_C1DD14 | Patch59
  * accesses CScenarioPoint::iType
    * 0xC1DEAD - 0xC1DEA8 = 0x5
    * `r15` contains CScenarioPoint*
    * `r9d` should contain iType
