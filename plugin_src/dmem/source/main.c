#include "plugin_common.h"
#include "Common.h"
// #include <stdbool.h>

attr_public const char *g_pluginName = "dmem";
attr_public const char *g_pluginDesc = "Used for testing various memory behaviors";
attr_public const char *g_pluginAuth = "stephen, red_prig";
attr_public u32 g_pluginVersion = 0x00000100; // 1.00

extern size_t Detour_GetInstructionSize(Detour* This, uint64_t Address, size_t MinSize);
extern void Detour_WriteJump64(Detour* This, void* Address, uint64_t Destination);
extern void Detour_WriteJump32(Detour* This, void* Address, uint64_t Destination);

//jmp -7 -> 0xEB 0xF9
uint8_t JumpInstructions16[2] = { 0xEB , 0xF9 };

void Detour_WriteJump16(Detour* This, void* Address) {
    sceKernelMprotect((void*)Address, 2, VM_PROT_ALL);
    memcpy(Address, JumpInstructions16, sizeof(JumpInstructions16));
}

void* Detour_DetourFunction16(Detour* This, uint64_t FunctionPtr, void* HookPtr) {
    if (!FunctionPtr || !HookPtr) {
#if (DEBUG) == 1
        klog("[Detour] %s: FunctionPtr or HookPtr NULL (%p -> %p)\n", __FUNCTION__, (void*)FunctionPtr, HookPtr);
#endif
        return NULL;
    }

    size_t InstructionSize = Detour_GetInstructionSize(This, FunctionPtr, sizeof(JumpInstructions16));

#if (DEBUG) == 1
    klog("[Detour] %s: - InstructionSize: %zu\n", __FUNCTION__, InstructionSize);
#endif

    if (InstructionSize < sizeof(JumpInstructions16)) {
#if (DEBUG) == 1
        klog("[Detour] %s: Hooking Requires a minimum of %d bytes to write jump!\n", __FUNCTION__, (int)sizeof(This->JumpInstructions64));
#endif
        return NULL;
    }

    This->TrampolinePtr = malloc(sizeof(This->JumpInstructions64));

    if (This->TrampolinePtr == 0) {
#if (DEBUG) == 1
        klog("[Detour] %s: malloc failed.\n", __FUNCTION__);
#endif
        return 0;
    }

    Detour_WriteJump64(This, This->TrampolinePtr, (uint64_t)HookPtr);

    // Save Pointers for later
    This->FunctionPtr = (void*)FunctionPtr;
    This->HookPtr = HookPtr;

    // Set protection.
    sceKernelMprotect((void*)(FunctionPtr - 5), InstructionSize + 5, VM_PROT_ALL);

    //Allocate Executable memory for stub and write instructions to stub and a jump back to original execution.
    This->StubSize = (InstructionSize + sizeof(This->JumpInstructions64));

    int res = sceKernelMmap(0, This->StubSize, VM_PROT_ALL, 0x1000 | 0x2, -1, 0, &This->StubPtr);

    if (res < 0 || This->StubPtr == 0) {
#if (DEBUG) == 1
        klog("[Detour] %s: sceKernelMmap failed (0x%X).\n", __FUNCTION__, res);
#endif
        return 0;
    }

    memcpy(This->StubPtr, (void*)FunctionPtr, InstructionSize);
    Detour_WriteJump64(This, (void*)((uint64_t)This->StubPtr + InstructionSize), (uint64_t)(FunctionPtr + InstructionSize));

    //write back jump
    memset((void*)FunctionPtr, 0x90, InstructionSize);
    Detour_WriteJump16(This, (void*)FunctionPtr);

    // Write jump from function to hook.
    Detour_WriteJump32(This, (void*)(FunctionPtr - 5), (uint64_t)This->TrampolinePtr);
    
#if (DEBUG) == 1
    klog("[Detour] %s: Detour Written Successfully! (FunctionPtr: %p - HookPtr: %p - HookPtrTrampoline: %p - StubPtr: %p - StubSize: %zu)\n", __FUNCTION__, This->FunctionPtr, This->HookPtr, This->TrampolinePtr, This->StubPtr, This->StubSize);
#endif

    return This->StubPtr;
};

#define HOOK16(name) do { \
    klog("%s:%d HOOK16() Create " #name "\n", __FUNCTION__, __LINE__);  \
    Detour_Construct( (&(Detour_##name)), DetourMode_x32);                                 \
    Detour_DetourFunction16( (&(Detour_##name)), (uint64_t)name, (void *)(&(name##_hook)) ); \
} while (0)

HOOK_INIT(mmap);
HOOK_INIT(sceKernelMapNamedFlexibleMemory);
HOOK_INIT(sceKernelMapFlexibleMemory);
HOOK_INIT(sceKernelMapDirectMemory);
HOOK_INIT(sceKernelMunmap);
HOOK_INIT(sceKernelOpen);
HOOK_INIT(sceKernelStat);
HOOK_INIT(sceKernelVirtualQuery);

HOOK_INIT(scePthreadCreate);
HOOK_INIT(scePthreadExit);

HOOK_INIT(sceGnmMapComputeQueue);
HOOK_INIT(sceGnmMapComputeQueueWithPriority);
HOOK_INIT(sceGnmUnmapComputeQueue);

HOOK_INIT(sceKernelGetCompiledSdkVersion);
HOOK_INIT(sceKernelGetAppInfo);

HOOK_INIT(sceFiberReturnToThread);
HOOK_INIT(sceFiberRun);
HOOK_INIT(sceFiberSwitch);

HOOK_INIT(scePadSetVibration);

// Function defs
//int sceKernelMapFlexibleMemory(void**, size_t, int, int);
//int sceKernelMapNamedFlexibleMemory(void**, size_t, int, int, const char*);
//int sceKernelOpen(const char*, int, OrbisKernelMode);
//int sceKernelVirtualQuery(const void *, int, OrbisKernelVirtualQueryInfo *, size_t);
//void* mmap(void* addr, uint64_t len, int prot, int flags, int fd, uint64_t pos);

void* sceGnmMapComputeQueue;
void* sceGnmMapComputeQueueWithPriority;
void* sceGnmUnmapComputeQueue;

int (*sceFiberGetSelf)       (void** fiber);
int (*sceFiberReturnToThread)(uint64_t argOnReturn, uint64_t* argOnRun);
int (*sceFiberRun)           (void* fiber, uint64_t argOnRunTo, uint64_t* argOnReturn);
int (*sceFiberSwitch)        (void* fiber, uint64_t argOnRunTo, uint64_t* argOnRun);

int (*scePadSetVibration)(int handle, void* pParam);


#define GET_SELF_NAME() \
    char Selfname[32+4+10+1] = {}; \
    { \
     scePthreadGetname(scePthreadSelf(), &Selfname); \
     void* ftmp = {}; \
     sceFiberGetSelf(&ftmp); \
     if (ftmp != NULL) { \
      int len = strnlen(&Selfname, 32); \
      snprintf(&Selfname[len], 4 + 10 + 1, ":F0x%010llX", ftmp); \
     } \
    }

[[gnu::force_align_arg_pointer]]
void* mmap_hook(void* addr, uint64_t len, int prot, int flags, int fd, uint64_t pos) {

    final_printf("[GoldHEN] mmap-> called on 0x%010llX,0x%010llX,0x%02llX,0x%08llX,%d,0x%010llX \n", addr, len, prot, flags, fd, pos);

    void* ret = HOOK_CONTINUE(mmap, void*(*)(void*, uint64_t, int, int, int, uint64_t), addr, len, prot, flags, fd, pos);

    final_printf("[GoldHEN] mmap<- returning = 0x%p\n", ret);

    return ret;

}

[[gnu::force_align_arg_pointer]]
int32_t sceKernelMapNamedFlexibleMemory_hook(void** addr, uint64_t len, int prot, int flags, const char* name) {

  GET_SELF_NAME();

  final_printf("[GoldHEN] [%s] sceKernelMapNamedFlexibleMemory-> called on 0x%010llX,0x%010llX,0x%02llX,0x%08llX,%s \n", &Selfname, *addr, len, prot, flags, name);

  int32_t ret = HOOK_CONTINUE(sceKernelMapNamedFlexibleMemory, int(*)(void**, uint64_t, int, int, const char*), addr, len, prot, flags, name);
  
  final_printf("[GoldHEN] [%s] sceKernelMapNamedFlexibleMemory<- called on 0x%010llX, returning = 0x%08llX\n", &Selfname, *addr, ret);

  return ret;
};

[[gnu::force_align_arg_pointer]]
int32_t sceKernelMapFlexibleMemory_hook(void** addr, uint64_t len, int prot, int flags) {

  GET_SELF_NAME();

  final_printf("[GoldHEN] [%s] sceKernelMapFlexibleMemory-> called on 0x%010llX,0x%010llX,0x%02llX,0x%08llX \n", &Selfname, *addr, len, prot, flags);

  int32_t ret = HOOK_CONTINUE(sceKernelMapFlexibleMemory, int(*)(void**, uint64_t, int, int), addr, len, prot, flags);

  final_printf("[GoldHEN] [%s] sceKernelMapFlexibleMemory<- called on 0x%010llX, returning = 0x%08llX\n", &Selfname, *addr, ret);

  return ret;
};

[[gnu::force_align_arg_pointer]]
int32_t sceKernelMapDirectMemory_hook(void** addr, uint64_t len, int prot, int flags, uint64_t directMemoryStart, uint64_t alignment) {

    GET_SELF_NAME();

    final_printf("[GoldHEN] [%s] sceKernelMapDirectMemory-> called on 0x%010llX,0x%010llX,0x%02llX,0x%08llX,0x%08llX,0x%08llX \n", &Selfname, *addr, len, prot, flags, directMemoryStart, alignment);

    int32_t ret = HOOK_CONTINUE(sceKernelMapDirectMemory, int(*)(void**, uint64_t, int, int, uint64_t, uint64_t), addr, len, prot, flags, directMemoryStart, alignment);

    final_printf("[GoldHEN] [%s] sceKernelMapDirectMemory<- called on 0x%010llX, returning = 0x%08llX\n", &Selfname, *addr, ret);

    return ret;
}

[[gnu::force_align_arg_pointer]]
int sceKernelMunmap_hook(void* addr, uint64_t len) {

    GET_SELF_NAME();

    final_printf("[GoldHEN] [%s] sceKernelMunmap-> called on 0x%010llX,0x%010llX \n", &Selfname, addr, len);

    int32_t ret = HOOK_CONTINUE(sceKernelMunmap, int(*)(void*, uint64_t), addr, len);

    final_printf("[GoldHEN] [%s] sceKernelMunmap<- called on 0x%010llX, returning = 0x%08llX\n", &Selfname, addr, ret);

    return ret;
}


[[gnu::force_align_arg_pointer]]
int sceKernelOpen_hook(const char* path, int flags, OrbisKernelMode mode) {

  GET_SELF_NAME();

  int ret = HOOK_CONTINUE(sceKernelOpen, int(*)(const char*, int, OrbisKernelMode), path, flags, mode);

  final_printf("[GoldHEN] [%s] sceKernelOpen called on path %s, returning = %d\n", &Selfname, path, ret);

  return ret;
};

[[gnu::force_align_arg_pointer]]
int sceKernelStat_hook(const char* path, void* sb) {

    GET_SELF_NAME();

    int ret = HOOK_CONTINUE(sceKernelStat, int(*)(const char* path, void* sb), path, sb);

    final_printf("[GoldHEN] [%s] sceKernelStat called on path %s, returning = %d\n", &Selfname, path, ret);

    return ret;
}

typedef struct {
    void* start_addr;
    void* end_addr;
    off_t offset;
    int32_t prot;
    int32_t mtype;
    unsigned isFlexibleMemory : 1;
    unsigned isDirectMemory : 1;
    unsigned isStack : 1;
    unsigned isPooledMemory : 1;
    unsigned isCommitted : 1;
    char name[32];
} _OrbisKernelVirtualQueryInfo;

[[gnu::force_align_arg_pointer]]
int sceKernelVirtualQuery_hook(const void * addr, int flags, _OrbisKernelVirtualQueryInfo * info, uint64_t size) {

  GET_SELF_NAME();

  final_printf("[GoldHEN] [%s] sceKernelVirtualQuery-> called on 0x%010llX,%d \n", &Selfname, addr, flags);

  int ret = HOOK_CONTINUE(sceKernelVirtualQuery, int(*)(const void *, int, _OrbisKernelVirtualQueryInfo *, uint64_t), addr, flags, info, size);
  
  final_printf("[GoldHEN] [%s] sceKernelVirtualQuery<- called on 0x%010llX, returning = %d\n"
               "  start =0x%010llX\n"
               "  end   =0x%010llX\n"
               "  offset=0x%010lX\n"
               "  prot  =0x%02X\n"
               "  mtype =%d\n"
               "  isFlexibleMemory=%d\n"
               "  isDirectMemory  =%d\n"
               "  isStack         =%d\n"
               "  isPooledMemory  =%d\n"
               "  isCommitted     =%d\n"
               "  name =%s\n"
   ,
   &Selfname,
   addr, ret,
   info->start_addr,
   info->end_addr,
   info->offset,
   info->prot,
   info->mtype,
   info->isFlexibleMemory,
   info->isDirectMemory,
   info->isStack,
   info->isPooledMemory,
   info->isCommitted,
   info->name
  );
  

  return ret;
};

[[gnu::force_align_arg_pointer]]
int scePthreadCreate_hook(void** thread, void* attr, void* func, void* arg, const char* name) {

    GET_SELF_NAME();

    final_printf("[GoldHEN] [%s] scePthreadCreate(%s) \n", &Selfname, name);

    int ret = HOOK_CONTINUE(scePthreadCreate, int(*)(void** thread, void* attr, void* func, void* arg, const char* name), thread, attr, func, arg, name);

    return ret;
};

[[gnu::force_align_arg_pointer]]
void scePthreadExit_hook(void* value_ptr) {

    GET_SELF_NAME();

    final_printf("[GoldHEN] [%s] scePthreadExit(0x%010llX)\n", &Selfname, value_ptr);

    HOOK_CONTINUE(scePthreadExit, void(*)(void*), value_ptr);

}

[[gnu::force_align_arg_pointer]]
int sceGnmMapComputeQueue_hook(uint globalPipeId, uint queueId, void* ringBaseAddr, uint ringSizeInDW, void* readPtrAddr) {

    GET_SELF_NAME();

    int ret = HOOK_CONTINUE(sceGnmMapComputeQueue, int(*)(uint, uint, void*, uint, void*), globalPipeId, queueId, ringBaseAddr, ringSizeInDW, readPtrAddr);

    final_printf("[GoldHEN] [%s] sceGnmMapComputeQueue(%d,%d,0x%010llX,%d,0x%010llX), returning = %d\n", &Selfname, globalPipeId, queueId, ringBaseAddr, ringSizeInDW, readPtrAddr, ret);

    return ret;
};

[[gnu::force_align_arg_pointer]]
int sceGnmMapComputeQueueWithPriority_hook(uint globalPipeId, uint queueId, void* ringBaseAddr, uint ringSizeInDW, void* readPtrAddr, uint pipePriority) {

    GET_SELF_NAME();

    int ret = HOOK_CONTINUE(sceGnmMapComputeQueueWithPriority, int(*)(uint, uint, void*, uint, void*, uint), globalPipeId, queueId, ringBaseAddr, ringSizeInDW, readPtrAddr, pipePriority);

    final_printf("[GoldHEN] [%s] sceGnmMapComputeQueueWithPriority(%d,%d,0x%010llX,%d,0x%010llX,%d), returning = %d\n", &Selfname, globalPipeId, queueId, ringBaseAddr, ringSizeInDW, readPtrAddr, pipePriority, ret);

    return ret;
};

[[gnu::force_align_arg_pointer]]
void sceGnmUnmapComputeQueue_hook(uint vqueueId) {

    GET_SELF_NAME();

    HOOK_CONTINUE(sceGnmUnmapComputeQueue, int(*)(uint), vqueueId);

    final_printf("[GoldHEN] [%s] sceGnmUnmapComputeQueue(%d)\n", &Selfname, vqueueId);
};

[[gnu::force_align_arg_pointer]]
int sceKernelGetCompiledSdkVersion_hook(uint* p_sdk_version) {

    GET_SELF_NAME();

    int ret = HOOK_CONTINUE(sceKernelGetCompiledSdkVersion, int(*)(uint*), p_sdk_version);

    final_printf("[GoldHEN] [%s] sceKernelGetCompiledSdkVersion(0x%08llX), returning = %d\n", &Selfname, *p_sdk_version, ret);

    return ret;
};

typedef struct
{
    int32_t version;
    int32_t;
    uint64_t ids_bits[2];
} OrbisTitleWorkaround;

typedef struct
{
    int32_t  AppId;
    int32_t  mmap_flags;
    int32_t  attributeExe;
    int32_t  AppType;
    char     TitleId[10];
    uint8_t  debug_level;
    uint8_t  slv_flags;
    uint8_t  miniAppDmemFlags;
    uint8_t  render_mode;
    uint8_t  mdbg_out;
    uint8_t  requiredHdcpType;
    uint64_t preloadPrxFlags;
    int32_t  attribute;
    int32_t  hasParamSfo;
    OrbisTitleWorkaround TitleWorkaround;
} OrbisAppInfo;

[[gnu::force_align_arg_pointer]]
int sceKernelGetAppInfo_hook(int pid, OrbisAppInfo* app_info) {

    GET_SELF_NAME();

    int ret = HOOK_CONTINUE(sceKernelGetAppInfo, int(*)(int, int*), pid, app_info);

    final_printf("[GoldHEN] [%s] sceKernelGetAppInfo() returning = %d\n"
                 "  AppId           =0x%08llX\n"
                 "  mmap_flags      =0x%08llX\n"
                 "  attributeExe    =0x%08llX\n"
                 "  AppType         =0x%08llX\n"
                 "  TitleId         =%s\n"
                 "  debug_level     =0x%02llX\n"
                 "  slv_flags       =0x%02llX\n"
                 "  miniAppDmemFlags=0x%02llX\n"
                 "  render_mode     =0x%02llX\n"
                 "  mdbg_out        =0x%02llX\n"
                 "  requiredHdcpType=0x%02llX\n"
                 "  preloadPrxFlags =0x%016llX\n"
                 "  attribute       =0x%08llX\n"
                 "  hasParamSfo     =0x%08llX\n"
                 "  version         =0x%08llX\n"
                 "  ids_bits[0]     =0x%016llX\n"
                 "  ids_bits[1]     =0x%016llX\n"
        ,
        &Selfname,
        ret,
        app_info->AppId,
        app_info->mmap_flags,
        app_info->attributeExe,
        app_info->AppType,
        app_info->TitleId,
        app_info->debug_level,
        app_info->slv_flags,
        app_info->miniAppDmemFlags,
        app_info->render_mode,
        app_info->mdbg_out,
        app_info->requiredHdcpType,
        app_info->preloadPrxFlags,
        app_info->attribute,
        app_info->hasParamSfo,
        app_info->TitleWorkaround.version,
        app_info->TitleWorkaround.ids_bits[0],
        app_info->TitleWorkaround.ids_bits[1]
    );


    //final_printf("[GoldHEN] [%s] sceKernelGetAppInfo(), AppId = 0x%08llX, mmap_flags = %d, returning = %d\n", &Selfname, app_info[0], app_info[1], ret);

    return ret;
};

[[gnu::force_align_arg_pointer]]
int sceFiberReturnToThread_hook(uint64_t argOnReturn, uint64_t* argOnRun) {

    {
        GET_SELF_NAME();
        final_printf("[GoldHEN] [%s] ->sceFiberReturnToThread(0x%016llX,)\n", &Selfname, argOnReturn);
    }

    int ret = HOOK_CONTINUE(sceFiberReturnToThread, int(*)(uint64_t, uint64_t*), argOnReturn, argOnRun);

    {
        GET_SELF_NAME();
        final_printf("[GoldHEN] [%s] <-sceFiberReturnToThread(,0x%016llX), returning = %d\n", &Selfname, *argOnRun, ret);
    }

    return ret;
};

[[gnu::force_align_arg_pointer]]
int sceFiberRun_hook(void* fiber, uint64_t argOnRunTo, uint64_t* argOnReturn) {

    {
        GET_SELF_NAME();
        final_printf("[GoldHEN] [%s] ->sceFiberRun(0x%010llX,0x%016llX,)\n", &Selfname, fiber, argOnRunTo);
    }

    int ret = HOOK_CONTINUE(sceFiberRun, int(*)(void*, uint64_t, uint64_t*), fiber, argOnRunTo, argOnReturn);

    {
        GET_SELF_NAME();
        final_printf("[GoldHEN] [%s] <-sceFiberRun(0x%010llX,,0x%016llX), returning = %d\n", &Selfname, fiber, *argOnReturn, ret);
    }

    return ret;
};

[[gnu::force_align_arg_pointer]]
int sceFiberSwitch_hook(void* fiber, uint64_t argOnRunTo, uint64_t* argOnRun) {

    {
        GET_SELF_NAME();
        final_printf("[GoldHEN] [%s] ->sceFiberSwitch(0x%010llX)\n", &Selfname, fiber);
    }

    int ret = HOOK_CONTINUE(sceFiberSwitch, int(*)(void*, uint64_t, uint64_t*), fiber, argOnRunTo, argOnRun);

    {
        GET_SELF_NAME();
        final_printf("[GoldHEN] [%s] <-sceFiberSwitch(0x%010llX), returning = %d\n", &Selfname, fiber, ret);
    }

    return ret;
};

[[gnu::force_align_arg_pointer]]
int scePadSetVibration_hook(int handle, void* pParam) {

    GET_SELF_NAME();
    final_printf("[GoldHEN] [%s] ->scePadSetVibration(0x%08llX,0x%010llX)\n", &Selfname, handle, pParam);

    int ret = HOOK_CONTINUE(scePadSetVibration, int(*)(int, void*), handle, pParam);

    final_printf("[GoldHEN] [%s] <-scePadSetVibration(), returning = %d\n", &Selfname, ret);

    return ret;
};


[[gnu::force_align_arg_pointer]]
int32_t attr_public plugin_load(s32 argc, const char* argv[]) {

  final_printf("[GoldHEN] <%s\\Ver.0x%08x> %s\n", g_pluginName, g_pluginVersion, __func__);
  final_printf("[GoldHEN] Plugin Author(s): %s\n", g_pluginAuth);
  boot_ver();

  HOOK32(sceKernelMapNamedFlexibleMemory);
  HOOK16(sceKernelMapFlexibleMemory);
  HOOK32(sceKernelMapDirectMemory);
  HOOK16(sceKernelMunmap);
  HOOK32(sceKernelOpen);
  HOOK16(sceKernelStat);
  HOOK16(sceKernelVirtualQuery);

  HOOK16(scePthreadCreate);
  HOOK16(scePthreadExit);

  s32 h = 0;
  sys_dynlib_load_prx("libSceGnmDriver.sprx", &h);
  sys_dynlib_dlsym(h, "sceGnmMapComputeQueue"            , &sceGnmMapComputeQueue);
  sys_dynlib_dlsym(h, "sceGnmMapComputeQueueWithPriority", &sceGnmMapComputeQueueWithPriority);
  sys_dynlib_dlsym(h, "sceGnmUnmapComputeQueue"          , &sceGnmUnmapComputeQueue);

  HOOK32(sceGnmMapComputeQueue);
  HOOK32(sceGnmMapComputeQueueWithPriority);
  HOOK16(sceGnmUnmapComputeQueue);

  HOOK32(sceKernelGetCompiledSdkVersion);
  HOOK32(sceKernelGetAppInfo);

  h = 0;
  sys_dynlib_load_prx("libSceFiber.sprx", &h);
  sys_dynlib_dlsym(h, "sceFiberGetSelf"       , &sceFiberGetSelf);
  sys_dynlib_dlsym(h, "sceFiberReturnToThread", &sceFiberReturnToThread);
  sys_dynlib_dlsym(h, "sceFiberRun"           , &sceFiberRun);
  sys_dynlib_dlsym(h, "sceFiberSwitch"        , &sceFiberSwitch);

  HOOK32(sceFiberReturnToThread);
  HOOK32(sceFiberRun);
  HOOK32(sceFiberSwitch);

  h = 0;
  sys_dynlib_load_prx("libScePad.sprx", &h);
  sys_dynlib_dlsym(h, "scePadSetVibration", &scePadSetVibration);

  HOOK32(scePadSetVibration);

  return 0;
};

[[gnu::force_align_arg_pointer]]
int32_t attr_public plugin_unload(s32 argc, const char* argv[]) {

  final_printf("[GoldHEN] UNHOOKED\n");

  UNHOOK(sceKernelMapNamedFlexibleMemory);
  UNHOOK(sceKernelMapFlexibleMemory);
  UNHOOK(sceKernelMapDirectMemory);
  UNHOOK(sceKernelMunmap);
  UNHOOK(sceKernelOpen);
  UNHOOK(sceKernelStat);
  UNHOOK(sceKernelVirtualQuery);

  UNHOOK(scePthreadCreate);
  UNHOOK(scePthreadExit);

  UNHOOK(sceGnmMapComputeQueue);
  UNHOOK(sceGnmMapComputeQueueWithPriority);
  UNHOOK(sceGnmUnmapComputeQueue);

  UNHOOK(sceKernelGetCompiledSdkVersion);
  UNHOOK(sceKernelGetAppInfo);

  UNHOOK(sceFiberReturnToThread);
  UNHOOK(sceFiberRun);
  UNHOOK(sceFiberSwitch);

  UNHOOK(scePadSetVibration);

  return 0;
};

s32 attr_module_hidden module_start(s64 argc, const void *args)
{
    return 0;
};

s32 attr_module_hidden module_stop(s64 argc, const void *args)
{
    return 0;
};

