#include "plugin_common.h"
#include "Common.h"
// #include <stdbool.h>

attr_public const char *g_pluginName = "dmem";
attr_public const char *g_pluginDesc = "Used for testing various memory behaviors";
attr_public const char *g_pluginAuth = "stephen";
attr_public u32 g_pluginVersion = 0x00000100; // 1.00

HOOK_INIT(mmap);
HOOK_INIT(sceKernelMapNamedFlexibleMemory);
HOOK_INIT(sceKernelMapFlexibleMemory);
HOOK_INIT(sceKernelOpen);
HOOK_INIT(sceKernelVirtualQuery);

// Function defs
//int sceKernelMapFlexibleMemory(void**, size_t, int, int);
//int sceKernelMapNamedFlexibleMemory(void**, size_t, int, int, const char*);
//int sceKernelOpen(const char*, int, OrbisKernelMode);
//int sceKernelVirtualQuery(const void *, int, OrbisKernelVirtualQueryInfo *, size_t);
void* mmap(void* addr, uint64_t len, int prot, int flags, int fd, uint64_t pos);


[[gnu::force_align_arg_pointer]]
void* mmap_hook(void* addr, uint64_t len, int prot, int flags, int fd, uint64_t pos) {

    final_printf("[GoldHEN] mmap-> called on 0x%010llX,0x%010llX,0x%02llX,0x%08llX,%d,0x%010llX \n", addr, len, prot, flags, fd, pos);

    void* ret = HOOK_CONTINUE(mmap, void*(*)(void*, uint64_t, int, int, int, uint64_t), addr, len, prot, flags, fd, pos);

    final_printf("[GoldHEN] mmap<- returning = 0x%p\n", ret);

    return ret;

}

[[gnu::force_align_arg_pointer]]
int32_t sceKernelMapNamedFlexibleMemory_hook(void** addr, uint64_t len, int prot, int flags, const char* name) {

  int32_t ret = HOOK_CONTINUE(sceKernelMapNamedFlexibleMemory, int(*)(void**, uint64_t, int, int, const char*), addr, len, prot, flags, name);
  
  final_printf("[GoldHEN] sceKernelMapNamedFlexibleMemory called on 0x%010llX, returning = 0x%08llX\n", *addr, ret);

  return ret;
};

[[gnu::force_align_arg_pointer]]
int32_t sceKernelMapFlexibleMemory_hook(void** addr, uint64_t len, int prot, int flags) {

  final_printf("[GoldHEN] sceKernelMapFlexibleMemory-> called on 0x%010llX,0x%010llX,0x%02llX,0x%08llX \n", *addr, len, prot, flags);

  int32_t ret = HOOK_CONTINUE(sceKernelMapFlexibleMemory, int(*)(void**, uint64_t, int, int), addr, len, prot, flags);

  final_printf("[GoldHEN] sceKernelMapFlexibleMemory<- called on 0x%010llX, returning = 0x%08llX\n", *addr, ret);

  return ret;
};

[[gnu::force_align_arg_pointer]]
int sceKernelOpen_hook(const char* path, int flags, OrbisKernelMode mode) {

  int ret = HOOK_CONTINUE(sceKernelOpen, int(*)(const char*, int, OrbisKernelMode), path, flags, mode);

  final_printf("[GoldHEN] sceKernelOpen called on path %s, returning = %d\n", path, ret);

  return ret;
};

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
int sceKernelVirtualQuery_hook(const void * addr, int flags, _OrbisKernelVirtualQueryInfo * info, size_t size) {

  int ret = HOOK_CONTINUE(sceKernelVirtualQuery, int(*)(const void *, int, _OrbisKernelVirtualQueryInfo *, size_t), addr, flags, info, size);

  final_printf("[GoldHEN] sceKernelVirtualQuery called on 0x%010llX, returning = %d\n"
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
int32_t attr_public plugin_load(s32 argc, const char* argv[]) {

  final_printf("[GoldHEN] <%s\\Ver.0x%08x> %s\n", g_pluginName, g_pluginVersion, __func__);
  final_printf("[GoldHEN] Plugin Author(s): %s\n", g_pluginAuth);
  boot_ver();

  //HOOK32(mmap);

  HOOK32(sceKernelMapNamedFlexibleMemory);
  HOOK32(sceKernelMapFlexibleMemory);
  HOOK32(sceKernelOpen);
  HOOK32(sceKernelVirtualQuery);

  return 0;
};

[[gnu::force_align_arg_pointer]]
int32_t attr_public plugin_unload(s32 argc, const char* argv[]) {

  final_printf("[GoldHEN] UNHOOKED\n");

  //UNHOOK(mmap);

  UNHOOK(sceKernelMapNamedFlexibleMemory);
  UNHOOK(sceKernelMapFlexibleMemory);
  UNHOOK(sceKernelOpen);
  UNHOOK(sceKernelVirtualQuery);

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

