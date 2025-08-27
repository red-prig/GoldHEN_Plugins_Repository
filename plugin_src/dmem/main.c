#include "plugin_common.h"
#include "Common.h"
// #include <stdbool.h>

attr_public const char *g_pluginName = "dmem";
attr_public const char *g_pluginDesc = "Used for testing various memory behaviors";
attr_public const char *g_pluginAuth = "stephen";
attr_public u32 g_pluginVersion = 0x00000100; // 1.00

HOOK_INIT(sceKernelMapNamedFlexibleMemory);
HOOK_INIT(sceKernelMapFlexibleMemory);
HOOK_INIT(sceKernelOpen);
HOOK_INIT(sceKernelVirtualQuery);

// Function defs
int (*sceKernelMapFlexibleMemory)     (void**, size_t, int, int);
int (*sceKernelMapNamedFlexibleMemory)(void**, size_t, int, int, const char*);
int (*sceKernelOpen)                  (const char*, int, OrbisKernelMode);
int (*sceKernelVirtualQuery)          (const void *, int, OrbisKernelVirtualQueryInfo *, size_t);

__attribute__ ((force_align_arg_pointer))
int32_t sceKernelMapNamedFlexibleMemory_hook(void** addr, size_t len, int prot, int flags, const char* name) {

  final_printf("[1]");

  int32_t ret = HOOK_CONTINUE(sceKernelMapNamedFlexibleMemory, int(*)(void**, size_t, int, int, const char*), addr, len, prot, flags, name);

  final_printf("[GoldHEN] sceKernelMapNamedFlexibleMemory called on 0x%010llX, returning = %d\n", *addr,  ret);

  return ret;
};

__attribute__ ((force_align_arg_pointer))
int32_t sceKernelMapFlexibleMemory_hook(void** addr, size_t len, int prot, int flags) {

  final_printf("[2]");

  int32_t ret = HOOK_CONTINUE(sceKernelMapFlexibleMemory, int(*)(void**, size_t, int, int), addr, len, prot, flags);

  final_printf("[GoldHEN] sceKernelMapFlexibleMemory called on 0x%010llX, returning = %d\n", *addr,  ret);

  return ret;
};

__attribute__ ((force_align_arg_pointer))
int sceKernelOpen_hook(const char* path, int flags, OrbisKernelMode mode) {
  int ret = HOOK_CONTINUE(sceKernelOpen, int(*)(const char*, int, OrbisKernelMode), path, flags, mode);

  final_printf("[GoldHEN] sceKernelOpen called on path %s, returning = %p\n", path, ret);

  return ret;
};

__attribute__ ((force_align_arg_pointer))
int sceKernelVirtualQuery_hook(const void * addr, int flags, OrbisKernelVirtualQueryInfo * info, size_t size) {

  int ret = HOOK_CONTINUE(sceKernelVirtualQuery, int(*)(const void *, int, OrbisKernelVirtualQueryInfo *, size_t),
     addr, flags, info, size);

  final_printf("[GoldHEN] sceKernelVirtualQuery called on 0x%010llX, returning = %d\n"
               "  start =0x%010llX\n"
               "  end   =0x%010llX\n"
               "  offset=0x%010llX\n"
               "  prot  =0x%02llX\n"
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

__attribute__ ((force_align_arg_pointer))
int32_t attr_public plugin_load(s32 argc, const char* argv[]) {
  final_printf("[GoldHEN] <%s\\Ver.0x%08x> %s\n", g_pluginName, g_pluginVersion, __func__);
  final_printf("[GoldHEN] Plugin Author(s): %s\n", g_pluginAuth);
  boot_ver();

  s32 h = 0;
  sys_dynlib_load_prx("libkernel.sprx", &h);
  sys_dynlib_dlsym(h, "sceKernelMapNamedFlexibleMemory", &sceKernelMapNamedFlexibleMemory);
  sys_dynlib_dlsym(h, "sceKernelMapFlexibleMemory", &sceKernelMapFlexibleMemory);
  sys_dynlib_dlsym(h, "sceKernelOpen", &sceKernelOpen);
  sys_dynlib_dlsym(h, "sceKernelVirtualQuery", &sceKernelVirtualQuery);

  HOOK(sceKernelMapNamedFlexibleMemory);
  HOOK(sceKernelMapFlexibleMemory);
  HOOK(sceKernelOpen);
  HOOK(sceKernelVirtualQuery);
  return 0;
};


__attribute__ ((force_align_arg_pointer))
int32_t attr_public plugin_unload(s32 argc, const char* argv[]) {
  final_printf("[GoldHEN] UNHOOKED\n");
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

