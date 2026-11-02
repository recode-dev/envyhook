#include "memory.h"

#include <libkern/OSCacheControl.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static bool page_range(uintptr_t addr, size_t len, uintptr_t *page, size_t *plen)
{
    if (addr == 0 || len == 0)
        return false;
    uintptr_t ps = (uintptr_t)vm_page_size;
    uintptr_t start = addr & ~(ps - 1);
    uintptr_t end = (addr + len + ps - 1) & ~(ps - 1);
    *page = start;
    *plen = (size_t)(end - start);
    return true;
}

static bool query_protect(uintptr_t addr, vm_prot_t *prot)
{
    vm_address_t region = (vm_address_t)addr;
    vm_size_t size = 0;
    struct vm_region_basic_info_64 info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;

    if (vm_region(mach_task_self(), &region, &size, VM_REGION_BASIC_INFO_64,
                  (vm_region_info_t)&info, &count, &object) != KERN_SUCCESS)
        return false;
    if (object != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), object);
    if ((uintptr_t)region > addr || addr >= (uintptr_t)region + size)
        return false;
    *prot = info.protection;
    return true;
}

uint32_t envy_query_page_size(void)
{
    return (uint32_t)vm_page_size;
}

uintptr_t envy_module_find_base_address(const char *module)
{
    if (module == NULL)
        return 0;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *path = _dyld_get_image_name(i);
        if (path == NULL)
            continue;
        const char *slash = strrchr(path, '/');
        const char *name = (slash != NULL) ? slash + 1 : path;
        if (strcasecmp(name, module) != 0)
            continue;
        return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

bool envy_query_protection(uintptr_t addr, EnvyPageProtection *prot)
{
    vm_prot_t p;
    if (prot == NULL || !query_protect(addr, &p))
        return false;
    EnvyPageProtection out = ENVY_PAGE_NO_PROTECTION;
    if (p & VM_PROT_READ)
        out |= ENVY_PAGE_READ;
    if (p & VM_PROT_WRITE)
        out |= ENVY_PAGE_WRITE;
    if (p & VM_PROT_EXECUTE)
        out |= ENVY_PAGE_EXECUTE;
    *prot = out;
    return true;
}

bool envy_memory_is_readable(uintptr_t addr, size_t len)
{
    if (addr == 0 || len == 0)
        return false;
    uintptr_t cur = addr;
    uintptr_t end = addr + len;
    while (cur < end) {
        vm_address_t region = (vm_address_t)cur;
        vm_size_t size = 0;
        struct vm_region_basic_info_64 info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        if (vm_region(mach_task_self(), &region, &size, VM_REGION_BASIC_INFO_64,
                      (vm_region_info_t)&info, &count, &object) != KERN_SUCCESS)
            return false;
        if (object != MACH_PORT_NULL)
            mach_port_deallocate(mach_task_self(), object);
        if (!(info.protection & VM_PROT_READ))
            return false;
        uintptr_t rend = (uintptr_t)region + size;
        if (rend <= cur)
            return false;
        cur = rend;
    }
    return true;
}

uint8_t *envy_memory_read(uintptr_t addr, size_t len, size_t *n_bytes_read)
{
    if (!envy_memory_is_readable(addr, len))
        return NULL;
    uint8_t *buf = (uint8_t *)malloc(len);
    if (buf == NULL)
        return NULL;
    memcpy(buf, (const void *)addr, len);
    if (n_bytes_read != NULL)
        *n_bytes_read = len;
    return buf;
}

bool envy_memory_write(uintptr_t addr, const void *bytes, size_t len)
{
    if (addr == 0 || bytes == NULL || len == 0)
        return false;
    vm_prot_t saved;
    if (!query_protect(addr, &saved))
        return false;
    if (saved & VM_PROT_WRITE) {
        memcpy((void *)addr, bytes, len);
        return true;
    }
    if (!envy_mprotect(addr, len, ENVY_PAGE_READ | ENVY_PAGE_WRITE))
        return false;
    memcpy((void *)addr, bytes, len);
    uintptr_t page;
    size_t plen;
    page_range(addr, len, &page, &plen);
    vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)plen, 0, saved);
    return true;
}

bool envy_mprotect(uintptr_t addr, size_t len, EnvyPageProtection prot)
{
    uintptr_t page;
    size_t plen;
    if (!page_range(addr, len, &page, &plen))
        return false;
    vm_prot_t vmprot = VM_PROT_NONE;
    if (prot & ENVY_PAGE_READ)
        vmprot |= VM_PROT_READ;
    if (prot & ENVY_PAGE_WRITE)
        vmprot |= VM_PROT_WRITE;
    if (prot & ENVY_PAGE_EXECUTE)
        vmprot |= VM_PROT_EXECUTE;
    if (prot & ENVY_PAGE_WRITE)
        vmprot |= VM_PROT_COPY;
    return vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)plen, 0, vmprot) == KERN_SUCCESS;
}

bool envy_memory_patch_code(uintptr_t addr, size_t len, EnvyPatchCodeFunc func, void *user_data)
{
    uintptr_t page;
    size_t plen;
    if (addr == 0 || len == 0 || func == NULL || !page_range(addr, len, &page, &plen))
        return false;

    if (vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)plen, 0,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) == KERN_SUCCESS) {
        func((void *)addr, user_data);
        vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)plen, 0,
                   VM_PROT_READ | VM_PROT_EXECUTE);
        sys_icache_invalidate((void *)addr, len);
        return true;
    }

    vm_address_t scratch = 0;
    if (vm_allocate(mach_task_self(), &scratch, (vm_size_t)plen, VM_FLAGS_ANYWHERE) != KERN_SUCCESS)
        return false;

    memcpy((void *)scratch, (const void *)page, plen);
    func((void *)(scratch + (addr - page)), user_data);
    vm_protect(mach_task_self(), scratch, (vm_size_t)plen, 0, VM_PROT_READ | VM_PROT_EXECUTE);

    vm_address_t dst = (vm_address_t)page;
    vm_prot_t cur = 0;
    vm_prot_t max = 0;
    kern_return_t kr = vm_remap(mach_task_self(), &dst, (vm_size_t)plen, 0,
                                VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                                mach_task_self(), scratch, false, &cur, &max, VM_INHERIT_COPY);
    vm_deallocate(mach_task_self(), scratch, (vm_size_t)plen);
    if (kr != KERN_SUCCESS)
        return false;
    sys_icache_invalidate((void *)addr, len);
    return true;
}

typedef struct {
    const void *bytes;
    size_t len;
} PatchValue;

static void patch_code_value_cb(void *address, void *user_data)
{
    const PatchValue *pv = (const PatchValue *)user_data;
    memcpy(address, pv->bytes, pv->len);
}

bool envy_memory_patch_code_value(uintptr_t addr, const void *bytes, size_t len)
{
    PatchValue pv = { bytes, len };
    return envy_memory_patch_code(addr, len, patch_code_value_cb, &pv);
}

void envy_clear_cache(uintptr_t addr, size_t len)
{
    if (addr == 0 || len == 0)
        return;
    sys_icache_invalidate((void *)addr, len);
}