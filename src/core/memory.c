#include "memory.h"

#include <libkern/OSCacheControl.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
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

uintptr_t envy_base(const char *module)
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

bool envy_read(uintptr_t addr, void *out, size_t len)
{
    if (addr == 0 || out == NULL || len == 0)
        return false;
    memcpy(out, (const void *)addr, len);
    return true;
}

bool envy_make_rw(uintptr_t addr, size_t len)
{
    uintptr_t page;
    size_t plen;
    if (!page_range(addr, len, &page, &plen))
        return false;
    return vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)plen, 0,
                      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) == KERN_SUCCESS;
}

bool envy_patch(uintptr_t addr, const void *buf, size_t len)
{
    uintptr_t page;
    size_t plen;
    if (addr == 0 || buf == NULL || len == 0 || !page_range(addr, len, &page, &plen))
        return false;

    if (vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)plen, 0,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) == KERN_SUCCESS) {
        memcpy((void *)addr, buf, len);
        vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)plen, 0,
                   VM_PROT_READ | VM_PROT_EXECUTE);
        sys_icache_invalidate((void *)addr, len);
        return true;
    }

    vm_address_t scratch = 0;
    if (vm_allocate(mach_task_self(), &scratch, (vm_size_t)plen, VM_FLAGS_ANYWHERE) != KERN_SUCCESS)
        return false;

    memcpy((void *)scratch, (const void *)page, plen);
    memcpy((void *)(scratch + (addr - page)), buf, len);
    vm_protect(mach_task_self(), scratch, (vm_size_t)plen, 0, VM_PROT_READ | VM_PROT_EXECUTE);

    vm_address_t dst = (vm_address_t)page;
    vm_prot_t cur = 0;
    vm_prot_t max = 0;
    kern_return_t kr = vm_remap(mach_task_self(), &dst, (vm_size_t)plen, 0,
                                VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                                mach_task_self(), scratch, false, &cur, &max, VM_INHERIT_COPY);
    vm_deallocate(mach_task_self(), scratch, (vm_size_t)plen);
    return kr == KERN_SUCCESS;
}