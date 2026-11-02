#include "memory.h"

#include <libkern/OSCacheControl.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct {
    const void *bytes;
    size_t len;
} PatchValue;

static bool page_range(uintptr_t addr, size_t len, uintptr_t *page, size_t *plen)
{
    if (addr == 0 || len == 0 || len > (uintptr_t)-1 - addr)
        return false;
    uintptr_t ps = (uintptr_t)vm_page_size;
    uintptr_t end = addr + len;
    *page = addr & ~(ps - 1);
    *plen = (size_t)(((end + ps - 1) & ~(ps - 1)) - *page);
    return true;
}

static bool region_at(uintptr_t addr, uintptr_t *start, size_t *size, vm_prot_t *prot)
{
    vm_address_t region = (vm_address_t)(addr & ~((uintptr_t)vm_page_size - 1));
    vm_size_t rsize = 0;
    struct vm_region_basic_info_64 info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;

    if (vm_region(mach_task_self(), &region, &rsize, VM_REGION_BASIC_INFO_64,
                  (vm_region_info_t)&info, &count, &object) != KERN_SUCCESS)
        return false;
    if (object != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), object);
    if ((uintptr_t)region > addr || addr >= (uintptr_t)region + rsize)
        return false;
    if (start != NULL)
        *start = (uintptr_t)region;
    if (size != NULL)
        *size = (size_t)rsize;
    if (prot != NULL)
        *prot = info.protection;
    return true;
}

static vm_prot_t to_vm_prot(EnvyPageProtection prot)
{
    vm_prot_t out = VM_PROT_NONE;
    if (prot & ENVY_PAGE_READ)
        out |= VM_PROT_READ;
    if (prot & ENVY_PAGE_WRITE)
        out |= VM_PROT_READ | VM_PROT_WRITE;
    if (prot & ENVY_PAGE_EXECUTE)
        out |= VM_PROT_READ | VM_PROT_EXECUTE;
    return out;
}

static bool apply_page_prot(uintptr_t addr, size_t len, EnvyPageProtection prot)
{
    if (addr == 0 || len == 0 || len > (uintptr_t)-1 - addr)
        return false;
    vm_prot_t vmprot = to_vm_prot(prot);
    if (vmprot == VM_PROT_NONE)
        return false;
    return vm_protect(mach_task_self(), (vm_address_t)addr, (vm_size_t)len, 0, vmprot) == KERN_SUCCESS;
}

uint32_t envy_query_page_size(void)
{
    return (uint32_t)vm_page_size;
}

uintptr_t envy_module_find_base_address(const char *module)
{
    if (module == NULL || module[0] == '\0')
        return 0;
    bool by_path = strchr(module, '/') != NULL;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *path = _dyld_get_image_name(i);
        if (path == NULL)
            continue;
        const char *name;
        if (by_path) {
            name = path;
        } else {
            const char *slash = strrchr(path, '/');
            name = (slash != NULL) ? slash + 1 : path;
        }
        if (strcasecmp(name, module) != 0)
            continue;
        return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

bool envy_query_protection(uintptr_t addr, EnvyPageProtection *prot)
{
    vm_prot_t p;
    if (prot == NULL || !region_at(addr, NULL, NULL, &p))
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
    if (addr == 0 || len == 0 || len > (uintptr_t)-1 - addr)
        return false;
    uintptr_t cur = addr;
    uintptr_t end = addr + len;
    while (cur < end) {
        uintptr_t start;
        size_t rsize;
        vm_prot_t prot;
        if (!region_at(cur, &start, &rsize, &prot))
            return false;
        if (!(prot & VM_PROT_READ))
            return false;
        cur = start + rsize;
    }
    return true;
}

uint8_t *envy_memory_read(uintptr_t addr, size_t len, size_t *n_bytes_read)
{
    if (addr == 0 || len == 0 || len > (uintptr_t)-1 - addr)
        return NULL;
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
    if (addr == 0 || bytes == NULL || len == 0 || len > (uintptr_t)-1 - addr)
        return false;
    if (!envy_memory_is_readable(addr, len))
        return false;

    uintptr_t ps = (uintptr_t)vm_page_size;
    uintptr_t cur = addr;
    uintptr_t end = addr + len;
    size_t off = 0;
    while (cur < end) {
        uintptr_t start;
        size_t rsize;
        vm_prot_t saved;
        if (!region_at(cur, &start, &rsize, &saved))
            return false;
        uintptr_t rend = start + rsize;
        size_t chunk = ((rend < end) ? rend : end) - cur;
        if (saved & VM_PROT_WRITE) {
            memcpy((void *)cur, (const char *)bytes + off, chunk);
        } else {
            uintptr_t pstart = cur & ~(ps - 1);
            uintptr_t pend = (cur + chunk + ps - 1) & ~(ps - 1);
            if (vm_protect(mach_task_self(), (vm_address_t)pstart, (vm_size_t)(pend - pstart), 0,
                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS)
                return false;
            memcpy((void *)cur, (const char *)bytes + off, chunk);
            vm_protect(mach_task_self(), (vm_address_t)pstart, (vm_size_t)(pend - pstart), 0, saved);
        }
        cur += chunk;
        off += chunk;
    }
    return true;
}

bool envy_mprotect(uintptr_t addr, size_t len, EnvyPageProtection prot)
{
    uintptr_t page;
    size_t plen;
    if (!page_range(addr, len, &page, &plen))
        return false;
    vm_prot_t vmprot = to_vm_prot(prot);
    if (vmprot == VM_PROT_NONE)
        return false;
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
    if (!envy_memory_is_readable(addr, len))
        return false;

    vm_address_t scratch = 0;
    if (vm_allocate(mach_task_self(), &scratch, (vm_size_t)plen, VM_FLAGS_ANYWHERE) == KERN_SUCCESS) {
        memcpy((void *)scratch, (const void *)page, plen);
        func((void *)(scratch + (addr - page)), user_data);
        if (vm_protect(mach_task_self(), scratch, (vm_size_t)plen, 0,
                       VM_PROT_READ | VM_PROT_EXECUTE) == KERN_SUCCESS) {
            vm_address_t dst = (vm_address_t)page;
            vm_prot_t cur = 0;
            vm_prot_t max = 0;
            if (vm_remap(mach_task_self(), &dst, (vm_size_t)plen, 0,
                         VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, mach_task_self(), scratch, true, &cur,
                         &max, VM_INHERIT_COPY) == KERN_SUCCESS) {
                vm_deallocate(mach_task_self(), scratch, (vm_size_t)plen);
                sys_icache_invalidate((void *)addr, len);
                return true;
            }
        }
        vm_deallocate(mach_task_self(), scratch, (vm_size_t)plen);
    }

    vm_prot_t saved = VM_PROT_READ | VM_PROT_EXECUTE;
    region_at(page, NULL, NULL, &saved);
    if (vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)plen, 0,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS)
        return false;
    func((void *)addr, user_data);
    vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)plen, 0, saved);
    sys_icache_invalidate((void *)addr, len);
    return true;
}

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
    if (addr == 0 || len == 0 || len > (uintptr_t)-1 - addr)
        return;
    sys_icache_invalidate((void *)addr, len);
}

uintptr_t envy_alloc_n_pages(size_t n_pages, EnvyPageProtection prot)
{
    if (n_pages == 0 || (size_t)vm_page_size == 0 || n_pages > SIZE_MAX / (size_t)vm_page_size)
        return 0;
    size_t total = n_pages * (size_t)vm_page_size;
    vm_address_t addr = 0;
    if (vm_allocate(mach_task_self(), &addr, (vm_size_t)total, VM_FLAGS_ANYWHERE) != KERN_SUCCESS)
        return 0;
    if (!apply_page_prot((uintptr_t)addr, total, prot)) {
        vm_deallocate(mach_task_self(), addr, (vm_size_t)total);
        return 0;
    }
    return (uintptr_t)addr;
}

uintptr_t envy_alloc_n_pages_near(size_t n_pages, EnvyPageProtection prot, uintptr_t near_value,
                                  uintptr_t max_distance)
{
    if (n_pages == 0 || near_value == 0 || max_distance == 0 || (size_t)vm_page_size == 0 ||
        n_pages > SIZE_MAX / (size_t)vm_page_size)
        return 0;
    size_t total = n_pages * (size_t)vm_page_size;
    if (max_distance < total)
        return 0;
    uintptr_t limit = max_distance - total;
    uintptr_t step = (total < 0x100000u) ? 0x100000u : total;
    unsigned attempts = 0;

    for (uintptr_t i = 0;; i += step) {
        uintptr_t candidates[2];
        candidates[0] = (i <= near_value) ? near_value - i : 0;
        candidates[1] = (i <= (uintptr_t)-1 - near_value) ? near_value + i : 0;
        for (int c = 0; c < 2; c++) {
            if (candidates[c] == 0)
                continue;
            vm_address_t addr = (vm_address_t)candidates[c];
            if (vm_allocate(mach_task_self(), &addr, (vm_size_t)total, VM_FLAGS_ANYWHERE) != KERN_SUCCESS)
                continue;
            uintptr_t got = (uintptr_t)addr;
            uintptr_t delta = (got > near_value) ? got - near_value : near_value - got;
            if (delta <= limit && apply_page_prot(got, total, prot))
                return got;
            vm_deallocate(mach_task_self(), addr, (vm_size_t)total);
            if (delta <= limit)
                return 0;
        }
        if (++attempts > 1024 || i > limit || i + step < i)
            return 0;
    }
}

void envy_free_pages(uintptr_t address)
{
    uintptr_t start;
    size_t rsize;
    if (address == 0 || !region_at(address, &start, &rsize, NULL))
        return;
    vm_deallocate(mach_task_self(), (vm_address_t)start, (vm_size_t)rsize);
}