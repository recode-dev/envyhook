#ifndef MEMORY_H
#define MEMORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t EnvyPageProtection;

#define ENVY_PAGE_NO_PROTECTION 0
#define ENVY_PAGE_READ (1 << 0)
#define ENVY_PAGE_WRITE (1 << 1)
#define ENVY_PAGE_EXECUTE (1 << 2)
#define ENVY_PAGE_RW (ENVY_PAGE_READ | ENVY_PAGE_WRITE)
#define ENVY_PAGE_RX (ENVY_PAGE_READ | ENVY_PAGE_EXECUTE)
#define ENVY_PAGE_RWX (ENVY_PAGE_RW | ENVY_PAGE_EXECUTE)

typedef void (*EnvyPatchCodeFunc)(void *address, void *user_data);

uint32_t envy_query_page_size(void);
uintptr_t envy_module_find_base_address(const char *module);
bool envy_query_protection(uintptr_t addr, EnvyPageProtection *prot);
bool envy_memory_is_readable(uintptr_t addr, size_t len);
uint8_t *envy_memory_read(uintptr_t addr, size_t len, size_t *n_bytes_read);
bool envy_memory_write(uintptr_t addr, const void *bytes, size_t len);
bool envy_mprotect(uintptr_t addr, size_t len, EnvyPageProtection prot);
bool envy_memory_patch_code(uintptr_t addr, size_t len, EnvyPatchCodeFunc func, void *user_data);
bool envy_memory_patch_code_value(uintptr_t addr, const void *bytes, size_t len);
void envy_clear_cache(uintptr_t addr, size_t len);

uintptr_t envy_alloc_n_pages(size_t n_pages, EnvyPageProtection prot);
uintptr_t envy_alloc_n_pages_near(size_t n_pages, EnvyPageProtection prot, uintptr_t near_value,
                                  uintptr_t max_distance);
void envy_free_pages(uintptr_t address);

#ifdef __cplusplus
}
#endif

#endif
