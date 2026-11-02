#ifndef MEMORY_H
#define MEMORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

uintptr_t envy_base(const char *module);
bool envy_read(uintptr_t addr, void *out, size_t len);
bool envy_make_rw(uintptr_t addr, size_t len);
bool envy_patch(uintptr_t addr, const void *buf, size_t len);

#endif