#ifndef INLINE_H
#define INLINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ENVY_INLINE_OK = 0,
    ENVY_INLINE_ERROR_INVALID_ARGUMENT = 1,
    ENVY_INLINE_ERROR_ALREADY_ATTACHED = 2,
    ENVY_INLINE_ERROR_NOT_ATTACHED = 3,
    ENVY_INLINE_ERROR_UNSUPPORTED_INSTRUCTION = 4,
    ENVY_INLINE_ERROR_NO_SPACE = 5,
    ENVY_INLINE_ERROR_PROTECTION = 6,
    ENVY_INLINE_ERROR_OUT_OF_MEMORY = 7,
    ENVY_INLINE_ERROR_NOT_FOUND = 8
} EnvyInlineResult;

typedef struct EnvyInlineHook EnvyInlineHook;

EnvyInlineHook *envy_inline_hook_new(void *target, void *replacement, void *user_data);
void envy_inline_hook_free(EnvyInlineHook *hook);
EnvyInlineResult envy_inline_hook_attach(EnvyInlineHook *hook);
EnvyInlineResult envy_inline_hook_detach(EnvyInlineHook *hook);
EnvyInlineResult envy_inline_hook_replace(void *target, void *replacement, void *user_data,
                                          EnvyInlineHook **hook_out);
EnvyInlineResult envy_inline_hook_revert(void *target);
bool envy_inline_hook_is_attached(const EnvyInlineHook *hook);
void *envy_inline_hook_get_target(const EnvyInlineHook *hook);
void *envy_inline_hook_get_replacement(const EnvyInlineHook *hook);
void *envy_inline_hook_get_user_data(const EnvyInlineHook *hook);
void *envy_inline_hook_get_trampoline(const EnvyInlineHook *hook);

#ifdef __cplusplus
}
#endif

#endif
