#include "inline.h"

#include "../memory/memory.h"

#include <stdlib.h>
#include <string.h>

#define ENVY_ISLAND_SLOT_SIZE 64u
#define ENVY_ISLAND_ENTRY_SIZE 16u
#define ENVY_ISLAND_PAGE_SLOTS_MAX 256u
#define ENVY_ISLAND_GRAVEYARD_LIMIT 256u
#define ENVY_ISLAND_BRANCH_WINDOW (((uintptr_t)128 << 20) - (uintptr_t)ENVY_ISLAND_SLOT_SIZE)

typedef struct EnvIslandPage {
    struct EnvIslandPage *next;
    uintptr_t base;
    uint64_t bitmap[ENVY_ISLAND_PAGE_SLOTS_MAX / 64u];
    uint32_t live;
    uint32_t slot_count;
} EnvIslandPage;

typedef struct EnvyInlineHook {
    void *target;
    void *replacement;
    void *user_data;
    uint8_t *slot;
    EnvIslandPage *page;
    uint32_t index;
    void *trampoline;
    uint32_t original;
    bool attached;
    struct EnvyInlineHook *next;
} EnvyInlineHook;

typedef struct {
    EnvIslandPage *page;
    uint32_t index;
} EnvGraveEntry;

static EnvyInlineHook *g_hooks;
static EnvIslandPage *g_pages;
static EnvGraveEntry g_graveyard[ENVY_ISLAND_GRAVEYARD_LIMIT];
static size_t g_graveyard_head;
static size_t g_graveyard_count;
static uint32_t g_lock;

static void lock_acquire(void)
{
    for (;;) {
        if (__atomic_exchange_n(&g_lock, 1u, __ATOMIC_ACQUIRE) == 0u)
            return;
        while (__atomic_load_n(&g_lock, __ATOMIC_RELAXED) != 0u) {
        }
    }
}

static void lock_release(void)
{
    __atomic_store_n(&g_lock, 0u, __ATOMIC_RELEASE);
}

static int64_t sign_extend(uint32_t value, uint32_t bits)
{
    if (bits >= 32u)
        return (int64_t)value;
    value &= (1u << bits) - 1u;
    return (int64_t)(int32_t)(value << (32u - bits)) >> (32u - bits);
}

static uint32_t encode_branch(int64_t word_offset, bool link)
{
    return (link ? 0x94000000u : 0x14000000u) | ((uint32_t)word_offset & 0x03FFFFFFu);
}

static uint32_t encode_branch_cond(uint32_t cond, int64_t word_offset)
{
    return 0x54000000u | (((uint32_t)word_offset & 0x0007FFFFu) << 5) | (cond & 0x0Fu);
}

static uint32_t encode_cbz(uint32_t sf, uint32_t op, uint32_t rt, int64_t word_offset)
{
    return 0x34000000u | (sf << 31) | (op << 24) | (((uint32_t)word_offset & 0x0007FFFFu) << 5) | rt;
}

static uint32_t encode_tbz(uint32_t op, uint32_t bit, uint32_t rt, int64_t word_offset)
{
    return 0x36000000u | ((bit >> 5) << 31) | (op << 24) | ((bit & 0x1Fu) << 19) |
           (((uint32_t)word_offset & 0x00003FFFu) << 5) | rt;
}

static uint32_t encode_ldr_literal(uint32_t rt, int64_t word_offset)
{
    return 0x58000000u | (((uint32_t)word_offset & 0x0007FFFFu) << 5) | rt;
}

static uint32_t encode_br_x17(void)
{
    return 0xD61F0220u;
}

static uint32_t encode_blr_x17(void)
{
    return 0xD63F0220u;
}

static uint32_t encode_nop(void)
{
    return 0xD503201Fu;
}

static bool branch_in_range(uintptr_t from, uintptr_t to)
{
    int64_t delta = (int64_t)to - (int64_t)from;
    if (delta < 0)
        delta = -delta;
    return delta <= (int64_t)ENVY_ISLAND_BRANCH_WINDOW;
}

static uint32_t branch_to(uintptr_t from, uintptr_t to)
{
    return encode_branch((int64_t)(to - from) >> 2, false);
}

static void emit_far_branch(uint32_t *w, uint32_t first, uintptr_t out_addr, uintptr_t fallthrough,
                            int64_t target)
{
    w[0] = first;
    w[1] = branch_to(out_addr + 4u, fallthrough);
    w[2] = encode_ldr_literal(17, 2);
    w[3] = encode_br_x17();
    w[4] = (uint32_t)target;
    w[5] = (uint32_t)((uint64_t)target >> 32);
}

static EnvyInlineResult relocate(uint32_t insn, uintptr_t pc, uint8_t *out, uintptr_t out_addr,
                                 uintptr_t fallthrough, uint32_t *words_out)
{
    uint32_t *w = (uint32_t *)out;
    uint32_t group = insn & 0xFC000000u;

    if (group == 0x14000000u || group == 0x94000000u) {
        bool link = (group == 0x94000000u);
        int64_t target = (int64_t)pc + (sign_extend(insn & 0x03FFFFFFu, 26) << 2);
        w[0] = encode_ldr_literal(17, 3);
        w[1] = link ? encode_blr_x17() : encode_br_x17();
        w[2] = branch_to(out_addr + 8u, fallthrough);
        w[3] = (uint32_t)target;
        w[4] = (uint32_t)((uint64_t)target >> 32);
        *words_out = 5u;
        return ENVY_INLINE_OK;
    }

    if ((insn & 0xFF000000u) == 0x54000000u) {
        uint32_t cond = insn & 0x0Fu;
        int64_t target = (int64_t)pc + (sign_extend((insn >> 5) & 0x7FFFFu, 19) << 2);
        emit_far_branch(w, encode_branch_cond(cond, 2), out_addr, fallthrough, target);
        *words_out = 6u;
        return ENVY_INLINE_OK;
    }

    if ((insn & 0x7E000000u) == 0x34000000u) {
        uint32_t sf = (insn >> 31) & 1u;
        uint32_t op = (insn >> 24) & 1u;
        uint32_t rt = insn & 0x1Fu;
        int64_t target = (int64_t)pc + (sign_extend((insn >> 5) & 0x7FFFFu, 19) << 2);
        emit_far_branch(w, encode_cbz(sf, op, rt, 2), out_addr, fallthrough, target);
        *words_out = 6u;
        return ENVY_INLINE_OK;
    }

    if ((insn & 0x7E000000u) == 0x36000000u) {
        uint32_t bit = (((insn >> 31) & 1u) << 5) | ((insn >> 19) & 0x1Fu);
        uint32_t op = (insn >> 24) & 1u;
        uint32_t rt = insn & 0x1Fu;
        int64_t target = (int64_t)pc + (sign_extend((insn >> 5) & 0x3FFFu, 14) << 2);
        emit_far_branch(w, encode_tbz(op, bit, rt, 2), out_addr, fallthrough, target);
        *words_out = 6u;
        return ENVY_INLINE_OK;
    }

    group = insn & 0x9F000000u;
    if (group == 0x10000000u || group == 0x90000000u) {
        uint32_t rd = insn & 0x1Fu;
        uint32_t immhi = (insn >> 5) & 0x7FFFFu;
        uint32_t immlo = (insn >> 29) & 0x3u;
        int64_t imm = sign_extend((immhi << 2) | immlo, 21);
        int64_t target = (group == 0x90000000u) ? (int64_t)(pc & ~(uintptr_t)0xFFFull) + (imm << 12)
                                                : (int64_t)pc + imm;
        w[0] = encode_ldr_literal(rd, 2);
        w[1] = encode_branch(3, false);
        w[2] = (uint32_t)target;
        w[3] = (uint32_t)((uint64_t)target >> 32);
        w[4] = branch_to(out_addr + 16u, fallthrough);
        *words_out = 5u;
        return ENVY_INLINE_OK;
    }

    if ((insn & 0xFF000000u) == 0xD8000000u) {
        w[0] = encode_nop();
        w[1] = branch_to(out_addr + 4u, fallthrough);
        *words_out = 2u;
        return ENVY_INLINE_OK;
    }

    group = insn & 0x1F000000u;
    if (group == 0x18000000u || group == 0x1C000000u) {
        uint32_t size;
        if (group == 0x18000000u)
            size = (((insn >> 30) & 0x3u) == 1u) ? 8u : 4u;
        else {
            uint32_t opc = (insn >> 29) & 0x7u;
            if (opc == 0u)
                size = 1u;
            else if (opc == 1u)
                size = 2u;
            else if (opc == 2u)
                size = 4u;
            else if (opc == 3u)
                size = 8u;
            else if (opc == 4u)
                size = 16u;
            else
                return ENVY_INLINE_ERROR_UNSUPPORTED_INSTRUCTION;
        }
        int64_t pool = (int64_t)pc + (sign_extend((insn >> 5) & 0x7FFFFu, 19) << 2);
        uint8_t *raw = envy_memory_read((uintptr_t)pool, size, NULL);
        if (raw == NULL)
            return ENVY_INLINE_ERROR_UNSUPPORTED_INSTRUCTION;
        uint32_t data_words = (size + 3u) / 4u;
        w[0] = (insn & ~0x00FFFFE0u) | (2u << 5);
        w[1] = encode_branch((int64_t)data_words + 1, false);
        memcpy(out + 8u, raw, size);
        free(raw);
        w[2u + data_words] = branch_to(out_addr + (2u + data_words) * 4u, fallthrough);
        *words_out = 2u + data_words + 1u;
        return ENVY_INLINE_OK;
    }

    w[0] = insn;
    w[1] = branch_to(out_addr + 4u, fallthrough);
    *words_out = 2u;
    return ENVY_INLINE_OK;
}

static bool island_page_find_free(EnvIslandPage *page, uint32_t *index_out)
{
    for (uint32_t word = 0; word < ENVY_ISLAND_PAGE_SLOTS_MAX / 64u; word++) {
        uint64_t bits = page->bitmap[word];
        if (bits == UINT64_MAX)
            continue;
        uint32_t index = word * 64u + (uint32_t)__builtin_ctzll(~bits);
        if (index >= page->slot_count)
            continue;
        *index_out = index;
        return true;
    }
    return false;
}

static void island_page_mark(EnvIslandPage *page, uint32_t index)
{
    page->bitmap[index >> 6] |= (uint64_t)1 << (index & 63u);
    page->live++;
}

static void island_page_clear(EnvIslandPage *page, uint32_t index)
{
    page->bitmap[index >> 6] &= ~((uint64_t)1 << (index & 63u));
    page->live--;
}

static EnvIslandPage *island_page_create(uintptr_t target)
{
    size_t ps = envy_query_page_size();
    if (ps < ENVY_ISLAND_SLOT_SIZE || ps / ENVY_ISLAND_SLOT_SIZE > ENVY_ISLAND_PAGE_SLOTS_MAX)
        return NULL;
    uintptr_t mem = envy_alloc_n_pages_near(1, ENVY_PAGE_RW, target,
                                            ENVY_ISLAND_BRANCH_WINDOW - (uintptr_t)ps);
    if (mem == 0)
        return NULL;
    EnvIslandPage *page = (EnvIslandPage *)malloc(sizeof(*page));
    if (page == NULL) {
        envy_free_pages(mem);
        return NULL;
    }
    page->next = NULL;
    page->base = mem;
    for (uint32_t word = 0; word < ENVY_ISLAND_PAGE_SLOTS_MAX / 64u; word++)
        page->bitmap[word] = 0;
    page->live = 0;
    page->slot_count = (uint32_t)(ps / ENVY_ISLAND_SLOT_SIZE);
    page->next = g_pages;
    g_pages = page;
    return page;
}

static void island_page_release(EnvIslandPage *page)
{
    EnvIslandPage **link = &g_pages;
    while (*link != NULL) {
        if (*link == page) {
            *link = page->next;
            break;
        }
        link = &(*link)->next;
    }
    envy_free_pages(page->base);
    free(page);
}

static uint8_t *island_slot_obtain(uintptr_t target, EnvIslandPage **page_out, uint32_t *index_out)
{
    size_t ps = envy_query_page_size();
    uintptr_t reach = ENVY_ISLAND_BRANCH_WINDOW - (uintptr_t)ps;
    EnvIslandPage *page;

    for (page = g_pages; page != NULL; page = page->next) {
        uintptr_t delta = (page->base > target) ? page->base - target : target - page->base;
        uint32_t index;
        if (delta > reach || !island_page_find_free(page, &index))
            continue;
        island_page_mark(page, index);
        *page_out = page;
        *index_out = index;
        if (envy_mprotect(page->base, ps, ENVY_PAGE_RW))
            return (uint8_t *)(page->base + (uintptr_t)index * ENVY_ISLAND_SLOT_SIZE);
        island_page_clear(page, index);
        return NULL;
    }

    page = island_page_create(target);
    if (page == NULL)
        return NULL;
    uint32_t index;
    if (!island_page_find_free(page, &index)) {
        island_page_release(page);
        return NULL;
    }
    island_page_mark(page, index);
    *page_out = page;
    *index_out = index;
    return (uint8_t *)(page->base + (uintptr_t)index * ENVY_ISLAND_SLOT_SIZE);
}

static void island_slot_retire(EnvIslandPage *page, uint32_t index)
{
    if (g_graveyard_count == ENVY_ISLAND_GRAVEYARD_LIMIT) {
        EnvGraveEntry *oldest = &g_graveyard[g_graveyard_head];
        island_page_clear(oldest->page, oldest->index);
        if (oldest->page->live == 0)
            island_page_release(oldest->page);
        g_graveyard_head = (g_graveyard_head + 1u) % ENVY_ISLAND_GRAVEYARD_LIMIT;
        g_graveyard_count--;
    }
    EnvGraveEntry *entry = &g_graveyard[(g_graveyard_head + g_graveyard_count) % ENVY_ISLAND_GRAVEYARD_LIMIT];
    entry->page = page;
    entry->index = index;
    g_graveyard_count++;
}

static EnvyInlineResult island_slot_build(uint8_t *slot, uintptr_t target, uint32_t insn,
                                          void *replacement)
{
    uint32_t *entry = (uint32_t *)slot;
    entry[0] = encode_ldr_literal(17, 2);
    entry[1] = encode_br_x17();
    entry[2] = (uint32_t)(uintptr_t)replacement;
    entry[3] = (uint32_t)((uintptr_t)replacement >> 32);

    uint32_t words = 0;
    EnvyInlineResult r = relocate(insn, target, slot + ENVY_ISLAND_ENTRY_SIZE,
                                  (uintptr_t)slot + ENVY_ISLAND_ENTRY_SIZE, target + 4, &words);
    if (r != ENVY_INLINE_OK)
        return r;
    if (words > (ENVY_ISLAND_SLOT_SIZE - ENVY_ISLAND_ENTRY_SIZE) / 4u)
        return ENVY_INLINE_ERROR_UNSUPPORTED_INSTRUCTION;
    envy_clear_cache((uintptr_t)slot, ENVY_ISLAND_SLOT_SIZE);
    return ENVY_INLINE_OK;
}

static void inline_patch_word(void *address, void *user_data)
{
    memcpy(address, user_data, 4);
}

static EnvyInlineResult detach_locked(EnvyInlineHook *hook)
{
    uint32_t word = hook->original;
    if (!envy_memory_patch_code((uintptr_t)hook->target, 4, inline_patch_word, &word))
        return ENVY_INLINE_ERROR_PROTECTION;
    EnvyInlineHook **link = &g_hooks;
    while (*link != NULL) {
        if (*link == hook) {
            *link = hook->next;
            break;
        }
        link = &(*link)->next;
    }
    hook->next = NULL;
    hook->attached = false;
    island_slot_retire(hook->page, hook->index);
    hook->page = NULL;
    hook->index = 0;
    hook->slot = NULL;
    hook->trampoline = NULL;
    return ENVY_INLINE_OK;
}

EnvyInlineHook *envy_inline_hook_new(void *target, void *replacement, void *user_data)
{
    if (target == NULL || replacement == NULL)
        return NULL;
    EnvyInlineHook *hook = (EnvyInlineHook *)malloc(sizeof(*hook));
    if (hook == NULL)
        return NULL;
    hook->target = target;
    hook->replacement = replacement;
    hook->user_data = user_data;
    hook->slot = NULL;
    hook->page = NULL;
    hook->index = 0;
    hook->trampoline = NULL;
    hook->original = 0;
    hook->attached = false;
    hook->next = NULL;
    return hook;
}

void envy_inline_hook_free(EnvyInlineHook *hook)
{
    if (hook == NULL)
        return;
    lock_acquire();
    if (hook->attached)
        detach_locked(hook);
    if (!hook->attached)
        free(hook);
    lock_release();
}

EnvyInlineResult envy_inline_hook_attach(EnvyInlineHook *hook)
{
    if (hook == NULL || hook->target == NULL || hook->replacement == NULL)
        return ENVY_INLINE_ERROR_INVALID_ARGUMENT;
    if ((((uintptr_t)hook->target) & 3u) != 0u)
        return ENVY_INLINE_ERROR_INVALID_ARGUMENT;

    lock_acquire();
    if (hook->attached) {
        lock_release();
        return ENVY_INLINE_ERROR_ALREADY_ATTACHED;
    }
    for (EnvyInlineHook *h = g_hooks; h != NULL; h = h->next) {
        if (h->attached && h->target == hook->target) {
            lock_release();
            return ENVY_INLINE_ERROR_ALREADY_ATTACHED;
        }
    }

    uint8_t *raw = envy_memory_read((uintptr_t)hook->target, 4, NULL);
    if (raw == NULL) {
        lock_release();
        return ENVY_INLINE_ERROR_PROTECTION;
    }
    uint32_t insn;
    memcpy(&insn, raw, 4);
    free(raw);

    EnvIslandPage *page = NULL;
    uint32_t index = 0;
    uint8_t *slot = island_slot_obtain((uintptr_t)hook->target, &page, &index);
    if (slot == NULL) {
        lock_release();
        return ENVY_INLINE_ERROR_NO_SPACE;
    }

    if (!branch_in_range((uintptr_t)hook->target, (uintptr_t)slot)) {
        island_slot_retire(page, index);
        lock_release();
        return ENVY_INLINE_ERROR_PROTECTION;
    }

    memset(slot, 0, ENVY_ISLAND_SLOT_SIZE);
    EnvyInlineResult r = island_slot_build(slot, (uintptr_t)hook->target, insn, hook->replacement);
    if (r != ENVY_INLINE_OK) {
        island_slot_retire(page, index);
        lock_release();
        return r;
    }

    size_t ps = envy_query_page_size();
    if (!envy_mprotect(page->base, ps, ENVY_PAGE_RX)) {
        island_slot_retire(page, index);
        lock_release();
        return ENVY_INLINE_ERROR_PROTECTION;
    }

    uint32_t word = encode_branch((int64_t)((uintptr_t)slot - (uintptr_t)hook->target) >> 2, false);
    if (!envy_memory_patch_code((uintptr_t)hook->target, 4, inline_patch_word, &word)) {
        island_slot_retire(page, index);
        lock_release();
        return ENVY_INLINE_ERROR_PROTECTION;
    }

    hook->slot = slot;
    hook->page = page;
    hook->index = index;
    hook->trampoline = slot + ENVY_ISLAND_ENTRY_SIZE;
    hook->original = insn;
    hook->attached = true;
    hook->next = g_hooks;
    g_hooks = hook;
    lock_release();
    return ENVY_INLINE_OK;
}

EnvyInlineResult envy_inline_hook_detach(EnvyInlineHook *hook)
{
    if (hook == NULL)
        return ENVY_INLINE_ERROR_INVALID_ARGUMENT;
    lock_acquire();
    if (!hook->attached) {
        lock_release();
        return ENVY_INLINE_ERROR_NOT_ATTACHED;
    }
    EnvyInlineResult r = detach_locked(hook);
    lock_release();
    return r;
}

EnvyInlineResult envy_inline_hook_replace(void *target, void *replacement, void *user_data,
                                          EnvyInlineHook **hook_out)
{
    if (hook_out == NULL)
        return ENVY_INLINE_ERROR_INVALID_ARGUMENT;
    *hook_out = NULL;
    EnvyInlineHook *hook = envy_inline_hook_new(target, replacement, user_data);
    if (hook == NULL)
        return ENVY_INLINE_ERROR_OUT_OF_MEMORY;
    EnvyInlineResult r = envy_inline_hook_attach(hook);
    if (r != ENVY_INLINE_OK) {
        free(hook);
        return r;
    }
    *hook_out = hook;
    return ENVY_INLINE_OK;
}

EnvyInlineResult envy_inline_hook_revert(void *target)
{
    if (target == NULL)
        return ENVY_INLINE_ERROR_INVALID_ARGUMENT;
    lock_acquire();
    EnvyInlineHook *found = NULL;
    for (EnvyInlineHook *h = g_hooks; h != NULL; h = h->next) {
        if (h->attached && h->target == target) {
            found = h;
            break;
        }
    }
    if (found == NULL) {
        lock_release();
        return ENVY_INLINE_ERROR_NOT_FOUND;
    }
    EnvyInlineResult r = detach_locked(found);
    if (r == ENVY_INLINE_OK)
        free(found);
    lock_release();
    return r;
}

bool envy_inline_hook_is_attached(const EnvyInlineHook *hook)
{
    return hook != NULL && hook->attached;
}

void *envy_inline_hook_get_target(const EnvyInlineHook *hook)
{
    return (hook != NULL) ? hook->target : NULL;
}

void *envy_inline_hook_get_replacement(const EnvyInlineHook *hook)
{
    return (hook != NULL) ? hook->replacement : NULL;
}

void *envy_inline_hook_get_user_data(const EnvyInlineHook *hook)
{
    return (hook != NULL) ? hook->user_data : NULL;
}

void *envy_inline_hook_get_trampoline(const EnvyInlineHook *hook)
{
    return (hook != NULL) ? hook->trampoline : NULL;
}
