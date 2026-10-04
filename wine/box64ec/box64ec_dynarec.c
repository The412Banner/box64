// SPDX-License-Identifier: MIT
/* Dynarec glue for box64ec: the hooks the ARM64 dynarec expects the host to
 * provide. Mirrors the WowBox64 stubs; the ELF-side helpers do not apply to
 * PE guests, and the alternate-jump / unaligned tracking is left for later. */
#include <stdint.h>
#include <stddef.h>

#include "box64ec_private.h"
#include "x64emu.h"
#include "debug.h"

int box64_rdtsc = 0;

int is_addr_unaligned(uintptr_t addr)
{
    (void)addr;
    return 0;
}

int is_addr_autosmc(uintptr_t addr)
{
    (void)addr;
    return 0;
}

int nUnalignedRange(uintptr_t start, size_t size)
{
    (void)start;
    (void)size;
    return 0;
}

void getUnalignedRange(uintptr_t start, size_t size, uintptr_t addrs[])
{
    (void)start;
    (void)size;
    (void)addrs;
}

typedef void (*wrapper_t)(x64emu_t* emu, uintptr_t fnc);

int isSimpleWrapper(wrapper_t fun)
{
    (void)fun;
    return 0;
}

int isRetX87Wrapper(wrapper_t fun)
{
    (void)fun;
    return 0;
}
