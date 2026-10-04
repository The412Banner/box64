// SPDX-License-Identifier: MIT
#include <string.h>
#include <windows.h>
#include <ntstatus.h>
#include <winternl.h>

#include "box64ec_exception.h"
#include "box64ec_private.h"
#include "box64ec_syscalls.h"
#include "debug.h"
#include "emu/x64emu_private.h"
#include "wine/compiler.h"
#ifdef DYNAREC
#include "custommem.h"
#include "dynablock.h"
#endif

#ifdef DYNAREC
/* A write hit a page box64 write-protected because it holds translated code:
 * drop the blocks, lift the protection and retry the faulting instruction.
 * The writer can be the JIT, the interpreter or native Wine code alike. */
static int handle_dynarec_write_fault(EXCEPTION_RECORD* record, ARM64_NT_CONTEXT* arm_context)
{
    uintptr_t addr;

    if (record->ExceptionCode != STATUS_ACCESS_VIOLATION ||
        record->NumberParameters < 2 || record->ExceptionInformation[0] != 1)
        return 0;
    addr = (uintptr_t)record->ExceptionInformation[1];
    if (!(getProtection(addr) & PROT_DYNAREC))
        return 0;
    printf_log(LOG_DEBUG, "box64ec: write to protected dynarec page %p from pc=%p, unprotecting\n",
               (void*)addr, (void*)(uintptr_t)arm_context->Pc);
    unprotectDB(addr, 1, 1);
    Box64EC_ContinueNative(arm_context, FALSE);
    return 1; /* not reached */
}

/* The fault is inside a translated block: the live guest registers are in the
 * dynarec's host registers (x10..x25 = RAX..R15, x26 = flags), not in emu. */
static int dynarec_fault_to_emu(ARM64_NT_CONTEXT* arm_context, x64emu_t* emu)
{
    dynablock_t* db = FindDynablockFromNativeAddress((void*)(uintptr_t)arm_context->Pc);
    const DWORD64* x;
    uintptr_t rip;

    if (!db)
        return 0;
    x = &arm_context->X0;
    for (int i = 0; i < 16; ++i)
        emu->regs[i].q[0] = x[10 + i];
    emu->eflags.x64 = (uint32_t)x[26];
    emu->df = d_none;
    rip = getX64Address(db, (uintptr_t)arm_context->Pc);
    if (rip)
        R_RIP = rip;
    printf_log(LOG_DEBUG, "box64ec: fault in dynarec block %p, pc=%p -> rip=%p\n",
               db, (void*)(uintptr_t)arm_context->Pc, (void*)(uintptr_t)R_RIP);
    return 1;
}
#endif

/* Dispatch a host fault in Run with the guest state, on the guest stack. */
static void rethrow_interpreter_fault(EXCEPTION_RECORD* record,
                                      ARM64_NT_CONTEXT* arm_context,
                                      x64emu_t* emu)
{
    CHPE_V2_CPU_AREA_INFO* area = Box64EC_GetCpuArea();
    box64ec_thr_t* state = Box64EC_GetThreadState();
    KiUserExceptionDispatcherStackLayout* args;
    uint64_t guest_sp = R_RSP & ~(uint64_t)63;

    if (!state || !Box64EC_KiUserExceptionDispatcher || !guest_sp ||
        Box64EC_IsEmulatorStackAddress(guest_sp))
        Box64EC_FatalEnterJit(0xec08);
    args = ((KiUserExceptionDispatcherStackLayout*)(uintptr_t)guest_sp) - 1;
    memset(args, 0, sizeof(*args));
    emu_to_arm64_ec_packed(emu, &args->Context);
    args->Context.Fpcr = arm_context->Fpcr;
    args->Context.Fpsr = arm_context->Fpsr;
    args->Rec = *record;
    args->Rec.ExceptionAddress = (void*)(uintptr_t)R_RIP;
    args->Sp = R_RSP;
    args->Pc = R_RIP;
    arm_context->Sp = (ULONG64)(uintptr_t)args;
    arm_context->Fp = arm_context->Sp;
    arm_context->Pc = Box64EC_KiUserExceptionDispatcher;
    arm_context->X18 = (ULONG64)(uintptr_t)NtCurrentTeb();
    state->guest_exception_code = record->ExceptionCode;
    state->guest_exception_address = (uintptr_t)args->Rec.ExceptionAddress;
    state->guest_exception_rip = R_RIP;
    state->guest_exception_rsp = R_RSP;
    InterlockedExchange(&state->guest_exception_pending, 1);
    area->InSimulation = FALSE;
    Box64EC_ContinueNative(arm_context, FALSE);
    Box64EC_FatalEnterJit(0xec08);
}

void WINAPI ResetToConsistentState(EXCEPTION_RECORD* record, CONTEXT* context,
                                    ARM64_NT_CONTEXT* arm_context)
{
    CHPE_V2_CPU_AREA_INFO* area = Box64EC_GetCpuArea();
    x64emu_t* emu = area ? area->EmulatorData[EC_DATA_EMU] : NULL;
    box64ec_thr_t* state = Box64EC_GetThreadState();

    if (!record || !arm_context || !emu || !state || !context)
        return;
    if (InterlockedCompareExchange(&state->guest_exception_pending, 1, 1) == 1 &&
        record->ExceptionCode == state->guest_exception_code &&
        (uintptr_t)record->ExceptionAddress == state->guest_exception_address &&
        arm_context->Pc == state->guest_exception_rip &&
        arm_context->Sp == state->guest_exception_rsp &&
        InterlockedCompareExchange(&state->guest_exception_pending, 0, 1) == 1) {
        Box64EC_ResetAbandonedEmuRun(state, emu);
        merge_unmapped_context_from_emu(emu, (ARM64EC_NT_CONTEXT*)context);
        area->InSimulation = FALSE;
        return;
    }
    if (record->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION &&
        arm_context->Pc == (uintptr_t)&ExitFunctionSuspendPoint) {
        arm_context->Pc = (uintptr_t)&ExitFunctionSuspendResumePoint;
        area->InSimulation = FALSE;
        if (area->SuspendDoorbell)
            *area->SuspendDoorbell = 0;
        Box64EC_ContinueNative(arm_context, FALSE);
        return;
    }
#ifdef DYNAREC
    if (handle_dynarec_write_fault(record, arm_context))
        return;
    if (area->InSimulation && dynarec_fault_to_emu(arm_context, emu)) {
        arm_context->X18 = (ULONG64)(uintptr_t)NtCurrentTeb();
        emu_to_context(emu, area->ContextAmd64);
        emu_to_context(emu, (ARM64EC_NT_CONTEXT*)context);
        rethrow_interpreter_fault(record, arm_context, emu);
    }
#endif
    if (area->InSimulation &&
        Box64EC_IsEmulatorStackAddress(arm_context->Sp)) {
        emu_to_context(emu, area->ContextAmd64);
        emu_to_context(emu, (ARM64EC_NT_CONTEXT*)context);
        rethrow_interpreter_fault(record, arm_context, emu);
    }
    merge_unmapped_context_from_emu(emu, (ARM64EC_NT_CONTEXT*)context);
}
