/*
 * LFI (Lightweight Fault Isolation) Sandboxing Module for NASM.
 *
 * Implements the highly-optimized LLVM LFI sandboxing model:
 * - Segment-based memory sandboxing via '%gs:' override in Segue Mode (default).
 * - Explicit '%r14' base register addition in No-Segue Mode (-lfi-no-segue).
 * - Fine-grained control over loads/stores sandboxing (-lfi-no-loads, -lfi-no-stores).
 * - Stack sandboxing via flags-preserving 'lea rsp, [rsp + r14*1]' sequences.
 * - Control flow sandboxing (returns, indirect calls/jumps) using '%r14' as code base.
 */

#include "compiler.h"
#include "nasm.h"
#include "nasmlib.h"
#include "assemble.h"
#include "insns.h"
#include "stdscan.h"
#include "lfi.h"
#include "parser.h"
#include "outform.h"
#include <stdarg.h>
#include <stdio.h>

/* LFI Sandboxing Registers */
#define LFI_SBX_BASE    R_R14
#define LFI_CTXREG      R_R15
#define LFI_SCRATCH_REG R_R11

#define regName(reg) (nasm_reg_names[reg-EXPR_REG_START])

/*
 * Helper to parse a formatted string into a NASM instruction.
 * Eliminates the need for local character buffers and manual sprintf.
 */
static void parse_line_fmt(insn *ret, int bits, const char *fmt, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    parse_line(buf, ret, bits);
}

/*
 * Typedef representing a bundle-lock mask.
 *
 * We use a bitmask to represent the bundle-lock layout:
 * - The LSB (bit 0) represents the first instruction in the expanded sequence.
 * - Bit j (1 <= j < 8) is set to 1 if instruction j must be kept in the same
 *   bundle-locked block as its predecessor (instruction j - 1).
 * - Bit j is 0 if instruction j can safely start a new block/bundle.
 */
typedef uint8_t bundle_lock_mask_t;

/* =========================================================================
 * 1. Low-Level Register and Memory Helper Utilities
 * ========================================================================= */

/* Map any GPR register to its 64-bit parent */
static enum reg_enum get_64bit_parent(enum reg_enum reg)
{
    switch (reg) {
        case R_RAX: case R_EAX: case R_AX: case R_AL: case R_AH: return R_RAX;
        case R_RBX: case R_EBX: case R_BX: case R_BL: case R_BH: return R_RBX;
        case R_RCX: case R_ECX: case R_CX: case R_CL: case R_CH: return R_RCX;
        case R_RDX: case R_EDX: case R_DX: case R_DL: case R_DH: return R_RDX;
        case R_RSI: case R_ESI: case R_SI: case R_SIL: return R_RSI;
        case R_RDI: case R_EDI: case R_DI: case R_DIL: return R_RDI;
        case R_RBP: case R_EBP: case R_BP: case R_BPL: return R_RBP;
        case R_RSP: case R_ESP: case R_SP: case R_SPL: return R_RSP;
        case R_R8:  case R_R8D:  case R_R8W:  case R_R8B:  return R_R8;
        case R_R9:  case R_R9D:  case R_R9W:  case R_R9B:  return R_R9;
        case R_R10: case R_R10D: case R_R10W: case R_R10B: return R_R10;
        case R_R11: case R_R11D: case R_R11W: case R_R11B: return R_R11;
        case R_R12: case R_R12D: case R_R12W: case R_R12B: return R_R12;
        case R_R13: case R_R13D: case R_R13W: case R_R13B: return R_R13;
        case R_R14: case R_R14D: case R_R14W: case R_R14B: return R_R14;
        case R_R15: case R_R15D: case R_R15W: case R_R15B: return R_R15;
        default: return reg;
    }
}

/* Get the 32-bit counterpart register name for any given x86 register */
static const char *get_32bit_reg_name(enum reg_enum reg)
{
    switch (get_64bit_parent(reg)) {
        case R_RAX: return "eax";
        case R_RBX: return "ebx";
        case R_RCX: return "ecx";
        case R_RDX: return "edx";
        case R_RSI: return "esi";
        case R_RDI: return "edi";
        case R_RBP: return "ebp";
        case R_RSP: return "esp";
        case R_R8:  return "r8d";
        case R_R9:  return "r9d";
        case R_R10: return "r10d";
        case R_R11: return "r11d";
        case R_R12: return "r12d";
        case R_R13: return "r13d";
        case R_R14: return "r14d";
        case R_R15: return "r15d";
        default: return regName(reg);
    }
}

/* Helper to check if an operand is of a specific type */
static bool is_op_type(operand op, opflags_t type)
{
    return (op.type & type) == type;
}

/* Helper to check if effective address flags are set */
static bool is_ea_flags(operand op, int flags)
{
    return (op.eaflags & flags) == flags;
}

/* Check if a memory operand is inherently safe (does not require sandboxing) */
static bool is_safe_memop(operand *op)
{
    if (is_ea_flags(*op, EAF_REL)) {
        return true; /* RIP-relative is always safe */
    }
    if (op->indexreg != R_none) {
        return false; /* Any index register makes it unsafe and requires truncation/sandboxing */
    }
    enum reg_enum base = op->basereg;
    if (base == R_RSP || base == R_RBP || base == LFI_SBX_BASE || base == LFI_CTXREG) {
        return true; /* Simple offset from stack, frame, or base registers is safe */
    }
    return false;
}

/* Find the index of the memory operand in an instruction (returns -1 if none) */
static int get_mem_op_index(insn *ins)
{
    for (int i = 0; i < ins->operands; i++) {
        if (is_op_type(ins->oprs[i], MEMORY)) {
            return i;
        }
    }
    return -1;
}

/* Check if an opcode is an x87 FPU store instruction */
static bool is_x87_store(int opcode)
{
    switch (opcode) {
        case I_FST:
        case I_FSTP:
        case I_FIST:
        case I_FISTP:
        case I_FISTTP:
        case I_FBSTP:
        case I_FSTENV:
        case I_FNSTENV:
        case I_FSTCW:
        case I_FNSTCW:
        case I_FSTSW:
        case I_FNSTSW:
        case I_FSAVE:
        case I_FNSAVE:
        case I_FXSAVE:
        case I_FXSAVE64:
            return true;
        default:
            return false;
    }
}

/* Check if an instruction is an x87 FPU instruction with a memory operand */
static bool is_x87_insn_with_mem(insn *ins)
{
    const char *name = nasm_insn_names[ins->opcode];
    if ((name[0] == 'f' || name[0] == 'F') && get_mem_op_index(ins) != -1) {
        return true;
    }
    return false;
}

/* Determine if the memory operand at mem_index is a load (read) operation */
static bool is_memload(insn *ins, int mem_index)
{
    if (ins->opcode == I_LEA) {
        return false; /* LEA does not perform a memory load */
    }
    if (is_x87_insn_with_mem(ins)) {
        return !is_x87_store(ins->opcode);
    }
    if (mem_index >= 1) {
        return true; /* Source operand is memory */
    }
    return false;
}

/* Format a non-memory operand (register or immediate) as a string */
static void get_operand_string_rep(operand *op, char *dest)
{
    if (is_op_type(*op, REGISTER)) {
        strcpy(dest, regName(op->basereg));
    } else if (is_op_type(*op, IMMEDIATE)) {
        sprintf(dest, "%ld", op->offset);
    } else {
        strcpy(dest, "");
    }
}

/* Helper to get the NASM size specifier string (e.g. "qword ", "dword ", etc.) */
static const char *get_operand_size_specifier(operand *op)
{
    opflags_t type = op->type;
    if (type & BITS8)   return "byte ";
    if (type & BITS16)  return "word ";
    if (type & BITS32)  return "dword ";
    if (type & BITS64)  return "qword ";
    if (type & BITS128) return "oword ";
    if (type & BITS256) return "yword ";
    if (type & BITS512) return "zword ";
    return ""; /* Default: no size specifier */
}

/* Format a sandboxed memory reference string using GS segment and 32-bit registers */
static void get_segue_memstr(operand *op, char *dest)
{
    const char *sizeSpec = get_operand_size_specifier(op);
    const char *base_name = (op->basereg != R_none) ? get_32bit_reg_name(op->basereg) : NULL;
    const char *index_name = (op->indexreg != R_none) ? get_32bit_reg_name(op->indexreg) : NULL;

    char base_part[64] = "";
    if (base_name) {
        strcpy(base_part, base_name);
    }

    char index_part[64] = "";
    if (index_name) {
        const char *plus = (base_name) ? "+" : "";
        if (op->scale > 1) {
            sprintf(index_part, "%s%s*%d", plus, index_name, op->scale);
        } else {
            sprintf(index_part, "%s%s", plus, index_name);
        }
    }

    char offset_part[64] = "";
    if (op->offset != 0 || (!base_name && !index_name)) {
        const char *plus = (base_name || index_name) ? "+" : "";
        if (op->offset > 0) {
            sprintf(offset_part, "%s%ld", plus, op->offset);
        } else if (op->offset < 0) {
            sprintf(offset_part, "%ld", op->offset);
        } else {
            /* offset is 0, but no base or index registers are present (i.e. absolute address 0) */
            strcpy(offset_part, "0");
        }
    }

    sprintf(dest, "%sgs:[%s%s%s]", sizeSpec, base_part, index_part, offset_part);
}

/* Helper to parse an instruction with its operand strings, preserving the LOCK prefix if present. */
static void parse_insn_ops(insn *ins, insn *dest, const char *op0, const char *op1, const char *op2)
{
    int bits = ins->bits;
    const char *instrName = nasm_insn_names[ins->opcode];

    /* Prepend LOCK prefix if present */
    bool hasLock = false;
    for (int i = 0; i < MAXPREFIX; i++) {
        if (ins->prefixes[i] == P_LOCK) {
            hasLock = true;
            break;
        }
    }
    const char *lockPrefix = hasLock ? "lock " : "";

    if (ins->operands == 1) {
        parse_line_fmt(dest, bits, "%s%s %s", lockPrefix, instrName, op0);
    } else if (ins->operands == 2) {
        parse_line_fmt(dest, bits, "%s%s %s,%s", lockPrefix, instrName, op0, op1);
    } else if (ins->operands == 3) {
        parse_line_fmt(dest, bits, "%s%s %s,%s,%s", lockPrefix, instrName, op0, op1, op2);
    }
}

/* Rewrite a memory-accessing instruction in-place to use GS segment override */
static void rewrite_gs_mem(insn *ins, int mem_index, insn *dest)
{
    char opsStr[3][256];
    for (int i = 0; i < ins->operands; i++) {
        if (i == mem_index) {
            get_segue_memstr(&ins->oprs[i], opsStr[i]);
        } else {
            get_operand_string_rep(&ins->oprs[i], opsStr[i]);
        }
    }
    parse_insn_ops(ins, dest, opsStr[0], opsStr[1], opsStr[2]);
}

/* Format the TLS memory operand string: gs:[scratch32 + base32 + offset] or [scratch64 + base64 + offset] */
static void get_tls_memstr(operand *op, enum reg_enum scratch, bool use_gs, char *dest)
{
    const char *seg = use_gs ? "gs:" : "";
    const char *scratch_name = use_gs ? get_32bit_reg_name(scratch) : regName(scratch);

    char base_part[64] = "";
    if (op->basereg != R_none) {
        const char *base_name = use_gs ? get_32bit_reg_name(op->basereg) : regName(op->basereg);
        sprintf(base_part, "+%s", base_name);
    }

    char index_part[64] = "";
    if (op->indexreg != R_none) {
        const char *index_name = use_gs ? get_32bit_reg_name(op->indexreg) : regName(op->indexreg);
        if (op->scale > 1) {
            sprintf(index_part, "+%s*%d", index_name, op->scale);
        } else {
            sprintf(index_part, "+%s", index_name);
        }
    }

    char offset_part[64] = "";
    if (op->offset != 0) {
        if (op->offset > 0) {
            sprintf(offset_part, "+%ld", op->offset);
        } else {
            sprintf(offset_part, "%ld", op->offset);
        }
    }

    sprintf(dest, "%s[%s%s%s%s]", seg, scratch_name, base_part, index_part, offset_part);
}

/* Format an explicit base addition memory operand string [base + index*scale + offset] */
static void get_explicit_memstr(operand *op, enum reg_enum base, enum reg_enum index, int scale, int64_t offset, char *dest)
{
    const char *sizeSpec = get_operand_size_specifier(op);
    const char *base_name = (base != R_none) ? regName(base) : NULL;
    const char *index_name = (index != R_none) ? regName(index) : NULL;

    char base_part[64] = "";
    if (base_name) {
        strcpy(base_part, base_name);
    }

    char index_part[64] = "";
    if (index_name) {
        const char *plus = (base_name) ? "+" : "";
        if (scale > 1) {
            sprintf(index_part, "%s%s*%d", plus, index_name, scale);
        } else {
            sprintf(index_part, "%s%s", plus, index_name);
        }
    }

    char offset_part[64] = "";
    if (offset != 0 || (!base_name && !index_name)) {
        const char *plus = (base_name || index_name) ? "+" : "";
        if (offset > 0) {
            sprintf(offset_part, "%s%ld", plus, offset);
        } else if (offset < 0) {
            sprintf(offset_part, "%ld", offset);
        } else {
            strcpy(offset_part, "0");
        }
    }

    sprintf(dest, "%s[%s%s%s]", sizeSpec, base_part, index_part, offset_part);
}

/*
 * Calculate the no-segue 32-bit effective address from a memory operand.
 *
 * If the base is already the sandbox base (%r14), we omit it from the 32-bit
 * address calculation (preventing 2*r14 base additions at runtime).
 */
static void get_nosegue_addr(operand *memOp, const char *scratch32, char *instStr)
{
    enum reg_enum baseReg = memOp->basereg;
    enum reg_enum indexReg = memOp->indexreg;
    int scale = memOp->scale;
    int64_t offset = memOp->offset;

    if (baseReg == LFI_SBX_BASE) {
        baseReg = R_none;
    }

    /* Optimization: If it's a simple register copy, use MOV instead of LEA */
    if (offset == 0 && indexReg == R_none && baseReg != R_none) {
        sprintf(instStr, "mov %s,%s", scratch32, get_32bit_reg_name(baseReg));
    } else if (offset == 0 && baseReg == R_none && indexReg != R_none && scale == 1) {
        sprintf(instStr, "mov %s,%s", scratch32, get_32bit_reg_name(indexReg));
    } else {
        /* Assemble the inner effective address parts declaratively */
        const char *base_name = (baseReg != R_none) ? regName(baseReg) : NULL;
        const char *index_name = (indexReg != R_none) ? regName(indexReg) : NULL;

        char base_part[64] = "";
        if (base_name) {
            strcpy(base_part, base_name);
        }

        char index_part[64] = "";
        if (index_name) {
            const char *plus = (base_name) ? "+" : "";
            if (scale > 1) {
                sprintf(index_part, "%s%s*%d", plus, index_name, scale);
            } else {
                sprintf(index_part, "%s%s", plus, index_name);
            }
        }

        char offset_part[64] = "";
        if (offset != 0 || (!base_name && !index_name)) {
            const char *plus = (base_name || index_name) ? "+" : "";
            if (offset > 0) {
                sprintf(offset_part, "%s%ld", plus, offset);
            } else if (offset < 0) {
                sprintf(offset_part, "%ld", offset);
            } else {
                strcpy(offset_part, "0");
            }
        }

        sprintf(instStr, "lea %s,[%s%s%s]", scratch32, base_part, index_part, offset_part);
    }
}

/* =========================================================================
 * 2. Specialized Instruction Expansion & Rewrite Helpers
 * ========================================================================= */

/* Rewrite 1: Returns (ret, retn, retf) */
static void rewrite_return(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    int bits = ins->bits;
    int64_t popBytes = (ins->operands > 0) ? ins->oprs[0].offset : 0;

    const char *scratch = regName(LFI_SCRATCH_REG);
    const char *scratch32 = get_32bit_reg_name(LFI_SCRATCH_REG);
    const char *sbx_base = regName(LFI_SBX_BASE);

    if (popBytes == 0) {
        *count = 4;
        *bundle_lock_mask = 0b1110;

        parse_line_fmt(&(ret[0]), bits, "pop %s", scratch);
        parse_line_fmt(&(ret[1]), bits, "and %s,-32", scratch32);
        parse_line_fmt(&(ret[2]), bits, "add %s,%s", scratch, sbx_base);
        parse_line_fmt(&(ret[3]), bits, "jmp %s", scratch);
    } else {
        *count = 6;
        *bundle_lock_mask = 0b110100; /* Two locks: [add, lea] (bits 1,2) and [and, add, jmp] (bits 3,4,5) */

        parse_line_fmt(&(ret[0]), bits, "pop %s", scratch);
        parse_line_fmt(&(ret[1]), bits, "add esp,%ld", popBytes);
        parse_line_fmt(&(ret[2]), bits, "lea rsp,[rsp+%s]", sbx_base);
        parse_line_fmt(&(ret[3]), bits, "and %s,-32", scratch32);
        parse_line_fmt(&(ret[4]), bits, "add %s,%s", scratch, sbx_base);
        parse_line_fmt(&(ret[5]), bits, "jmp %s", scratch);
    }
}

/* Rewrite 2: POP RSP */
static void rewrite_rsp_pop(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    int bits = ins->bits;
    *count = 3;
    *bundle_lock_mask = 0b0100; /* [mov, lea] are locked together (bits 1,2) */

    const char *scratch = regName(LFI_SCRATCH_REG);
    const char *scratch32 = get_32bit_reg_name(LFI_SCRATCH_REG);
    const char *sbx_base = regName(LFI_SBX_BASE);

    parse_line_fmt(&(ret[0]), bits, "pop %s", scratch);
    parse_line_fmt(&(ret[1]), bits, "mov esp,%s", scratch32);
    parse_line_fmt(&(ret[2]), bits, "lea rsp,[rsp+%s]", sbx_base);
}

/* Rewrite 3: Direct RSP updates (add/sub/mov rsp, source) */
static void rewrite_rsp_update(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    int bits = ins->bits;
    const char *instrName = nasm_insn_names[ins->opcode];
    const char *sbx_base = regName(LFI_SBX_BASE);

    *count = 2;
    *bundle_lock_mask = 0b0010;

    if (is_op_type(ins->oprs[1], IMMEDIATE)) {
        parse_line_fmt(&(ret[0]), bits, "%s esp,0x%llx", instrName, (unsigned long long)ins->oprs[1].offset);
    } else if (is_op_type(ins->oprs[1], REGISTER)) {
        const char *loweredReg = get_32bit_reg_name(ins->oprs[1].basereg);
        parse_line_fmt(&(ret[0]), bits, "%s esp,%s", instrName, loweredReg);
    } else if (is_op_type(ins->oprs[1], MEMORY)) {
        char memoryStringRep[256];
        if (!lfi_no_segue) {
            get_segue_memstr(&ins->oprs[1], memoryStringRep);
        } else {
            get_explicit_memstr(&ins->oprs[1], LFI_SBX_BASE, LFI_SCRATCH_REG, 1, 0, memoryStringRep);
            *count = 3;
            *bundle_lock_mask = 0b0110;
            char preLoad[128];
            const char *scratch32 = get_32bit_reg_name(LFI_SCRATCH_REG);
            get_nosegue_addr(&ins->oprs[1], scratch32, preLoad);
            parse_line(preLoad, &(ret[0]), bits);
            ret++; /* shift ret pointer for the next instruction */
        }
        parse_line_fmt(&(ret[0]), bits, "%s esp,%s", instrName, memoryStringRep);
    } else {
        nasm_fatal("LFI: Unexpected operand type in RSP manipulation");
    }

    parse_line_fmt(&(ret[1]), bits, "lea rsp,[rsp+%s]", sbx_base);
}

/* Rewrite 4: LEA into RSP */
static void rewrite_rsp_lea(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    int bits = ins->bits;
    *count = 2;
    *bundle_lock_mask = 0b0010;

    const char *baseReg32 = (ins->oprs[1].basereg != R_none) ? get_32bit_reg_name(ins->oprs[1].basereg) : "";
    const char *indexReg32 = (ins->oprs[1].indexreg != R_none) ? get_32bit_reg_name(ins->oprs[1].indexreg) : "";
    int scale = ins->oprs[1].scale;
    int64_t offset = ins->oprs[1].offset;
    const char *sbx_base = regName(LFI_SBX_BASE);

    if (indexReg32[0] != '\0') {
        if (scale > 1) {
            parse_line_fmt(&(ret[0]), bits, "lea esp,[%s+%s*%d+%ld]", baseReg32, indexReg32, scale, offset);
        } else {
            parse_line_fmt(&(ret[0]), bits, "lea esp,[%s+%s+%ld]", baseReg32, indexReg32, offset);
        }
    } else {
        parse_line_fmt(&(ret[0]), bits, "lea esp,[%s+%ld]", baseReg32, offset);
    }

    parse_line_fmt(&(ret[1]), bits, "lea rsp,[rsp+%s]", sbx_base);
}

/* Rewrite 5: Indirect Jumps and Calls through Register or Memory */
static void rewrite_indirect_branch(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    int bits = ins->bits;
    const char *instrName = (ins->opcode == I_CALL) ? "call" : "jmp";

    const char *scratch = regName(LFI_SCRATCH_REG);
    const char *scratch32 = get_32bit_reg_name(LFI_SCRATCH_REG);
    const char *sbx_base = regName(LFI_SBX_BASE);

    if (is_op_type(ins->oprs[0], REGISTER)) {
        enum reg_enum targetReg = ins->oprs[0].basereg;
        const char *targetReg32 = get_32bit_reg_name(targetReg);
        const char *targetReg64 = regName(get_64bit_parent(targetReg));

        *count = 3;
        *bundle_lock_mask = 0b0110;

        parse_line_fmt(&(ret[0]), bits, "and %s,-32", targetReg32);
        parse_line_fmt(&(ret[1]), bits, "add %s,%s", targetReg64, sbx_base);
        parse_line_fmt(&(ret[2]), bits, "%s %s", instrName, targetReg64);
    }
    else if (is_op_type(ins->oprs[0], MEMORY)) {
        char memoryStringRep[256];
        bool isSafe = is_safe_memop(&ins->oprs[0]);

        if (isSafe) {
            /* Safe memory operands (e.g. [rsp], [rbp]) do not require sandboxing the load address */
            get_explicit_memstr(&ins->oprs[0], ins->oprs[0].basereg, ins->oprs[0].indexreg, ins->oprs[0].scale, ins->oprs[0].offset, memoryStringRep);
            *count = 4;
            *bundle_lock_mask = 0b1100; /* [and, add, jmp/call] are locked (bits 2,3,4) */

            parse_line_fmt(&(ret[0]), bits, "mov %s,%s", scratch, memoryStringRep);
        } else {
            /* Unsafe memory operands require sandboxing the load address */
            if (!lfi_no_segue) {
                get_segue_memstr(&ins->oprs[0], memoryStringRep);
                *count = 4;
                *bundle_lock_mask = 0b1100; /* [and, add, jmp/call] are locked (bits 2,3,4) */

                parse_line_fmt(&(ret[0]), bits, "mov %s,%s", scratch, memoryStringRep);
            } else {
                get_explicit_memstr(&ins->oprs[0], LFI_SBX_BASE, LFI_SCRATCH_REG, 1, 0, memoryStringRep);
                *count = 5;
                *bundle_lock_mask = 0b11100; /* [mov, and, add, jmp/call] are locked (bits 3,4,5) */

                char preLoad[128];
                get_nosegue_addr(&ins->oprs[0], scratch32, preLoad);
                parse_line(preLoad, &(ret[0]), bits);
                parse_line_fmt(&(ret[1]), bits, "mov %s,%s", scratch, memoryStringRep);
                ret++; /* Shift ret pointer for the remaining instructions */
            }
        }

        parse_line_fmt(&(ret[1]), bits, "and %s,-32", scratch32);
        parse_line_fmt(&(ret[2]), bits, "add %s,%s", scratch, sbx_base);
        parse_line_fmt(&(ret[3]), bits, "%s %s", instrName, scratch);
    }
}

/* Rewrite 6: System Calls (syscall) */
static void rewrite_syscall(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    int bits = ins->bits;
    static int64_t last_pass = -1;
    static int syscall_label_counter = 0;

    int64_t current_pass = pass_count();
    if (current_pass != last_pass) {
        syscall_label_counter = 0;
        last_pass = current_pass;
    }

    *count = 3;
    *bundle_lock_mask = 0b0010;

    /* Generate a unique local label for return address */
    char labelStr[64];
    sprintf(labelStr, ".Ltmp_sys%d", syscall_label_counter++);

    const char *scratch = regName(LFI_SCRATCH_REG);
    const char *sbx_base = regName(LFI_SBX_BASE);

    parse_line_fmt(&(ret[0]), bits, "lea %s,[rel %s]", scratch, labelStr);
    parse_line_fmt(&(ret[1]), bits, "jmp [%s]", sbx_base);

    memset(&(ret[2]), 0, sizeof(insn));
    ret[2].opcode = I_none;
    ret[2].label = nasm_strdup(labelStr);
}

/* Rewrite 7: Thread-Local Storage (TLS) Reads (loads from %fs:offset) */
static void rewrite_tlsread(insn *ins, int mem_index, int *count, insn *ret)
{
    int bits = ins->bits;
    operand *fsOp = &ins->oprs[mem_index];

    const char *scratch = regName(LFI_SCRATCH_REG);
    const char *ctxreg = regName(LFI_CTXREG);

    /* Case 7a: Optimized simple thread-pointer load (e.g. mov rax, [fs:0]) */
    if (ins->opcode == I_MOV && fsOp->offset == 0 && fsOp->basereg == R_none && fsOp->indexreg == R_none) {
        *count = 1;
        char opsStr[3][256];
        for (int i = 0; i < ins->operands; i++) {
            if (i == mem_index) {
                sprintf(opsStr[i], "[%s+32]", ctxreg);
            } else {
                get_operand_string_rep(&ins->oprs[i], opsStr[i]);
            }
        }
        parse_insn_ops(ins, &(ret[0]), opsStr[0], opsStr[1], opsStr[2]);
        return;
    }

    /* Case 7b: Segment Translation -> Load thread pointer into scratch, then access */
    *count = 2;
    parse_line_fmt(&(ret[0]), bits, "mov %s,[%s+32]", scratch, ctxreg);

    char tlsMemStr[256];
    get_tls_memstr(fsOp, LFI_SCRATCH_REG, !lfi_no_loads, tlsMemStr);

    /* Format the main instruction */
    char opsStr[3][256];
    for (int i = 0; i < ins->operands; i++) {
        if (i == mem_index) {
            strcpy(opsStr[i], tlsMemStr);
        } else {
            get_operand_string_rep(&ins->oprs[i], opsStr[i]);
        }
    }
    parse_insn_ops(ins, &(ret[1]), opsStr[0], opsStr[1], opsStr[2]);
}

/* Rewrite 8: Thread-Local Storage (TLS) Writes (stores to %fs:offset) */
static void rewrite_tlswrite(insn *ins, int mem_index, int *count, insn *ret)
{
    int bits = ins->bits;
    operand *fsOp = &ins->oprs[mem_index];

    *count = 2;
    const char *scratch = regName(LFI_SCRATCH_REG);
    const char *ctxreg = regName(LFI_CTXREG);

    parse_line_fmt(&(ret[0]), bits, "mov %s,[%s+32]", scratch, ctxreg);

    char tlsMemStr[256];
    get_tls_memstr(fsOp, LFI_SCRATCH_REG, true, tlsMemStr);

    /* Format the main instruction (store) */
    char opsStr[3][256];
    for (int i = 0; i < ins->operands; i++) {
        if (i == mem_index) {
            strcpy(opsStr[i], tlsMemStr);
        } else {
            get_operand_string_rep(&ins->oprs[i], opsStr[i]);
        }
    }
    parse_insn_ops(ins, &(ret[1]), opsStr[0], opsStr[1], opsStr[2]);
}

/* =========================================================================
 * 3. Instruction Classification Predicates
 * ========================================================================= */

static bool is_syscall(insn *ins)
{
    return ins->opcode == I_SYSCALL;
}

static bool is_tls_access(insn *ins)
{
    int mem_index = get_mem_op_index(ins);
    return mem_index != -1 && (ins->oprs[mem_index].eaflags & EAF_FS);
}

static bool is_direct_call(insn *ins)
{
    return ins->opcode == I_CALL && ins->operands == 1 &&
           !is_op_type(ins->oprs[0], REGISTER) && !is_op_type(ins->oprs[0], MEMORY);
}

static bool is_indirect_branch(insn *ins)
{
    return (ins->opcode == I_JMP || ins->opcode == I_CALL) && ins->operands == 1 &&
           (is_op_type(ins->oprs[0], REGISTER) || is_op_type(ins->oprs[0], MEMORY));
}

static bool is_return(insn *ins)
{
    return ins->opcode == I_RET || ins->opcode == I_RETN || ins->opcode == I_RETF;
}

static bool is_string_op(insn *ins)
{
    return ins->opcode == I_CMPSB || ins->opcode == I_CMPSW || ins->opcode == I_CMPSD || ins->opcode == I_CMPSQ ||
           ins->opcode == I_MOVSB || ins->opcode == I_MOVSW || ins->opcode == I_MOVSD || ins->opcode == I_MOVSQ ||
           ins->opcode == I_STOSB || ins->opcode == I_STOSD || ins->opcode == I_STOSQ || ins->opcode == I_STOSW;
}

static bool is_stack_mod(insn *ins)
{
    /* pop rsp */
    if (ins->opcode == I_POP && ins->operands == 1 && is_op_type(ins->oprs[0], REGISTER) && ins->oprs[0].basereg == R_RSP) {
        return true;
    }
    /* Direct RSP updates (add rsp, imm, etc.) */
    if (ins->operands == 2 && is_op_type(ins->oprs[0], REGISTER) && ins->oprs[0].basereg == R_RSP && ins->opcode != I_LEA) {
        return true;
    }
    /* LEA into RSP (lea rsp, [rax+8]) */
    if (ins->opcode == I_LEA && is_op_type(ins->oprs[0], REGISTER) && ins->oprs[0].basereg == R_RSP) {
        return true;
    }
    return false;
}

static bool modifies_reserved_reg(insn *ins, enum reg_enum reg)
{
    /* Simple check to prevent modifications of R14 base register */
    for (int i = 0; i < ins->operands; i++) {
        if (is_op_type(ins->oprs[i], REGISTER) && ins->oprs[i].basereg == reg) {
            /* If it is a destination operand in a register-modifying instruction */
            if (i == 0 && ins->opcode != I_CMP && ins->opcode != I_TEST) {
                return true;
            }
        }
    }
    return false;
}

static bool uses_gs_invalidly(insn *ins)
{
    /* GS segment is reserved for sandboxing, user assembly should not use it explicitly */
    for (int i = 0; i < ins->operands; i++) {
        if (is_op_type(ins->oprs[i], MEMORY) && (ins->oprs[i].eaflags & EAF_GS)) {
            return true;
        }
    }
    return false;
}

/* =========================================================================
 * 4. Instruction Expansion Helpers
 * ========================================================================= */

static void expand_syscall(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    rewrite_syscall(ins, count, ret, bundle_lock_mask);
}

static void expand_tlsread(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    int mem_index = get_mem_op_index(ins);
    rewrite_tlsread(ins, mem_index, count, ret);
    *bundle_lock_mask = 0b0000; /* TLS reads are not bundle-locked */
}

static void expand_tlswrite(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    rewrite_tlswrite(ins, 0, count, ret);
    *bundle_lock_mask = 0b0000; /* TLS writes are not bundle-locked */
}

static void expand_direct_call(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    /* Direct call: Align to end of bundle.
     * We achieve this by wrapping it in a bundle lock with size 1.
     */
    *count = 1;
    *bundle_lock_mask = 0b0001;
    ret[0] = *ins;
    ret[0].times = 1;
}

static void expand_indirect_branch(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    rewrite_indirect_branch(ins, count, ret, bundle_lock_mask);
}

static void expand_return(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    rewrite_return(ins, count, ret, bundle_lock_mask);
}

static void expand_stack_mod(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    if (ins->opcode == I_POP && ins->oprs[0].basereg == R_RSP) {
        rewrite_rsp_pop(ins, count, ret, bundle_lock_mask);
    } else if (ins->opcode == I_LEA && ins->oprs[0].basereg == R_RSP) {
        rewrite_rsp_lea(ins, count, ret, bundle_lock_mask);
    } else {
        rewrite_rsp_update(ins, count, ret, bundle_lock_mask);
    }
}

static void expand_string_op(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    int bits = ins->bits;
    const char *sbx_base = regName(LFI_SBX_BASE);

    /* 1. cmpsb, cmpsw, cmpsd, cmpsq */
    if (ins->opcode == I_CMPSB || ins->opcode == I_CMPSW || ins->opcode == I_CMPSD || ins->opcode == I_CMPSQ) {
        if (lfi_no_loads) {
            *count = 1;
            *bundle_lock_mask = 0b0000;
            ret[0] = *ins;
            ret[0].times = 1;
            return;
        }
        *count = 5;
        *bundle_lock_mask = 0b11110;
        parse_line("mov esi,esi", &(ret[0]), bits);
        parse_line_fmt(&(ret[1]), bits, "lea rsi,[%s+rsi]", sbx_base);
        parse_line("mov edi,edi", &(ret[2]), bits);
        parse_line_fmt(&(ret[3]), bits, "lea rdi,[%s+rdi]", sbx_base);
        ret[4] = *ins;
        ret[4].times = 1;
    }
    /* 2. movsb, movsw, movsd, movsq */
    else if (ins->opcode == I_MOVSB || ins->opcode == I_MOVSW || ins->opcode == I_MOVSD || ins->opcode == I_MOVSQ) {
        bool sandboxLoad = !lfi_no_loads;
        bool sandboxStore = !lfi_no_stores;

        if (sandboxLoad && sandboxStore) {
            *count = 5;
            *bundle_lock_mask = 0b11110;
            parse_line("mov esi,esi", &(ret[0]), bits);
            parse_line_fmt(&(ret[1]), bits, "lea rsi,[%s+rsi]", sbx_base);
            parse_line("mov edi,edi", &(ret[2]), bits);
            parse_line_fmt(&(ret[3]), bits, "lea rdi,[%s+rdi]", sbx_base);
            ret[4] = *ins;
            ret[4].times = 1;
        } else if (sandboxLoad) {
            *count = 3;
            *bundle_lock_mask = 0b0110;
            parse_line("mov esi,esi", &(ret[0]), bits);
            parse_line_fmt(&(ret[1]), bits, "lea rsi,[%s+rsi]", sbx_base);
            ret[2] = *ins;
            ret[2].times = 1;
        } else if (sandboxStore) {
            *count = 3;
            *bundle_lock_mask = 0b0110;
            parse_line("mov edi,edi", &(ret[0]), bits);
            parse_line_fmt(&(ret[1]), bits, "lea rdi,[%s+rdi]", sbx_base);
            ret[2] = *ins;
            ret[2].times = 1;
        } else {
            *count = 1;
            *bundle_lock_mask = 0b0000;
            ret[0] = *ins;
            ret[0].times = 1;
        }
    }
    /* 3. stosb, stosw, stosd, stosq */
    else if (ins->opcode == I_STOSB || ins->opcode == I_STOSD || ins->opcode == I_STOSQ || ins->opcode == I_STOSW) {
        if (lfi_no_stores) {
            *count = 1;
            *bundle_lock_mask = 0b0000;
            ret[0] = *ins;
            ret[0].times = 1;
            return;
        }
        *count = 3;
        *bundle_lock_mask = 0b0110;
        parse_line("mov edi,edi", &(ret[0]), bits);
        parse_line_fmt(&(ret[1]), bits, "lea rdi,[%s+rdi]", sbx_base);
        ret[2] = *ins;
        ret[2].times = 1;
    }
}

static void expand_load_store(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    int bits = ins->bits;
    int mem_index = get_mem_op_index(ins);

    if (mem_index == -1) {
        goto bypass;
    }

    /* 1. Determine if this is a store or a load */
    bool isStore = (mem_index == 0 && ins->opcode != I_LEA);
    if (isStore && is_x87_insn_with_mem(ins) && !is_x87_store(ins->opcode)) {
        isStore = false; /* x87 arithmetic with memory is a load */
    }

    /* For non-store instructions, verify it is actually a load (e.g. bypass LEA) */
    if (!isStore && !is_memload(ins, mem_index)) {
        goto bypass;
    }

    /* 2. Check bypass flags */
    if (isStore && lfi_no_stores) {
        goto bypass;
    }
    if (!isStore && lfi_no_loads) {
        goto bypass;
    }

    /* 3. Check if the memory operand is safe (stack/frame/absolute pointer relative) */
    if (is_safe_memop(&ins->oprs[mem_index])) {
        goto bypass;
    }

    /* 4. Segue Mode: In-place rewrite to use GS segment override */
    if (!lfi_no_segue) {
        *count = 1;
        *bundle_lock_mask = 0b0000;
        rewrite_gs_mem(ins, mem_index, &(ret[0]));
        return;
    }

    /* 5. No-Segue Mode: Explicit base addition */
    else {
        if (isStore) {
            char memoryStringRep[256];
            *count = 2;
            *bundle_lock_mask = 0b0010;

            operand *memOp = &ins->oprs[0];
            char addressCalcStr[1024];
            const char *scratch32 = get_32bit_reg_name(LFI_SCRATCH_REG);
            get_nosegue_addr(memOp, scratch32, addressCalcStr);
            parse_line(addressCalcStr, &(ret[0]), bits);

            /* Format original instruction relative to SBX_BASE+SCRATCH */
            get_explicit_memstr(memOp, LFI_SBX_BASE, LFI_SCRATCH_REG, 1, 0, memoryStringRep);

            char opsStr[3][256];
            strcpy(opsStr[0], memoryStringRep);
            get_operand_string_rep(&ins->oprs[1], opsStr[1]);
            get_operand_string_rep(&ins->oprs[2], opsStr[2]);

            parse_insn_ops(ins, &(ret[1]), opsStr[0], opsStr[1], opsStr[2]);
            return;
        } else {
            *count = 2;
            *bundle_lock_mask = 0b0010;

            operand *memOp = &ins->oprs[mem_index];
            enum reg_enum scratchReg = LFI_SCRATCH_REG;

            /* Optimization: If it is a simple MOV load, reuse the destination register as scratch */
            if (ins->opcode == I_MOV && is_op_type(ins->oprs[0], REGISTER)) {
                scratchReg = ins->oprs[0].basereg;
            }

            const char *scratch32 = get_32bit_reg_name(scratchReg);

            char addressCalcStr[1024];
            get_nosegue_addr(memOp, scratch32, addressCalcStr);
            parse_line(addressCalcStr, &(ret[0]), bits);

            /* Format original instruction relative to r14+scratch */
            char memoryStringRep[256];
            get_explicit_memstr(memOp, LFI_SBX_BASE, scratchReg, 1, 0, memoryStringRep);

            char opsStr[3][256];
            for (int i = 0; i < ins->operands; i++) {
                if (i == mem_index) {
                    strcpy(opsStr[i], memoryStringRep);
                } else {
                    get_operand_string_rep(&ins->oprs[i], opsStr[i]);
                }
            }

            parse_insn_ops(ins, &(ret[1]), opsStr[0], opsStr[1], opsStr[2]);
            return;
        }
    }

bypass:
    *count = 1;
    *bundle_lock_mask = 0b0000;
    ret[0] = *ins;
    ret[0].times = 1;
    return;
}

/*
 * High-level driver to replace instructions with LFI sandboxed sequences.
 * Dispatches to specialized expand modules matching the LLVM rewriter's structure.
 */
static void rewrite_insn(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    if (ofmt != &of_elf64) {
        nasm_fatal("LFI: LFI mode is only supported for the elf64 output format");
    }

    /* Check for modification of reserved register R14 */
    if (modifies_reserved_reg(ins, LFI_SBX_BASE)) {
        nasm_fatal("LFI: illegal modification of reserved LFI register %%r14");
    }

    /* Dispatch based on instruction type, matching LLVM X86MCLFIRewriter.cpp */
    if (is_syscall(ins)) {
        expand_syscall(ins, count, ret, bundle_lock_mask);
    } else if (is_tls_access(ins)) {
        int mem_index = get_mem_op_index(ins);
        if (is_memload(ins, mem_index)) {
            expand_tlsread(ins, count, ret, bundle_lock_mask);
        } else {
            expand_tlswrite(ins, count, ret, bundle_lock_mask);
        }
    } else if (is_direct_call(ins)) {
        expand_direct_call(ins, count, ret, bundle_lock_mask);
    } else if (is_indirect_branch(ins)) {
        expand_indirect_branch(ins, count, ret, bundle_lock_mask);
    } else if (is_return(ins)) {
        expand_return(ins, count, ret, bundle_lock_mask);
    } else if (is_string_op(ins)) {
        expand_string_op(ins, count, ret, bundle_lock_mask);
    } else if (is_stack_mod(ins)) {
        expand_stack_mod(ins, count, ret, bundle_lock_mask);
    } else {
        /* Check for invalid use of GS segment in general instructions */
        if (uses_gs_invalidly(ins)) {
            nasm_fatal("LFI: invalid use of %%gs segment register");
        }
        expand_load_store(ins, count, ret, bundle_lock_mask);
    }
}

/* =========================================================================
 * 4. Layout, Padding, and Alignment Calculations
 * ========================================================================= */

/* Calculate the padding required to avoid straddling 32-byte boundaries */
static int get_bundle_padsize(int64_t offset, int minSpaceInCurrBlock, int64_t rawInstrSize, bool align_to_end)
{
    if (ofmt == &of_elf64) {
        if (rawInstrSize >= 32) {
            nasm_nonfatal("LFI: Instruction size greater than or equal to 32");
            return 0;
        }

        if (minSpaceInCurrBlock > 32) {
            nasm_nonfatal("LFI: More than 32 bytes of instructions that can't be separated");
            return 0;
        }

        if (rawInstrSize <= 0) {
            return 0;
        }

        int previousFinishOffset = (offset + 31) % 32;
        int currentStartOffset = (previousFinishOffset + 1) % 32;
        int remainingSpace = 32 - currentStartOffset;

        /* Align to end of bundle (for call instructions) */
        if (align_to_end) {
            int paddingRequired = (32 - (currentStartOffset + minSpaceInCurrBlock) % 32) % 32;
            return paddingRequired;
        }

        if (minSpaceInCurrBlock > remainingSpace) {
            return remainingSpace;
        }

        int currentInstructionFinishOffset = (currentStartOffset + rawInstrSize + 31) % 32;
        if (currentInstructionFinishOffset < rawInstrSize - 1) {
            /* instruction would straddle 32-byte boundary, pad to start of next block */
            return 32 - previousFinishOffset - 1;
        } else {
            return 0;
        }
    } else {
        nasm_nonfatal("LFI: Boundary checks not supported in formats other than elf64");
        return 0;
    }
    return 0; /* Satisfy compiler */
}

/* Process an instruction under LFI sandboxing rules */
void lfi_process_insn(insn *ins)
{
    int rewriteCount = 0;
    insn rewrittenInsns[16];
    memset(rewrittenInsns, 0, sizeof(rewrittenInsns));
    bundle_lock_mask_t bundle_lock_mask = 0;

    if (ins->opcode == I_none) {
        /* Only a label, it is aligned in lfi_align_label_if_needed */
        process_one_insn(ins);
        return;
    }

    int32_t times = ins->times;
    if (times <= 0) {
        return;
    }

    rewrite_insn(ins, &rewriteCount, rewrittenInsns, &bundle_lock_mask);

    while (times--) {
        for (int i = 0; i < rewriteCount; i++) {
            insn *curr_ins = &rewrittenInsns[i];

            if (curr_ins->opcode == I_none && curr_ins->label != NULL) {
                define_label(curr_ins->label, location.segment, location.offset, true);
                continue;
            }

            curr_ins->loc = location;

            int64_t currInstSize = insn_size(curr_ins);
            if (currInstSize < 0) {
                process_one_insn(curr_ins);
                continue;
            }

            /* Calculate the size of the current bundle-locked block */
            int minSpaceInCurrBlock = 0;
            int end_of_block = i;
            for (int j = i; j < rewriteCount; j++) {
                if (j > i && !(bundle_lock_mask & (1 << j))) {
                    break;
                }
                end_of_block = j;
                int64_t size = insn_size(&rewrittenInsns[j]);
                if (size > 0) {
                    minSpaceInCurrBlock += size;
                }
            }

            /* Detect if the block ends with a CALL (which requires aligning to the end of the bundle) */
            bool align_to_end = false;
            if (rewrittenInsns[end_of_block].opcode == I_CALL) {
                align_to_end = true;
            }

            int paddingSize = get_bundle_padsize(location.offset, minSpaceInCurrBlock, currInstSize, align_to_end);

            if (paddingSize > 0) {
                insn noop_ins;
                memset(&noop_ins, 0, sizeof(noop_ins));
                noop_ins.opcode = I_NOP;
                noop_ins.times = 1;
                noop_ins.bits = curr_ins->bits;

                for (int p = 0; p < paddingSize; p++) {
                    noop_ins.loc = location;
                    process_one_insn(&noop_ins);
                }
            }

            curr_ins->loc = location;
            process_one_insn(curr_ins);
        }
    }

    /* Free any dynamically allocated label strings to prevent memory leaks */
    for (int i = 0; i < rewriteCount; i++) {
        if (rewrittenInsns[i].opcode == I_none && rewrittenInsns[i].label != NULL) {
            nasm_free((void *)rewrittenInsns[i].label);
        }
    }
}

/* Scans the line to check if it defines a label */
static bool check_is_label(char *buffer)
{
    int i;
    struct tokenval local_tokval;

    stdscan_reset(buffer);
    i = stdscan(NULL, &local_tokval);

    if (i == TOKEN_EOS)
        return false;

    if (i == '[') {
        i = stdscan(NULL, &local_tokval);
        if (local_tokval.t_charptr && strcmp("global", local_tokval.t_charptr) == 0) {
            i = stdscan(NULL, &local_tokval);
        }
    }

    if (i != TOKEN_ID &&
        i != TOKEN_INSN &&
        i != TOKEN_PREFIX &&
        (i != TOKEN_REG || !IS_SREG(local_tokval.t_integer))) {
        return false;
    }

    if (i == TOKEN_ID) {
        i = stdscan(NULL, &local_tokval);
        if (i == ':') {
            i = stdscan(NULL, &local_tokval);
        }
    }

    if (i == TOKEN_EOS || (local_tokval.t_charptr && strcmp("function", local_tokval.t_charptr) == 0))
        return true;

    while (i == TOKEN_PREFIX ||
           (i == TOKEN_REG && IS_SREG(local_tokval.t_integer))) {
        i = stdscan(NULL, &local_tokval);
    }

    if (local_tokval.t_integer == I_none) {
        return true;
    }

    return false;
}

/* Align label to 32-byte boundary if needed for LFI */
void lfi_align_label_if_needed(char *line)
{
    if (lfi_mode && check_is_label(line) && !is_local_label(line)) {
        int paddingRequired = (32 - (location.offset % 32)) % 32;
        if (paddingRequired > 0) {
            insn padding_ins;
            char paddingInstruction[128];
            sprintf(paddingInstruction, "times %d nop", paddingRequired);

            parse_line(paddingInstruction, &padding_ins, globl.bits);
            process_insn(&padding_ins);
            cleanup_insn(&padding_ins);
        }
    }
}
