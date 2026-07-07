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
 * Unified LFI error and warning reporting helper.
 *
 * Under strict mode (default), it routes errors to nasm_fatal or nasm_nonfatal.
 * Under permissive mode (-lfi-warn-only), it maps all errors to warnings,
 * allowing compilation to continue, instructions to be emitted, and the build to succeed.
 */
static void lfi_report_error(bool is_fatal, const char *fmt, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (lfi_warn_only) {
        nasm_error(ERR_WARNING | WARN_OTHER, "%s", buf);
    } else if (is_fatal) {
        nasm_fatal("%s", buf);
    } else {
        nasm_nonfatal("%s", buf);
    }
}

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

static void expand_load_store(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask);

/* =========================================================================
 * 1. Low-Level Register and Memory Helper Utilities
 * ========================================================================= */

static bool is_vector_reg(enum reg_enum reg)
{
    if (reg == R_none) return false;
    opflags_t flags = nasm_reg_flags[reg];
    opflags_t reg_class = flags & REG_CLASS_MASK;
    return (reg_class == REG_CLASS_RM_XMM ||
            reg_class == REG_CLASS_RM_YMM ||
            reg_class == REG_CLASS_RM_ZMM);
}

static bool is_lfi_unsafe_vsib(const insn *ins)
{
    switch (ins->opcode) {
        case I_VPGATHERDQ:
        case I_VPGATHERQQ:
        case I_VPSCATTERDQ:
        case I_VPSCATTERQQ:
        case I_VGATHERQPD:
        case I_VGATHERQPS:
        case I_VSCATTERQPD:
        case I_VSCATTERQPS:
            return true;
        default:
            return false;
    }
}

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

static enum reg_enum get_32bit_reg_enum(enum reg_enum reg)
{
    switch (get_64bit_parent(reg)) {
        case R_RAX: return R_EAX;
        case R_RBX: return R_EBX;
        case R_RCX: return R_ECX;
        case R_RDX: return R_EDX;
        case R_RSI: return R_ESI;
        case R_RDI: return R_EDI;
        case R_RBP: return R_EBP;
        case R_RSP: return R_ESP;
        case R_R8:  return R_R8D;
        case R_R9:  return R_R9D;
        case R_R10: return R_R10D;
        case R_R11: return R_R11D;
        case R_R12: return R_R12D;
        case R_R13: return R_R13D;
        case R_R14: return R_R14D;
        case R_R15: return R_R15D;
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
    if (is_ea_flags(*op, EAF_REL) || is_op_type(*op, IP_REL)) {
        return true; /* RIP-relative is always safe */
    }
    if (op->indexreg != R_none) {
        return false; /* Any index register makes it unsafe and requires truncation/sandboxing */
    }
    enum reg_enum base = op->basereg;
    if (base == R_RSP || base == R_RBP) {
        return true; /* Stack and frame pointer accesses are always safe */
    }
    /* Context register access is always safe (user R15 accesses are virtualized before this) */
    if (base == LFI_CTXREG) {
        return true;
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


static void update_mem_operand_subclass_flags(operand *op)
{
    /* Preserve size flags and modifiers (bits 32-63) */
    opflags_t size_flags = op->type & ~OP_GENMASK(32, 0);
    
    /* Clear OPTYPE, REG_CLASS, and SUBCLASS flags (bits 0-31) */
    op->type &= ~OP_GENMASK(32, 0);
    
    /* Call the parser's type setup logic to rebuild them correctly */
    mref_set_optype(op);
    
    /* Restore size flags */
    op->type |= size_flags;
}

static void init_insn(insn *ins)
{
    memset(ins, 0, sizeof(insn));
    for (int i = 0; i < MAX_OPERANDS; i++) {
        ins->oprs[i].basereg = R_none;
        ins->oprs[i].indexreg = R_none;
        ins->oprs[i].segment = NO_SEG;
        ins->oprs[i].wrt = NO_SEG;
        ins->oprs[i].opidx = i;
    }
}

static void build_tls_mem_operand(operand *fsOp, enum reg_enum scratch_reg, bool use_gs, operand *dest)
{
    *dest = *fsOp;
    dest->type = MEMORY | (fsOp->type & SIZE_MASK);
    dest->eaflags &= ~(EAF_FS | EAF_GS); /* Clear segment flags */
    dest->hintbase = -1;
    dest->hinttype = EAH_NOHINT;
    if (use_gs) {
        dest->eaflags |= EAF_GS;
    }

    enum reg_enum scratch = use_gs ? get_32bit_reg_enum(scratch_reg) : scratch_reg;
    enum reg_enum orig_base = fsOp->basereg;
    enum reg_enum orig_index = fsOp->indexreg;

    if (use_gs) {
        if (orig_base != R_none) orig_base = get_32bit_reg_enum(orig_base);
        if (orig_index != R_none) orig_index = get_32bit_reg_enum(orig_index);
    }

    if (orig_base != R_none && orig_index != R_none) {
        nasm_fatal("LFI: TLS memory operand has both base and index registers, cannot add scratch");
    }

    dest->basereg = scratch;
    if (orig_base != R_none) {
        dest->indexreg = orig_base;
        dest->scale = 1;
    } else if (orig_index != R_none) {
        dest->indexreg = orig_index;
        dest->scale = fsOp->scale;
    } else {
        dest->indexreg = R_none;
    }

    update_mem_operand_subclass_flags(dest);
}

static void rewrite_nosegue_mem_operand(insn *ins, int mem_index, enum reg_enum scratch_reg, insn *dest)
{
    *dest = *ins;
    dest->times = 1;
    operand *op = &dest->oprs[mem_index];
    op->basereg = LFI_SBX_BASE;   /* R_R14 */
    op->indexreg = get_64bit_parent(scratch_reg); /* Scratch reg must be 64-bit */
    op->scale = 1;
    op->offset = 0;
    op->segment = NO_SEG;
    op->eaflags &= ~(EAF_FS | EAF_GS | EAF_REL);
    update_mem_operand_subclass_flags(op);
}

static void build_nosegue_addr_insn(operand *memOp, enum reg_enum dest_reg, insn *dest, int bits)
{
    enum reg_enum dest_reg32 = get_32bit_reg_enum(dest_reg);
    enum reg_enum baseReg = memOp->basereg;
    enum reg_enum indexReg = memOp->indexreg;
    int scale = memOp->scale;
    int64_t offset = memOp->offset;

    if (baseReg == LFI_SBX_BASE) {
        baseReg = R_none;
    }

    init_insn(dest);
    dest->bits = bits;

    /* Optimization: If it's a simple register copy, use MOV instead of LEA */
    if (offset == 0 && indexReg == R_none && baseReg != R_none) {
        dest->opcode = I_MOV;
        dest->operands = 2;
        dest->oprs[0].type = nasm_reg_flags[dest_reg32];
        dest->oprs[0].basereg = dest_reg32;
        dest->oprs[1].type = nasm_reg_flags[get_32bit_reg_enum(baseReg)];
        dest->oprs[1].basereg = get_32bit_reg_enum(baseReg);
    } else if (offset == 0 && baseReg == R_none && indexReg != R_none && scale == 1) {
        dest->opcode = I_MOV;
        dest->operands = 2;
        dest->oprs[0].type = nasm_reg_flags[dest_reg32];
        dest->oprs[0].basereg = dest_reg32;
        dest->oprs[1].type = nasm_reg_flags[get_32bit_reg_enum(indexReg)];
        dest->oprs[1].basereg = get_32bit_reg_enum(indexReg);
    } else {
        dest->opcode = I_LEA;
        dest->operands = 2;
        dest->oprs[0].type = nasm_reg_flags[dest_reg32];
        dest->oprs[0].basereg = dest_reg32;
        
        dest->oprs[1] = *memOp;
        dest->oprs[1].type = (dest->oprs[1].type & ~SIZE_MASK) | BITS64; // Keep 64-bit address size
        if (dest->oprs[1].basereg == LFI_SBX_BASE) {
            dest->oprs[1].basereg = R_none;
        }
        update_mem_operand_subclass_flags(&dest->oprs[1]);
    }
}



/* Mutate a memory operand in-place to Segue mode (adds GS override and downcasts to 32-bit) */
static void mutate_segue_mem_operand(operand *op)
{
    op->eaflags |= EAF_GS;
    if (op->basereg != R_none) {
        op->basereg = get_32bit_reg_enum(op->basereg);
    }
    if (op->indexreg != R_none) {
        op->indexreg = get_32bit_reg_enum(op->indexreg);
    }
    update_mem_operand_subclass_flags(op);
}

/* Mutate an instruction's memory operand to Segue mode */
static void rewrite_segue_mem_operand(insn *ins, int mem_index, insn *dest)
{
    *dest = *ins;
    dest->times = 1;
    mutate_segue_mem_operand(&dest->oprs[mem_index]);
    dest->prefixes[PPS_SEG] = R_GS;
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
        if (!lfi_no_segue) {
            rewrite_segue_mem_operand(ins, 1, &(ret[0]));
            ret[0].oprs[0].type = nasm_reg_flags[R_ESP];
            ret[0].oprs[0].basereg = R_ESP;
        } else {
            *count = 3;
            *bundle_lock_mask = 0b0110;
            build_nosegue_addr_insn(&ins->oprs[1], LFI_SCRATCH_REG, &(ret[0]), bits);
            ret++; /* shift ret pointer for the next instruction */
            
            rewrite_nosegue_mem_operand(ins, 1, LFI_SCRATCH_REG, &(ret[0]));
            ret[0].oprs[0].type = nasm_reg_flags[R_ESP];
            ret[0].oprs[0].basereg = R_ESP;
        }
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

/* Helper to emit the indirect branch mask-and-jump sequence */
static void emit_indirect_branch_seq(enum reg_enum target_reg, const char *instr_name, int bits, insn *dest)
{
    const char *reg64 = regName(get_64bit_parent(target_reg));
    const char *reg32 = get_32bit_reg_name(target_reg);
    const char *sbx_base = regName(LFI_SBX_BASE);

    parse_line_fmt(&(dest[0]), bits, "and %s,-32", reg32);
    parse_line_fmt(&(dest[1]), bits, "add %s,%s", reg64, sbx_base);
    parse_line_fmt(&(dest[2]), bits, "%s %s", instr_name, reg64);
}

/* Rewrite 5: Indirect Jumps and Calls through Register or Memory */
static void rewrite_indirect_branch(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    int bits = ins->bits;
    const char *instrName = (ins->opcode == I_CALL) ? "call" : "jmp";

    if (is_op_type(ins->oprs[0], REGISTER)) {
        *count = 3;
        *bundle_lock_mask = 0b0110;
        emit_indirect_branch_seq(ins->oprs[0].basereg, instrName, bits, ret);
    }
    else if (is_op_type(ins->oprs[0], MEMORY)) {
        /* 1. Build a GPR memory load into the scratch register */
        insn load_ins;
        init_insn(&load_ins);
        load_ins.opcode = I_MOV;
        load_ins.operands = 2;
        load_ins.bits = bits;
        load_ins.oprs[0].type = nasm_reg_flags[LFI_SCRATCH_REG];
        load_ins.oprs[0].basereg = LFI_SCRATCH_REG;
        load_ins.oprs[1] = ins->oprs[0];
        load_ins.oprs[1].type = (load_ins.oprs[1].type & ~SIZE_MASK) | BITS64;

        /* 2. Delegate sandboxing of this load to expand_load_store */
        int load_count = 0;
        bundle_lock_mask_t load_lock_mask = 0;
        expand_load_store(&load_ins, &load_count, ret, &load_lock_mask);

        /* 3. Append the branch sequence (mask, base addition, branch) */
        emit_indirect_branch_seq(LFI_SCRATCH_REG, instrName, bits, ret + load_count);

        *count = load_count + 3;
        *bundle_lock_mask = load_lock_mask | (0b110 << load_count);
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

    init_insn(&(ret[2]));
    ret[2].opcode = I_none;
    ret[2].label = nasm_strdup(labelStr);
}

/* Rewrite 7: Thread-Local Storage (TLS) Reads (loads from %fs:offset) */
/* Unify TLS Read and Write helper logic */
static void rewrite_tls_op(insn *ins, int mem_index, bool use_gs, int *count, insn *ret)
{
    int bits = ins->bits;
    operand *fsOp = &ins->oprs[mem_index];

    /* Case 7a: Optimized simple thread-pointer load (e.g. mov rax, [fs:0]).
     * We only optimize reads, not writes (writes to offset 0 are invalid/not generated).
     */
    bool isStore = (mem_index == 0 && ins->opcode != I_LEA);
    if (!isStore && ins->opcode == I_MOV && fsOp->offset == 0 && fsOp->basereg == R_none && fsOp->indexreg == R_none) {
        *count = 1;
        parse_line_fmt(&(ret[0]), bits, "mov %s,[%s+32]", regName(ins->oprs[0].basereg), regName(LFI_CTXREG));
        return;
    }

    /* Case 7b: Segment Translation -> Load thread pointer into scratch, then access */
    *count = 2;
    
    /* Instruction 0: mov r11, [r15 + 32] */
    parse_line_fmt(&(ret[0]), bits, "mov %s,[%s+32]", regName(LFI_SCRATCH_REG), regName(LFI_CTXREG));

    /* Instruction 1: original instruction with mutated memory operand */
    ret[1] = *ins;
    ret[1].times = 1;
    build_tls_mem_operand(fsOp, LFI_SCRATCH_REG, use_gs, &ret[1].oprs[mem_index]);
    if (use_gs) {
        ret[1].prefixes[PPS_SEG] = R_GS;
    } else {
        ret[1].prefixes[PPS_SEG] = 0;
    }
}

static bool uses_r15_invalidly(insn *ins)
{
    for (int i = 0; i < ins->operands; i++) {
        operand *op = &ins->oprs[i];

        /* Register Operand: R15 is strictly forbidden (prevents context pointer copy bypasses) */
        if (is_op_type(*op, REGISTER)) {
            enum reg_enum parent = get_64bit_parent(op->basereg);
            if (parent == LFI_CTXREG) {
                return true;
            }
        }

        /* Memory Operand: R15 is allowed ONLY as a base register with offset 32 */
        if (is_op_type(*op, MEMORY)) {
            if (op->basereg != R_none) {
                enum reg_enum parent = get_64bit_parent(op->basereg);
                if (parent == LFI_CTXREG && op->offset != 32) {
                    return true;
                }
            }
            if (op->indexreg != R_none) {
                enum reg_enum parent = get_64bit_parent(op->indexreg);
                if (parent == LFI_CTXREG) {
                    return true;
                }
            }
        }
    }
    return false;
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
    enum reg_enum parent_reg = get_64bit_parent(reg);
    for (int i = 0; i < ins->operands; i++) {
        if (is_op_type(ins->oprs[i], REGISTER)) {
            enum reg_enum op_parent = get_64bit_parent(ins->oprs[i].basereg);
            if (op_parent == parent_reg) {
                /* If it is a destination operand in a register-modifying instruction */
                if (i == 0 && ins->opcode != I_CMP && ins->opcode != I_TEST) {
                    return true;
                }
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
    rewrite_tls_op(ins, mem_index, !lfi_no_loads, count, ret);
    *bundle_lock_mask = 0b0000; /* TLS reads are not bundle-locked */
}

static void expand_tlswrite(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
    rewrite_tls_op(ins, 0, !lfi_no_stores, count, ret);
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

/* Build address pre-calculation instructions for VSIB under No-Segue mode.
 * Returns the number of instructions generated (0 or 2). */
static int build_vsib_nosegue_addr_insns(const operand *memOp, insn *dest, int bits)
{
    if (memOp->basereg == R_none) {
        return 0;
    }

    enum reg_enum base32 = get_32bit_reg_enum(memOp->basereg);
    parse_line_fmt(&(dest[0]), bits, "mov r11d, %s", regName(base32));
    parse_line_fmt(&(dest[1]), bits, "add r11, %s", regName(LFI_SBX_BASE));
    return 2;
}

/* Rewrite VSIB memory operand in the target instruction to use sandboxed base. */
static void rewrite_vsib_nosegue_mem_operand(const insn *ins, int mem_index, insn *dest)
{
    *dest = *ins;
    dest->times = 1;
    operand *op = &dest->oprs[mem_index];
    if (op->basereg == R_none) {
        op->basereg = LFI_SBX_BASE;
    } else {
        op->basereg = LFI_SCRATCH_REG;
    }
    op->eaflags &= ~(EAF_FS | EAF_GS | EAF_REL);
    update_mem_operand_subclass_flags(op);
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

    if (!lfi_no_segue) {
        *count = 1;
        *bundle_lock_mask = 0b0000;
        rewrite_segue_mem_operand(ins, mem_index, &(ret[0]));
        return;
    }

    /* 5. No-Segue Mode: Explicit base addition */
    else {
        operand *memOp = &ins->oprs[mem_index];

        if (is_vector_reg(memOp->indexreg)) {
            /* VSIB addressing mode */
            if (is_lfi_unsafe_vsib(ins)) {
                lfi_report_error(true, "LFI: gather/scatter with 64-bit indices is not supported in No-Segue mode (unsafe indices)");
                goto bypass;
            }

            int addr_count = build_vsib_nosegue_addr_insns(memOp, &(ret[0]), bits);
            rewrite_vsib_nosegue_mem_operand(ins, mem_index, &(ret[addr_count]));
            *count = addr_count + 1;
            *bundle_lock_mask = (addr_count == 2) ? 0b0110 : 0b0000;
            return;
        }

        *count = 2;
        *bundle_lock_mask = 0b0010;

        enum reg_enum scratchReg = LFI_SCRATCH_REG;
        if (!isStore) {
            /* Optimization: If it is a simple MOV load, reuse the destination register as scratch */
            if (ins->opcode == I_MOV && is_op_type(ins->oprs[0], REGISTER)) {
                scratchReg = ins->oprs[0].basereg;
            }
        }

        build_nosegue_addr_insn(memOp, scratchReg, &(ret[0]), bits);
        rewrite_nosegue_mem_operand(ins, mem_index, scratchReg, &(ret[1]));
        return;
    }

bypass:
    *count = 1;
    *bundle_lock_mask = 0b0000;
    ret[0] = *ins;
    ret[0].times = 1;
    return;
}

/* Determine virtual offset and size prefix for a virtualized register */
static bool get_virtual_reg_info(enum reg_enum reg, int *offset, const char **size_prefix)
{
    enum reg_enum parent = get_64bit_parent(reg);
    if (parent == LFI_SCRATCH_REG) {
        *offset = 40;
    } else if (parent == LFI_SBX_BASE) {
        *offset = 48;
    } else if (parent == LFI_CTXREG) {
        *offset = 56;
    } else {
        return false;
    }

    switch (reg) {
        case R_R11: case R_R14: case R_R15:
            *size_prefix = "qword";
            break;
        case R_R11D: case R_R14D: case R_R15D:
            *size_prefix = "dword";
            break;
        case R_R11W: case R_R14W: case R_R15W:
            *size_prefix = "word";
            break;
        case R_R11B: case R_R14B: case R_R15B:
            *size_prefix = "byte";
            break;
        default:
            *size_prefix = "qword";
            break;
    }
    return true;
}

/* Map to the corresponding size of the physical scratch register R11 */
static enum reg_enum get_physical_scratch(enum reg_enum size_ref_reg)
{
    switch (size_ref_reg) {
        case R_R11: case R_R14: case R_R15:
        case R_RAX: case R_RBX: case R_RCX: case R_RDX:
        case R_RSI: case R_RDI: case R_RBP: case R_RSP:
        case R_R8:  case R_R9:  case R_R10: case R_R12: case R_R13:
            return R_R11;
        case R_R11D: case R_R14D: case R_R15D:
        case R_EAX: case R_EBX: case R_ECX: case R_EDX:
        case R_ESI: case R_EDI: case R_EBP: case R_ESP:
        case R_R8D:  case R_R9D:  case R_R10D: case R_R12D: case R_R13D:
            return R_R11D;
        case R_R11W: case R_R14W: case R_R15W:
        case R_AX: case R_BX: case R_CX: case R_DX:
        case R_SI: case R_DI: case R_BP: case R_SP:
        case R_R8W:  case R_R9W:  case R_R10W: case R_R12W: case R_R13W:
            return R_R11W;
        case R_R11B: case R_R14B: case R_R15B:
        case R_AL: case R_BL: case R_CL: case R_DL:
        case R_SIL: case R_DIL: case R_BPL: case R_SPL:
        case R_R8B:  case R_R9B:  case R_R10B: case R_R12B: case R_R13B:
            return R_R11B;
        default:
            return R_R11;
    }
}

/* Check if an instruction needs register virtualization */
static bool needs_reg_virtualization(insn *ins)
{
    for (int i = 0; i < ins->operands; i++) {
        operand *op = &ins->oprs[i];

        /* 1. Register Operands: r11, r14, r15 all need virtualization */
        if (is_op_type(*op, REGISTER)) {
            enum reg_enum parent = get_64bit_parent(op->basereg);
            if (parent == LFI_SCRATCH_REG || parent == LFI_SBX_BASE || parent == LFI_CTXREG) {
                return true;
            }
        }

        /* 2. Check Memory Operands: r11, r14, and r15 need virtualization in memory operands. */
        if (is_op_type(*op, MEMORY)) {
            if (op->basereg != R_none) {
                enum reg_enum parent = get_64bit_parent(op->basereg);
                if (parent == LFI_SCRATCH_REG || parent == LFI_SBX_BASE || parent == LFI_CTXREG) {
                    return true;
                }
            }
            if (op->indexreg != R_none) {
                enum reg_enum parent = get_64bit_parent(op->indexreg);
                if (parent == LFI_SCRATCH_REG || parent == LFI_SBX_BASE || parent == LFI_CTXREG) {
                    return true;
                }
            }
        }
    }
    return false;
}


/* Map a 64-bit base register to match the size of a reference register */
static enum reg_enum get_sized_reg(enum reg_enum base_reg, enum reg_enum size_ref_reg)
{
    int size = 8;
    switch (size_ref_reg) {
        case R_EAX: case R_EBX: case R_ECX: case R_EDX:
        case R_ESI: case R_EDI: case R_EBP: case R_ESP:
        case R_R8D: case R_R9D: case R_R10D: case R_R11D:
        case R_R12D: case R_R13D: case R_R14D: case R_R15D:
            size = 4;
            break;
        case R_AX: case R_BX: case R_CX: case R_DX:
        case R_SI: case R_DI: case R_BP: case R_SP:
        case R_R8W: case R_R9W: case R_R10W: case R_R11W:
        case R_R12W: case R_R13W: case R_R14W: case R_R15W:
            size = 2;
            break;
        case R_AL: case R_BL: case R_CL: case R_DL:
        case R_SIL: case R_DIL: case R_BPL: case R_SPL:
        case R_R8B: case R_R9B: case R_R10B: case R_R11B:
        case R_R12B: case R_R13B: case R_R14B: case R_R15B:
        case R_AH: case R_BH: case R_CH: case R_DH:
            size = 1;
            break;
        default:
            break;
    }

    switch (base_reg) {
        case R_RAX:
            if (size == 4) return R_EAX;
            if (size == 2) return R_AX;
            if (size == 1) return R_AL;
            return R_RAX;
        case R_RBX:
            if (size == 4) return R_EBX;
            if (size == 2) return R_BX;
            if (size == 1) return R_BL;
            return R_RBX;
        case R_RCX:
            if (size == 4) return R_ECX;
            if (size == 2) return R_CX;
            if (size == 1) return R_CL;
            return R_RCX;
        case R_RDX:
            if (size == 4) return R_EDX;
            if (size == 2) return R_DX;
            if (size == 1) return R_DL;
            return R_RDX;
        case R_RSI:
            if (size == 4) return R_ESI;
            if (size == 2) return R_SI;
            if (size == 1) return R_SIL;
            return R_RSI;
        case R_RDI:
            if (size == 4) return R_EDI;
            if (size == 2) return R_DI;
            if (size == 1) return R_DIL;
            return R_RDI;
        case R_RBP:
            if (size == 4) return R_EBP;
            if (size == 2) return R_BP;
            if (size == 1) return R_BPL;
            return R_RBP;
        case R_R8:
            if (size == 4) return R_R8D;
            if (size == 2) return R_R8W;
            if (size == 1) return R_R8B;
            return R_R8;
        case R_R9:
            if (size == 4) return R_R9D;
            if (size == 2) return R_R9W;
            if (size == 1) return R_R9B;
            return R_R9;
        case R_R10:
            if (size == 4) return R_R10D;
            if (size == 2) return R_R10W;
            if (size == 1) return R_R10B;
            return R_R10;
        case R_R12:
            if (size == 4) return R_R12D;
            if (size == 2) return R_R12W;
            if (size == 1) return R_R12B;
            return R_R12;
        case R_R13:
            if (size == 4) return R_R13D;
            if (size == 2) return R_R13W;
            if (size == 1) return R_R13B;
            return R_R13;
        default:
            return base_reg;
    }
}

/* Find a safe GPR that is NOT used in the current instruction */
static enum reg_enum find_unused_gpr(insn *ins)
{
    bool used[REG_ENUM_LIMIT] = {false};

    for (int i = 0; i < ins->operands; i++) {
        operand *op = &ins->oprs[i];
        if (is_op_type(*op, REGISTER)) {
            used[get_64bit_parent(op->basereg)] = true;
        }
        if (is_op_type(*op, MEMORY)) {
            if (op->basereg != R_none) {
                used[get_64bit_parent(op->basereg)] = true;
            }
            if (op->indexreg != R_none) {
                used[get_64bit_parent(op->indexreg)] = true;
            }
        }
    }

    static const enum reg_enum safe_gprs[] = {
        R_RAX, R_RBX, R_RCX, R_RDX, R_RSI, R_RDI, R_RBP, R_R8, R_R9, R_R10, R_R12, R_R13
    };

    for (size_t i = 0; i < sizeof(safe_gprs)/sizeof(safe_gprs[0]); i++) {
        if (!used[safe_gprs[i]]) {
            return safe_gprs[i];
        }
    }

    return R_none;
}

/* Prepare register virtualization by generating loads/stores and rewriting to physical registers */
static void prepare_virtual_regs(insn *ins, insn *pre_load, int *pre_count, insn *post_store, int *post_count)
{
    int bits = ins->bits;
    int pre_idx = 0;
    int post_idx = 0;

    bool preloaded_scratch = false;
    int scratch_offset = 0;

    bool use_spill = false;
    enum reg_enum spill_reg = R_none;
    insn orig_ins = *ins;

restart:
    *ins = orig_ins;
    pre_idx = 0;
    post_idx = 0;
    preloaded_scratch = false;

    if (use_spill && spill_reg == R_none) {
        spill_reg = find_unused_gpr(ins);
        if (spill_reg == R_none) {
            lfi_report_error(true, "LFI: failed to find unused GPR for stack spilling");
            return;
        }
        /* Spill spill_reg to context slot 24 */
        parse_line_fmt(&(pre_load[pre_idx++]), bits, "mov [%s + 24], %s", regName(LFI_CTXREG), regName(spill_reg));
    }

    /* 1. Pre-load virtual r11/r14/r15 into physical scratch r11 (and spill_reg if needed) for memory operands,
     * and rewrite the memory operands to use physical registers. */
    for (int i = 0; i < ins->operands; i++) {
        operand *op = &ins->oprs[i];
        if (is_op_type(*op, MEMORY)) {
            if (op->basereg != R_none) {
                enum reg_enum parent = get_64bit_parent(op->basereg);
                if (parent == LFI_SCRATCH_REG || parent == LFI_SBX_BASE || parent == LFI_CTXREG) {
                    if (!preloaded_scratch) {
                        const char *dummy_size;
                        get_virtual_reg_info(op->basereg, &scratch_offset, &dummy_size);
                        /* Generate pre-load: mov r11, [r15 + scratch_offset] */
                        parse_line_fmt(&(pre_load[pre_idx++]), bits, "mov r11, [%s + %d]", regName(LFI_CTXREG), scratch_offset);
                        preloaded_scratch = true;
                        op->basereg = R_R11;
                    } else {
                        int current_offset;
                        const char *dummy_size;
                        get_virtual_reg_info(op->basereg, &current_offset, &dummy_size);
                        if (current_offset != scratch_offset) {
                            if (use_spill) {
                                enum reg_enum sized_spill = get_sized_reg(spill_reg, op->basereg);
                                parse_line_fmt(&(pre_load[pre_idx++]), bits, "mov %s, [%s + %d]",
                                               regName(sized_spill), regName(LFI_CTXREG), current_offset);
                                op->basereg = sized_spill;
                            } else {
                                use_spill = true;
                                goto restart;
                            }
                        } else {
                            op->basereg = R_R11;
                        }
                    }
                }
            }
            if (op->indexreg != R_none) {
                enum reg_enum parent = get_64bit_parent(op->indexreg);
                if (parent == LFI_SCRATCH_REG || parent == LFI_SBX_BASE || parent == LFI_CTXREG) {
                    if (!preloaded_scratch) {
                        const char *dummy_size;
                        get_virtual_reg_info(op->indexreg, &scratch_offset, &dummy_size);
                        parse_line_fmt(&(pre_load[pre_idx++]), bits, "mov r11, [%s + %d]", regName(LFI_CTXREG), scratch_offset);
                        preloaded_scratch = true;
                        op->indexreg = R_R11;
                    } else {
                        int current_offset;
                        const char *dummy_size;
                        get_virtual_reg_info(op->indexreg, &current_offset, &dummy_size);
                        if (current_offset != scratch_offset) {
                            if (use_spill) {
                                enum reg_enum sized_spill = get_sized_reg(spill_reg, op->indexreg);
                                parse_line_fmt(&(pre_load[pre_idx++]), bits, "mov %s, [%s + %d]",
                                               regName(sized_spill), regName(LFI_CTXREG), current_offset);
                                op->indexreg = sized_spill;
                            } else {
                                use_spill = true;
                                goto restart;
                            }
                        } else {
                            op->indexreg = R_R11;
                        }
                    }
                }
            }
        }
    }

    /* 2. Count register operands needing virtualization */
    int virtualized_ops_count = 0;
    int virtualized_op_indices[3];
    for (int i = 0; i < ins->operands; i++) {
        if (is_op_type(ins->oprs[i], REGISTER)) {
            enum reg_enum parent = get_64bit_parent(ins->oprs[i].basereg);
            if (parent == LFI_SCRATCH_REG || parent == LFI_SBX_BASE || parent == LFI_CTXREG) {
                virtualized_op_indices[virtualized_ops_count++] = i;
            }
        }
    }

    /* Case A: Virtual-to-Virtual operation (both operands are virtualized) */
    if (virtualized_ops_count == 2) {
        int dest_idx = virtualized_op_indices[0];
        int src_idx = virtualized_op_indices[1];
        enum reg_enum dest_reg = ins->oprs[dest_idx].basereg;
        enum reg_enum src_reg = ins->oprs[src_idx].basereg;

        int src_offset, dest_offset;
        const char *src_size, *dest_size;
        get_virtual_reg_info(src_reg, &src_offset, &src_size);
        get_virtual_reg_info(dest_reg, &dest_offset, &dest_size);

        enum reg_enum phys_scratch_dest = get_physical_scratch(dest_reg);
        bool dest_is_read = (ins->opcode != I_MOV && ins->opcode != I_MOVZX && ins->opcode != I_MOVSX && ins->opcode != I_LEA);

        if (preloaded_scratch) {
            if (!use_spill) {
                use_spill = true;
                goto restart;
            }
        }

        enum reg_enum dest_scratch = use_spill ? get_sized_reg(spill_reg, dest_reg) : phys_scratch_dest;
        const char *dest_scratch_name = regName(dest_scratch);

        /* Step 1: If destination is read, load it into scratch */
        if (dest_is_read) {
            parse_line_fmt(&(pre_load[pre_idx++]), bits, "mov %s, [%s + %d]",
                           dest_scratch_name, regName(LFI_CTXREG), dest_offset);
        }

        /* Step 2: Rewrite the instruction in-place:
         * dest becomes scratch.
         * src becomes memory slot [r15 + src_offset].
         */
        ins->oprs[dest_idx].basereg = dest_scratch;

        ins->oprs[src_idx].type = MEMORY | (ins->oprs[src_idx].type & ~REGISTER);
        ins->oprs[src_idx].basereg = LFI_CTXREG;
        ins->oprs[src_idx].indexreg = R_none;
        ins->oprs[src_idx].offset = src_offset;

        /* Step 3: Save scratch back to virtual destination slot */
        parse_line_fmt(&(post_store[post_idx++]), bits, "mov [%s + %d], %s",
                       regName(LFI_CTXREG), dest_offset, dest_scratch_name);
    }
    /* Case B: Standard operation (exactly 1 virtualized register operand) */
    else if (virtualized_ops_count == 1) {
        int v_idx = virtualized_op_indices[0];
        operand *v_op = &ins->oprs[v_idx];
        enum reg_enum v_reg = v_op->basereg;

        int v_offset;
        const char *v_size_prefix;
        get_virtual_reg_info(v_reg, &v_offset, &v_size_prefix);

        enum reg_enum phys_scratch = get_physical_scratch(v_reg);
        bool is_write = (v_idx == 0 && ins->opcode != I_PUSH && ins->opcode != I_CMP && ins->opcode != I_TEST);
        bool is_read = (v_idx == 1) || (ins->opcode == I_PUSH) || (v_idx == 0 && ins->opcode != I_MOV && ins->opcode != I_MOVZX && ins->opcode != I_MOVSX && ins->opcode != I_PMOVMSKB && ins->opcode != I_POP && ins->opcode != I_LEA);

        if (preloaded_scratch && get_64bit_parent(phys_scratch) == LFI_SCRATCH_REG) {
            if (scratch_offset == v_offset) {
                is_read = false; /* Already loaded */
            } else if (is_read) {
                if (!use_spill) {
                    use_spill = true;
                    goto restart;
                }
            }
        }

        enum reg_enum scratch = (use_spill && preloaded_scratch && scratch_offset != v_offset) ?
                                get_sized_reg(spill_reg, v_reg) : phys_scratch;
        const char *scratch_name = regName(scratch);

        /* Step 1: If read, load virtual register into scratch */
        if (is_read) {
            parse_line_fmt(&(pre_load[pre_idx++]), bits, "mov %s, [%s + %d]", scratch_name, regName(LFI_CTXREG), v_offset);
        }

        /* Step 2: Rewrite the instruction operand in-place to use scratch */
        v_op->basereg = scratch;

        /* Step 3: If written, save scratch back to virtual register slot */
        if (is_write) {
            parse_line_fmt(&(post_store[post_idx++]), bits, "mov [%s + %d], %s", regName(LFI_CTXREG), v_offset, scratch_name);
        }
    }

    if (use_spill) {
        /* Restore spill_reg from context slot 24 */
        parse_line_fmt(&(post_store[post_idx++]), bits, "mov %s, [%s + 24]", regName(spill_reg), regName(LFI_CTXREG));
    }

    *pre_count = pre_idx;
    *post_count = post_idx;
}

/*
 * Helper to dispatch an instruction to its corresponding LFI expansion module.
 */
static void dispatch_expand(insn *ins, int *count, insn *ret, bundle_lock_mask_t *bundle_lock_mask)
{
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
        if (uses_gs_invalidly(ins)) {
            lfi_report_error(true, "LFI: invalid use of %%gs segment register");
        }
        expand_load_store(ins, count, ret, bundle_lock_mask);
    }
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

    /* Bypass data directives (db, dw, dd, dq, resb, resw, incbin, etc.)
     * as they represent raw data, not executable code, and their operand arrays
     * are uninitialized, which can trigger false positive memory sandboxing matches. */
    if (opcode_is_db(ins->opcode) || opcode_is_resb(ins->opcode) || ins->opcode == I_INCBIN) {
        *count = 1;
        *bundle_lock_mask = 0b0000;
        ret[0] = *ins;
        ret[0].times = 1;
        return;
    }

    /* Relax all short jumps to near/auto jumps. Since LFI sandboxing expands instructions
     * (inserting bundle alignment, pre-loads, and address calculations), short jumps (1-byte offset)
     * can easily exceed their 127-byte range. Clearing the SHORT flag lets NASM's optimizer
     * choose the best jump size automatically, preventing out-of-range assembly errors. */
    for (int i = 0; i < ins->operands; i++) {
        ins->oprs[i].type &= ~SHORT;
    }

    /* =========================================================================
     * PATH 1: Normal Path (No Register Virtualization)
     * ========================================================================= */
    if (!needs_reg_virtualization(ins)) {
        /* 1. Safety Checks */
        if (modifies_reserved_reg(ins, LFI_SBX_BASE)) {
            lfi_report_error(true, "LFI: illegal modification of reserved LFI register %%r14");
        }
        if (modifies_reserved_reg(ins, LFI_SCRATCH_REG)) {
            lfi_report_error(true, "LFI: illegal modification of reserved LFI register %%r11");
        }
        if (uses_r15_invalidly(ins)) {
            lfi_report_error(true, "LFI: illegal use of reserved LFI context register %%r15");
        }

        /* 2. Direct Dispatch */
        dispatch_expand(ins, count, ret, bundle_lock_mask);
        return;
    }

    /* =========================================================================
     * PATH 2: Register Virtualization Path
     * ========================================================================= */
    insn pre_load[8];
    int pre_count = 0;
    insn post_store[8];
    int post_count = 0;
    insn working_ins = *ins;

    /* 1. Generate pre-load/post-store and rewrite working_ins */
    prepare_virtual_regs(&working_ins, pre_load, &pre_count, post_store, &post_count);

    /* 2. Dispatch the rewritten instruction to a temporary middle array */
    insn middle_insns[16];
    int middle_count = 0;
    bundle_lock_mask_t dummy_mask = 0; // Ignored because we lock the whole sequence

    dispatch_expand(&working_ins, &middle_count, middle_insns, &dummy_mask);

    /* 4. Combine pre_load + middle_insns + post_store into ret */
    int out_idx = 0;
    for (int i = 0; i < pre_count; i++) {
        ret[out_idx] = pre_load[i];
        ret[out_idx].times = 1;
        out_idx++;
    }
    for (int i = 0; i < middle_count; i++) {
        ret[out_idx] = middle_insns[i];
        ret[out_idx].times = 1;
        out_idx++;
    }
    for (int i = 0; i < post_count; i++) {
        ret[out_idx] = post_store[i];
        ret[out_idx].times = 1;
        out_idx++;
    }

    *count = out_idx;

    /* 5. Bundle-lock the entire expanded sequence */
    *bundle_lock_mask = (1 << out_idx) - 2;
}

/* =========================================================================
 * 4. Layout, Padding, and Alignment Calculations
 * ========================================================================= */

/* Calculate the padding required to avoid straddling 32-byte boundaries */
static int get_bundle_padsize(int64_t offset, int minSpaceInCurrBlock, int64_t rawInstrSize, bool align_to_end)
{
    if (ofmt == &of_elf64) {
        if (rawInstrSize >= 32) {
            lfi_report_error(false, "LFI: Instruction size greater than or equal to 32");
            return 0;
        }

        if (minSpaceInCurrBlock > 32) {
            lfi_report_error(false, "LFI: More than 32 bytes of instructions that can't be separated");
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
                init_insn(&noop_ins);
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

/* Low-level NOP emitter for LFI label alignment */
void lfi_emit_nops(int32_t segment, int count)
{
    if (count <= 0)
        return;

    /* 1. In the final pass, write the actual NOP bytes to the output format */
    if (pass_final()) {
        struct out_data odata;
        memset(&odata, 0, sizeof(odata));
        odata.loc = location; /* Write to current unaligned offset */
        odata.loc.segment = segment; /* Explicitly use the segment being defined */
        odata.type = OUT_RAWDATA;
        odata.size = count;

        /* Create a buffer of NOPs */
        uint8_t *nop_buf = nasm_malloc(count);
        memset(nop_buf, 0x90, count);
        odata.data = nop_buf;

        odata.tsegment = NO_SEG;
        odata.twrt = NO_SEG;

        /* Legacy translation required by NASM backends */
        odata.legacy.data = odata.data;
        odata.legacy.type = odata.type;
        odata.legacy.size = odata.size;
        odata.legacy.tsegment = odata.tsegment;
        odata.legacy.twrt = odata.twrt;

        ofmt->output(&odata);
        nasm_free(nop_buf);
    }

    /* 2. Advance the assembler's global location counter */
    location.offset += count;
}

/* Global array to track which segment IDs contain executable code.
 * NASM segment IDs are positive even integers, so 65536 covers IDs up to 131072. */
#define LFI_MAX_SECTIONS 65536
static bool lfi_is_code_seg[LFI_MAX_SECTIONS];

static const char *next_token(const char *src, char *dest, size_t dest_len)
{
    size_t len = 0;

    /* Skip leading separators */
    while (*src == ' ' || *src == '\t' || *src == ',') {
        src++;
    }
    if (!*src) {
        dest[0] = '\0';
        return NULL;
    }

    /* Copy token characters */
    while (*src && *src != ' ' && *src != '\t' && *src != ',') {
        if (len < dest_len - 1) {
            dest[len++] = *src;
        }
        src++;
    }
    dest[len] = '\0';

    return src;
}

void lfi_register_section(int32_t seg, const char *value)
{
    if (seg <= 0 || seg >= LFI_MAX_SECTIONS)
        return;

    if (!value) {
        /* Default section is always code (.text) */
        lfi_is_code_seg[seg] = true;
        return;
    }

    char token[256];
    const char *p = value;

    /* 1. First token is the Section Name */
    p = next_token(p, token, sizeof(token));
    if (!p) return;

    /* Check if section name indicates code */
    if (strcasecmp(token, ".text") == 0 ||
        strcasecmp(token, ".gtext") == 0 ||
        strncasecmp(token, ".text.", 6) == 0 ||   /* support sub-sections like .text.startup */
        strncasecmp(token, ".gtext.", 7) == 0) {
        lfi_is_code_seg[seg] = true;
        return;
    }

    /* 2. Scan remaining tokens for section attributes */
    while ((p = next_token(p, token, sizeof(token))) != NULL) {
        if (strcasecmp(token, "exec") == 0 || strcasecmp(token, "code") == 0) {
            lfi_is_code_seg[seg] = true;
            return;
        }
    }
}

bool lfi_is_code_segment(int32_t seg)
{
    if (seg <= 0 || seg >= LFI_MAX_SECTIONS)
        return false;
    return lfi_is_code_seg[seg];
}
