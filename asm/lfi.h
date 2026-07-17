/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright 2026 The NASM Authors - All Rights Reserved */

#ifndef NASM_LFI_H
#define NASM_LFI_H

#include "nasm.h"

extern bool lfi_mode;
extern bool lfi_evaluating_direct_branch;
extern bool lfi_realloc_enabled;
extern bool lfi_verbose_realloc;
extern int lfi_realloc_max_targets;

enum lfi_pseudo_reg {
    R_LFI_SPILL_SLOT_1 = EXPR_REG_START + 500, /* Target 1 Context Scratch Spill Slot 24 */
    R_LFI_SPILL_SLOT_2,                         /* Target 2 Context Scratch Spill Slot 32 */
    R_LFI_SPILL_SLOT_3,                         /* Target 3 Context Scratch Spill Slot 0 */
    R_LFI_VIRT_R11,                             /* Virtual R11 Context Slot 40 */
    R_LFI_VIRT_R14,                             /* Virtual R14 Context Slot 48 */
    R_LFI_VIRT_R15                              /* Virtual R15 Context Slot 56 */
};

void lfi_process_insn(insn *ins);
void lfi_emit_nops(int32_t segment, int count);
void lfi_register_section(int32_t seg, const char *value);
bool lfi_is_code_segment(int32_t seg);
int64_t lfi_handle_label_teardown(const char *label, int32_t segment, int64_t offset);
void lfi_handle_label_setup(const char *label, int32_t segment);

#endif /* NASM_LFI_H */

