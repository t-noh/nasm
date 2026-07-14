/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright 2026 The NASM Authors - All Rights Reserved */

#ifndef NASM_LFI_H
#define NASM_LFI_H

#include "nasm.h"

extern bool lfi_mode;
extern bool lfi_evaluating_direct_branch;

void lfi_process_insn(insn *ins);
void lfi_emit_nops(int32_t segment, int count);
void lfi_register_section(int32_t seg, const char *value);
bool lfi_is_code_segment(int32_t seg);

#endif /* NASM_LFI_H */
