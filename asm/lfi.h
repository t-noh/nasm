/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright 2026 The NASM Authors - All Rights Reserved */

#ifndef NASM_LFI_H
#define NASM_LFI_H

#include "nasm.h"

extern bool lfi_mode;

void lfi_process_insn(insn *ins);
void lfi_emit_nops(int32_t segment, int count);

#endif /* NASM_LFI_H */
