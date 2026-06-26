; RUN: nasm -lfi %s
bits 64
section .text

global _start
_start:
    nop

    ; =========================================================================
    ; LFI LABEL ALIGNMENT POLICY DEMONSTRATION:
    ; 1. All user-defined global labels (functions) MUST be aligned to 32 bytes
    ;    to satisfy the SFI/LFI control-flow sandboxing contract.
    ; 2. All local labels (starting with a single dot '.') and internal macro/loop
    ;    labels (starting with double dot '..') MUST NOT be aligned, preventing
    ;    code size bloat and compilation phase errors.
    ; =========================================================================

global_label:
    nop
.local_label:
    nop
..@macro_label:
    nop

    ; =========================================================================
    ; Case 1: User Local Label (Single Dot)
    ; Must NOT be aligned. The distance from global_label must be exactly 1 byte.
    ; =========================================================================
    mov rax, (.local_label - global_label)
    ; CHECK: mov eax,0x1

    ; =========================================================================
    ; Case 2: Internal/Macro Label (Double Dot)
    ; Must NOT be aligned. The distance from .local_label must be exactly 1 byte.
    ; =========================================================================
    mov rbx, (..@macro_label - .local_label)
    ; CHECK: mov ebx,0x1

    ; =========================================================================
    ; Case 3: Global Label
    ; MUST be aligned to 32 bytes.
    ; =========================================================================
    ; Trigger some instructions to push the offset away from 32-byte boundary
    mov rdx, rcx
    add rdx, 8

global_target:
    nop
    ; Load the offset of the global target. Since it is aligned, it should be 32!
    ; (The preceding global_label was at 32-byte boundary, so global_target aligns to +32).
    mov rcx, (global_target - global_label)
    ; CHECK: mov ecx,0x20
