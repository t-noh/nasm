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
    ; 2. Internal macro/loop labels (starting with double dot '..') MUST NOT be aligned,
    ;    preventing code size bloat and compilation phase errors.
    ; 3. User local labels (starting with a single dot '.') MUST be aligned because they
    ;    might be targets of indirect jumps (e.g. jump tables).
    ; =========================================================================

global_label:
    nop
.local_label:
    nop
..@macro_label:
    nop
.local@macro:
    nop
.Ltmp_user:
    nop


    ; =========================================================================
    ; Case 1: User Local Label (Single Dot)
    ; MUST be aligned to 32 bytes because they might be targets of indirect jumps (e.g. jump tables).
    ; =========================================================================
    mov rax, (.local_label - global_label)
    ; CHECK: mov eax,0x20

    ; =========================================================================
    ; Case 2: Internal/Macro Label (Double Dot)
    ; Must NOT be aligned. The distance from .local_label must be exactly 1 byte.
    ; =========================================================================
    mov rbx, (..@macro_label - .local_label)
    ; CHECK: mov ebx,0x1

    ; =========================================================================
    ; Case 4: Label containing '@' (macro local)
    ; Must NOT be aligned. The distance from .local_label to .local@macro must be 2 bytes.
    ; =========================================================================
    mov r8, (.local@macro - .local_label)
    ; CHECK: mov r8d,0x2

    ; =========================================================================
    ; Case 5: Label starting with '.Ltmp' (LFI temp label)
    ; Must NOT be aligned. The distance from .local@macro to .Ltmp_user must be 1 byte.
    ; =========================================================================
    mov r9, (.Ltmp_user - .local@macro)
    ; CHECK: mov r9d,0x1


    ; =========================================================================
    ; Case 3: Global Label
    ; MUST be aligned to 32 bytes.
    ; =========================================================================
    ; Trigger some instructions to push the offset away from 32-byte boundary
    mov rdx, rcx
    add rdx, 8

    global_target:
    nop
    ; Load the offset of the global target. Since it is aligned, it should be 96 (0x60)!
    ; (Because .local_label was also aligned, and we added macro-local/temp cases, global_target aligns to 128).
    mov rcx, (global_target - global_label)
    ; CHECK: mov ecx,0x60
