; RUN: nasm -lfi %s
; CHECK-ALIGN: .text 32
; CHECK-ALIGN: .rodata 8
; CHECK-ALIGN: .note.noncode 1

bits 64

; 1. A code segment - must align to 32
SECTION .text

_start:
    nop

; 2. A data segment - must NOT align to 32, should keep its natural or requested alignment
SECTION .rodata align=8
    dq 1

; 3. A non-executable note segment containing "noexec" in its declaration string
;    This must NOT be misclassified as code, and must NOT align to 32.
SECTION .note.noncode alloc noexec nowrite align=1
    db 1
