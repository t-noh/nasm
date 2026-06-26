; RUN: nasm -lfi %s
bits 64
section .text

global _start
_start:
    ; 1. Define raw bytes resembling a NOP (0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00)
    ; This must be emitted exactly as-is without any LFI sandboxing/rewriting.
    times (10 / 8) db 0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00
    ; CHECK: nop DWORD PTR [rax+rax*1+0x0]

    ; 2. Define other data directives (dw, dd, dq)
    dw 0x9090
    ; CHECK: nop
    ; CHECK-NEXT: nop

    dd 0x90909090
    ; CHECK: nop
    ; CHECK-NEXT: nop
    ; CHECK-NEXT: nop
    ; CHECK-NEXT: nop

    dq 0x9090909090909090
    ; CHECK: nop
    ; CHECK-NEXT: nop
    ; CHECK-NEXT: nop
    ; CHECK-NEXT: nop
    ; CHECK-NEXT: nop
    ; CHECK-NEXT: nop
    ; CHECK-NEXT: nop
    ; CHECK-NEXT: nop
