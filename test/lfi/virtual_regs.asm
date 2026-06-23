bits 64
section .text
global _start

_start:
    ; =========================================================================
    ; 1. Virtual R11 Rewriting Tests ([r15 + 40] -> [r15 + 0x28])
    ; =========================================================================
    mov r11, rax
    ; CHECK:      mov r11,rax
    ; CHECK-NEXT: mov qword ptr [r15+0x28],r11

    mov rax, r11
    ; CHECK:      mov r11,qword ptr [r15+0x28]
    ; CHECK-NEXT: mov rax,r11

    add r11, 16
    ; CHECK:      mov r11,qword ptr [r15+0x28]
    ; CHECK-NEXT: add r11,0x10
    ; CHECK-NEXT: mov qword ptr [r15+0x28],r11

    ; Memory access using virtual r11 as base - must be sandboxed inline with gs:!
    mov rax, [r11]
    ; CHECK:      mov r11,qword ptr [r15+0x28]
    ; CHECK-NEXT: mov rax,qword ptr gs:[r11d]

    ; =========================================================================
    ; 2. Virtual R14 Rewriting Tests ([r15 + 48] -> [r15 + 0x30])
    ; =========================================================================
    mov r14, rbx
    ; CHECK:      mov r11,rbx
    ; CHECK:      mov qword ptr [r15+0x30],r11

    mov rbx, r14
    ; CHECK:      mov r11,qword ptr [r15+0x30]
    ; CHECK-NEXT: mov rbx,r11

    sub r14, 8
    ; CHECK:      mov r11,qword ptr [r15+0x30]
    ; CHECK-NEXT: sub r11,0x8
    ; CHECK-NEXT: mov qword ptr [r15+0x30],r11

    ; =========================================================================
    ; 3. Virtual R15 Rewriting Tests ([r15 + 56] -> [r15 + 0x38])
    ; =========================================================================
    mov r15, rcx
    ; CHECK:      mov r11,rcx
    ; CHECK-NEXT: mov qword ptr [r15+0x38],r11

    mov rcx, r15
    ; CHECK:      mov r11,qword ptr [r15+0x38]
    ; CHECK-NEXT: mov rcx,r11

    ; GPR access to [r15 + 32] (virtualized because r15 is used as a GPR in this file!)
    mov rax, [r15 + 32]
    ; CHECK:      mov r11,qword ptr [r15+0x38]
    ; CHECK-NEXT: mov rax,qword ptr gs:[r11d+0x20]

    ; Push/Pop virtualization using memory operands
    push r15
    ; CHECK:      mov r11,qword ptr [r15+0x38]
    ; CHECK-NEXT: push r11

    pop r15
    ; CHECK:      pop r11
    ; CHECK-NEXT: mov qword ptr [r15+0x38],r11
