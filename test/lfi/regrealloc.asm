; RUN: nasm -lfi %s
bits 64
section .text
global _start

_start:
    ; =========================================================================
    ; Test 1: Single target (r15 x 3) -> Proxied to r13, Spill Slot 1 ([r15 + 0x18])
    ; Exit Teardown MUST be emitted BEFORE control flow instruction (jne)!
    ; =========================================================================
.L1:
    add r15, 1
    mov rcx, r15
    imul rcx, r15
    jne .L1
    ; CHECK:      mov QWORD PTR [r15+0x18],r13
    ; CHECK-NEXT: mov r13,QWORD PTR [r15+0x38]
    ; CHECK-NEXT: add r13,0x1
    ; CHECK-NEXT: mov rcx,r13
    ; CHECK-NEXT: imul rcx,r13
    ; CHECK-NEXT: mov QWORD PTR [r15+0x38],r13
    ; CHECK-NEXT: mov r13,QWORD PTR [r15+0x18]
    ; CHECK-NEXT: jne 8

    ; =========================================================================
    ; Test 2: Dual targets (r11 x 3, r14 x 3) -> Dual Spill Slots!
    ; Target 1 (r11) -> Proxy r13, Spill Slot 1 ([r15 + 0x18])
    ; Target 2 (r14) -> Proxy r12, Spill Slot 2 ([r15 + 0x10])
    ; =========================================================================
.L2:
    add r11, 2
    mov rdx, r11
    imul rdx, r11
    add r14, 4
    mov rsi, r14
    imul rsi, r14
    jne .L2
    ; CHECK:      mov QWORD PTR [r15+0x18],r13
    ; CHECK-NEXT: mov r13,QWORD PTR [r15+0x28]
    ; CHECK-NEXT: mov QWORD PTR [r15+0x10],r12
    ; CHECK-NEXT: mov r12,QWORD PTR [r15+0x30]
    ; CHECK-NEXT: add r13,0x2
    ; CHECK-NEXT: mov rdx,r13
    ; CHECK-NEXT: imul rdx,r13
    ; CHECK-NEXT: add r12,0x4
    ; CHECK:      mov rsi,r12
    ; CHECK-NEXT: imul rsi,r12
    ; CHECK-NEXT: mov QWORD PTR [r15+0x28],r13
    ; CHECK-NEXT: mov r13,QWORD PTR [r15+0x18]
    ; CHECK-NEXT: mov QWORD PTR [r15+0x30],r12
    ; CHECK-NEXT: mov r12,QWORD PTR [r15+0x10]
    ; CHECK-NEXT: jne 1d

    ; =========================================================================
    ; Test 3: Triple targets (r11 x 4, r14 x 3, r15 x 2) -> Max 2 Swaps Cap!
    ; Target 1 (r11) -> Proxy r13, Spill Slot 1 ([r15 + 0x18])
    ; Target 2 (r14) -> Proxy r12, Spill Slot 2 ([r15 + 0x10])
    ; Target 3 (r15) -> Capped (no proxy), stays baseline virtualized!
    ; =========================================================================
.L3:
    add r11, 1
    mov rax, r11
    sub rax, r11
    imul rax, r11
    add r14, 1
    mov rbx, r14
    imul rbx, r14
    add r15, 1
    mov rdi, r15
    jne .L3
    ; CHECK:      mov QWORD PTR [r15+0x18],r13
    ; CHECK:      mov r13,QWORD PTR [r15+0x28]
    ; CHECK-NEXT: mov QWORD PTR [r15+0x10],r12
    ; CHECK-NEXT: mov r12,QWORD PTR [r15+0x30]
    ; CHECK-NEXT: add r13,0x1
    ; CHECK-NEXT: mov rax,r13
    ; CHECK-NEXT: sub rax,r13
    ; CHECK-NEXT: imul rax,r13
    ; CHECK-NEXT: add r12,0x1
    ; CHECK:      mov rbx,r12
    ; CHECK-NEXT: imul rbx,r12
    ; CHECK-NEXT: mov r11,QWORD PTR [r15+0x38]
    ; CHECK-NEXT: add r11,0x1
    ; CHECK-NEXT: mov QWORD PTR [r15+0x38],r11
    ; CHECK-NEXT: mov r11,QWORD PTR [r15+0x38]
    ; CHECK-NEXT: mov rdi,r11
    ; CHECK:      mov QWORD PTR [r15+0x28],r13
    ; CHECK:      mov r13,QWORD PTR [r15+0x18]
    ; CHECK-NEXT: mov QWORD PTR [r15+0x30],r12
    ; CHECK-NEXT: mov r12,QWORD PTR [r15+0x10]
    ; CHECK-NEXT: jne 59

    ; =========================================================================
    ; Test 4: Conditional branch teardown ordering (jge)
    ; Target 1 (r11) & Target 2 (r14) proxied. Teardown MUST precede jge!
    ; =========================================================================
.L5:
    not r11
    sub r14b, cl
    not r11
    sub r14b, dl
    jge .L5
    ; CHECK:      mov QWORD PTR [r15+0x28],r13
    ; CHECK:      mov r13,QWORD PTR [r15+0x18]
    ; CHECK-NEXT: mov QWORD PTR [r15+0x30],r12
    ; CHECK-NEXT: mov r12,QWORD PTR [r15+0x10]
    ; CHECK-NEXT: jge ae

    ; =========================================================================
    ; Test 5: Threshold safeguard (r11 x 1 < min 2 refs) -> Realloc Bypassed
    ; =========================================================================
.L4:
    add r11, 1
    ret
    ; CHECK:      mov r11,QWORD PTR [r15+0x28]
    ; CHECK-NEXT: add r11,0x1
    ; CHECK-NEXT: mov QWORD PTR [r15+0x28],r11
    ; CHECK:      pop r11
