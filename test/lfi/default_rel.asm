; RUN: nasm -lfi %s
bits 64
default rel

extern foo

_start:
    ; 1. Implicit RIP-relative loads/stores under default rel
    mov rax, [foo]
    ; CHECK: mov rax,qword ptr [rip+0x0]

    mov [foo], rbx
    ; CHECK: mov qword ptr [rip+0x0],rbx

    ; 2. MMX/XMM implicit RIP-relative load
    movq xmm4, [foo]
    ; CHECK: movq xmm4,qword ptr [rip+0x0]

    ; 3. Explicit absolute override (should be sandboxed in Segue mode!)
    mov rax, [abs foo]
    ; CHECK: mov rax,qword ptr gs:0x0
