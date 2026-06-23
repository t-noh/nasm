; RUN: nasm -lfi %s

extern foo

; Basic load through register - uses GS segment
mov rdi, [rax]
; CHECK: mov rdi,qword ptr gs:[eax]

; Basic store through register
mov [rax], rcx
; CHECK: mov qword ptr gs:[eax],rcx

; Memory access with base and index
mov [rax + rdi], rcx
; CHECK: mov qword ptr gs:[eax+edi*1],rcx

; Memory access with scale
mov rcx, [rax + rdi*4]
; CHECK: mov rcx,qword ptr gs:[eax+edi*4]

mov rcx, [rax + rdi*8]
; CHECK: mov rcx,qword ptr gs:[eax+edi*8]

; Memory access with offset
mov rdi, [rax + 8]
; CHECK: mov rdi,qword ptr gs:[eax+0x8]

mov rdi, [rax + 16]
; CHECK: mov rdi,qword ptr gs:[eax+0x10]

mov rdi, [rax - 8]
; CHECK: mov rdi,qword ptr gs:[eax-0x8]

; Memory access with offset and index
mov rdi, [rax + rcx + 8]
; CHECK: mov rdi,qword ptr gs:[eax+ecx*1+0x8]

mov rdi, [rax + rcx*4 + 16]
; CHECK: mov rdi,qword ptr gs:[eax+ecx*4+0x10]

; RSP access is safe (no sandboxing needed)
mov rax, [rsp]
; CHECK: mov rax,qword ptr [rsp]

mov rax, [rsp + 8]
; CHECK: mov rax,qword ptr [rsp+0x8]

mov [rsp], rax
; CHECK: mov qword ptr [rsp],rax

mov [rsp - 8], rax
; CHECK: mov qword ptr [rsp-0x8],rax

; RIP-relative access is safe
mov rax, [rel foo]
; CHECK: mov rax,qword ptr [rip+0x0]

mov [rel foo], rax
; CHECK: mov qword ptr [rip+0x0],rax

; R14 (sandbox base) access is safe
mov rax, [r14]
; CHECK:      mov r11,qword ptr [r15+0x30]
; CHECK-NEXT: mov rax,qword ptr gs:[r11d]

mov rax, [r14 + 8]
; CHECK:      mov r11,qword ptr [r15+0x30]
; CHECK-NEXT: mov rax,qword ptr gs:[r11d+0x8]

; Different data sizes
mov edi, [rax]
; CHECK: mov edi,dword ptr gs:[eax]

mov di, [rax]
; CHECK: mov di,word ptr gs:[eax]

mov dil, [rax]
; CHECK: mov dil,byte ptr gs:[eax]

; Different instructions
add rdi, [rax]
; CHECK: add rdi,qword ptr gs:[eax]

sub rdi, [rax]
; CHECK: sub rdi,qword ptr gs:[eax]

and rdi, [rax]
; CHECK: and rdi,qword ptr gs:[eax]

or rdi, [rax]
; CHECK: or rdi,qword ptr gs:[eax]

xor rdi, [rax]
; CHECK: xor rdi,qword ptr gs:[eax]

cmp rdi, [rax]
; CHECK: cmp rdi,qword ptr gs:[eax]

test [rax], rdi
; CHECK: test qword ptr gs:[eax],rdi

; LEA does not need sandboxing (no memory access)
lea rdi, [rax]
; CHECK: lea rdi,[rax]

lea rdi, [rax + rcx*4 + 8]
; CHECK: lea rdi,[rax+rcx*4+0x8]

; Push/pop with memory operand
push qword [rax]
; CHECK: push qword ptr gs:[eax]

pop qword [rax]
; CHECK: pop qword ptr gs:[eax]

; Atomic operations
lock inc qword [rax]
; CHECK: lock inc qword ptr gs:[eax]

lock add qword [rax], 1
; CHECK: lock add qword ptr gs:[eax],0x1
