; RUN: nasm -lfi -lfi-no-loads %s

extern foo

; In stores-only mode, loads are not sandboxed but stores are.

; Load through register - not sandboxed
mov rdi, [rax]
; CHECK: mov rdi,qword ptr [rax]

; Store through register - sandboxed
mov [rax], rcx
; CHECK: mov qword ptr gs:[eax],rcx

; Load with base and index - not sandboxed
mov rcx, [rax + rdi]
; CHECK: mov rcx,qword ptr [rax+rdi*1]

; Store with base and index - sandboxed
mov [rax + rdi], rcx
; CHECK: mov qword ptr gs:[eax+edi*1],rcx

; Load with offset - not sandboxed
mov rdi, [rax + 8]
; CHECK: mov rdi,qword ptr [rax+0x8]

; Store with offset - sandboxed
mov [rax + 8], rdi
; CHECK: mov qword ptr gs:[eax+0x8],rdi

; ALU load - not sandboxed
add rdi, [rax]
; CHECK: add rdi,qword ptr [rax]

; ALU store - sandboxed
add [rax], rdi
; CHECK: add qword ptr gs:[eax],rdi

; Compare (load-only) - not sandboxed
cmp rdi, [rax]
; CHECK: cmp rdi,qword ptr [rax]

; LEA - never sandboxed
lea rdi, [rax]
; CHECK: lea rdi,[rax]

; Push/pop with memory (both may store) - sandboxed
push qword [rax]
; CHECK: push qword ptr gs:[eax]

pop qword [rax]
; CHECK: pop qword ptr gs:[eax]

; Lock prefix (atomic store) - sandboxed
lock inc qword [rax]
; CHECK: lock inc qword ptr gs:[eax]

; RSP access is safe (no sandboxing needed)
mov rax, [rsp]
; CHECK: mov rax,qword ptr [rsp]

mov [rsp], rax
; CHECK: mov qword ptr [rsp],rax

; RIP-relative access is safe
mov rax, [rel foo]
; CHECK: mov rax,qword ptr [rip+0x0]

mov [rel foo], rax
; CHECK: mov qword ptr [rip+0x0],rax

; TLS read (fs:0) - thread pointer rewrite still happens
mov rax, [fs:0]
; CHECK: mov rax,qword ptr [r15+0x20]

; TLS with offset (load) - TP rewrite but no GS sandbox
mov rax, [fs:8]
; CHECK:      mov r11,qword ptr [r15+0x20]
; CHECK-NEXT: mov rax,qword ptr [r11+0x8]

; TLS with register base (load) - TP rewrite but no GS sandbox
mov rax, [fs:rcx]
; CHECK:      mov r11,qword ptr [r15+0x20]
; CHECK-NEXT: mov rax,qword ptr [r11+rcx*1]

; TLS with register base and offset (load) - TP rewrite but no GS sandbox
mov rax, [fs:rcx + 16]
; CHECK:      mov r11,qword ptr [r15+0x20]
; CHECK-NEXT: mov rax,qword ptr [r11+rcx*1+0x10]

; TLS store - TP rewrite with GS sandbox
mov [fs:rcx], rax
; CHECK:      mov r11,qword ptr [r15+0x20]
; CHECK-NEXT: mov qword ptr gs:[r11d+ecx*1],rax

; String operations - only destination (RDI) is sandboxed
movsb
; CHECK:      mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: movs byte ptr [rdi],byte ptr [rsi]

stosb
; CHECK:      mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: stos byte ptr [rdi],al

rep movsq
; CHECK:      mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: rep movs qword ptr [rdi],qword ptr [rsi]
