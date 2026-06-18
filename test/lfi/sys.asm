; RUN: nasm -lfi %s

; Syscall is converted to runtime call
syscall
; CHECK:      lea r11,[rip+0x3]
; CHECK-NEXT: jmp qword ptr [r14]

; TLS read: mov rax, [fs:0]  ->  mov rax, [r15 + 32]
mov rax, [fs:0]
; CHECK: mov rax,qword ptr [r15+0x20]

mov rdi, [fs:0]
; CHECK: mov rdi,qword ptr [r15+0x20]

; TLS with immediate offset: mov rax, [fs:8]
; Load thread pointer into r11, then access gs:[r11d + 8]
mov rax, [fs:8]
; CHECK:      mov r11,qword ptr [r15+0x20]
; CHECK-NEXT: mov rax,qword ptr gs:[r11d+0x8]

; TLS with register: mov rax, [fs:rcx]
; Load thread pointer into r11, then access gs:[r11d + ecx]
mov rax, [fs:rcx]
; CHECK:      mov r11,qword ptr [r15+0x20]
; CHECK-NEXT: mov rax,qword ptr gs:[r11d+ecx*1]

; TLS with register and offset: mov rax, [fs:rcx + 16]
mov rax, [fs:rcx + 16]
; CHECK:      mov r11,qword ptr [r15+0x20]
; CHECK-NEXT: mov rax,qword ptr gs:[r11d+ecx*1+0x10]
