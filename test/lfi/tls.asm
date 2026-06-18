; RUN: nasm -lfi %s

; TLS read: mov rax, [fs:0]  ->  mov rax, [r15 + 32]
mov rax, [fs:0]
; CHECK:      mov rax,QWORD PTR [r15+0x20]

mov rdi, [fs:0]
; CHECK:      mov rdi,QWORD PTR [r15+0x20]

mov rcx, [fs:0]
; CHECK:      mov rcx,QWORD PTR [r15+0x20]

; TLS with immediate offset
; Load thread pointer into r11, then access with offset via GS segment.
mov rax, [fs:8]
; CHECK:      mov r11,QWORD PTR [r15+0x20]
; CHECK-NEXT: mov rax,QWORD PTR gs:[r11d+0x8]

mov rdi, [fs:16]
; CHECK:      mov r11,QWORD PTR [r15+0x20]
; CHECK-NEXT: mov rdi,QWORD PTR gs:[r11d+0x10]

; TLS with register base
; Load thread pointer into r11, base becomes index.
mov rax, [fs:rcx]
; CHECK:      mov r11,QWORD PTR [r15+0x20]
; CHECK-NEXT: mov rax,QWORD PTR gs:[r11d+ecx*1]

; TLS with register base and offset
mov rax, [fs:rcx + 16]
; CHECK:      mov r11,QWORD PTR [r15+0x20]
; CHECK-NEXT: mov rax,QWORD PTR gs:[r11d+ecx*1+0x10]

; TLS store
mov [fs:rcx], rax
; CHECK:      mov r11,QWORD PTR [r15+0x20]
; CHECK-NEXT: mov QWORD PTR gs:[r11d+ecx*1],rax

; TLS add (e.g. add rax, [fs:0])
add rax, [fs:0]
; CHECK:      mov r11,QWORD PTR [r15+0x20]
; CHECK-NEXT: add rax,QWORD PTR gs:[r11d]
