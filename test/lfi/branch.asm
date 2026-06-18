; RUN: nasm -lfi %s

extern foo
extern bar

; Direct calls - align to end of bundle
call foo
; CHECK:      call 0x20

call bar
; CHECK:      call 0x40

; Indirect call through register
call rax
; CHECK:      and eax,0xffffffe0
; CHECK-NEXT: add rax,r14
; CHECK-NEXT: call rax

call rbx
; CHECK:      and ebx,0xffffffe0
; CHECK-NEXT: add rbx,r14
; CHECK-NEXT: call rbx

call rdi
; CHECK:      and edi,0xffffffe0
; CHECK-NEXT: add rdi,r14
; CHECK-NEXT: call rdi

; Indirect call through memory
call [rax]
; CHECK:      mov r11,QWORD PTR gs:[eax]
; CHECK:      and r11d,0xffffffe0
; CHECK-NEXT: add r11,r14
; CHECK-NEXT: call r11

call [rbx + 8]
; CHECK:      mov r11,QWORD PTR gs:[ebx+0x8]
; CHECK:      and r11d,0xffffffe0
; CHECK-NEXT: add r11,r14
; CHECK-NEXT: call r11

call [rax + rcx*8]
; CHECK:      mov r11,QWORD PTR gs:[eax+ecx*8]
; CHECK:      and r11d,0xffffffe0
; CHECK-NEXT: add r11,r14
; CHECK-NEXT: call r11

; Call through stack pointer (safe, no sandboxing needed for load)
call [rsp]
; CHECK:      mov r11,QWORD PTR [rsp]
; CHECK:      and r11d,0xffffffe0
; CHECK-NEXT: add r11,r14
; CHECK-NEXT: call r11

; Indirect jump through register
jmp rax
; CHECK:      and eax,0xffffffe0
; CHECK-NEXT: add rax,r14
; CHECK-NEXT: jmp rax

jmp rbx
; CHECK:      and ebx,0xffffffe0
; CHECK-NEXT: add rbx,r14
; CHECK-NEXT: jmp rbx

; Indirect jump through memory
jmp [rax]
; CHECK:      mov r11,QWORD PTR gs:[eax]
; CHECK:      and r11d,0xffffffe0
; CHECK-NEXT: add r11,r14
; CHECK-NEXT: jmp r11

jmp [rbx + 16]
; CHECK:      mov r11,QWORD PTR gs:[ebx+0x10]
; CHECK:      and r11d,0xffffffe0
; CHECK-NEXT: add r11,r14
; CHECK-NEXT: jmp r11

jmp [rax + rcx*8]
; CHECK:      mov r11,QWORD PTR gs:[eax+ecx*8]
; CHECK:      and r11d,0xffffffe0
; CHECK-NEXT: add r11,r14
; CHECK-NEXT: jmp r11

; Jump through stack pointer
jmp [rsp]
; CHECK:      mov r11,QWORD PTR [rsp]
; CHECK:      and r11d,0xffffffe0
; CHECK-NEXT: add r11,r14
; CHECK-NEXT: jmp r11

; Direct jumps - no rewriting needed
jmp foo
; CHECK: jmp 0x173

je foo
; CHECK: je 0x179

jne bar
; CHECK: jne 0x17f
