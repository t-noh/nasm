; RUN: nasm -lfi %s

; Move to RSP
mov rsp, rdi
; CHECK:      mov esp,edi
; CHECK-NEXT: lea rsp,[rsp+r14*1]

mov rsp, rax
; CHECK:      mov esp,eax
; CHECK-NEXT: lea rsp,[rsp+r14*1]

; Add to RSP
add rsp, rax
; CHECK:      add esp,eax
; CHECK-NEXT: lea rsp,[rsp+r14*1]

add rsp, rcx
; CHECK:      add esp,ecx
; CHECK-NEXT: lea rsp,[rsp+r14*1]

; Add immediate to RSP
add rsp, 8
; CHECK:      add esp,0x8
; CHECK-NEXT: lea rsp,[rsp+r14*1]

add rsp, 16
; CHECK:      add esp,0x10
; CHECK-NEXT: lea rsp,[rsp+r14*1]

add rsp, 128
; CHECK:      add esp,0x80
; CHECK-NEXT: lea rsp,[rsp+r14*1]

; Sub from RSP
sub rsp, 8
; CHECK:      sub esp,0x8
; CHECK-NEXT: lea rsp,[rsp+r14*1]

sub rsp, 16
; CHECK:      sub esp,0x10
; CHECK-NEXT: lea rsp,[rsp+r14*1]

sub rsp, rax
; CHECK:      sub esp,eax
; CHECK-NEXT: lea rsp,[rsp+r14*1]

; And with RSP
and rsp, -16
; CHECK:      and esp,0xfffffff0
; CHECK-NEXT: lea rsp,[rsp+r14*1]

; Or with RSP
or rsp, 8
; CHECK:      or esp,0x8
; CHECK-NEXT: lea rsp,[rsp+r14*1]

; LEA into RSP
lea rsp, [rax + 8]
; CHECK:      lea esp,[eax+0x8]
; CHECK-NEXT: lea rsp,[rsp+r14*1]

lea rsp, [rax + rcx]
; CHECK:      lea esp,[eax+ecx*1]
; CHECK-NEXT: lea rsp,[rsp+r14*1]

; Pop into RSP (special case)
pop rsp
; CHECK:      pop r11
; CHECK-NEXT: mov esp,r11d
; CHECK-NEXT: lea rsp,[rsp+r14*1]

; Regular push/pop should NOT trigger stack modification handling
; (they implicitly modify RSP but don't have RSP as an explicit destination)
push rax
; CHECK: push rax

pop rax
; CHECK: pop rax

push rbx
; CHECK: push rbx

pop rbx
; CHECK: pop rbx
