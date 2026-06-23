; RUN: nasm -lfi -lfi-no-segue %s

; In no-segue mode, memory sandboxing uses explicit instructions instead of GS segment.
; The general pattern is: clear high bits with mov32/lea32, then use R14 as base.

; Load with simple addressing - dest register used as scratch
mov rdi, [rax]
; CHECK:      mov edi,eax
; CHECK-NEXT: mov rdi,qword ptr [r14+rdi*1]

; Store - R11 used as scratch
mov [rax], rsi
; CHECK:      mov r11d,eax
; CHECK-NEXT: mov qword ptr [r14+r11*1],rsi

; Non-mov instruction - R11 used as scratch
add rdi, [rax]
; CHECK:      mov r11d,eax
; CHECK-NEXT: add rdi,qword ptr [r14+r11*1]

; Load with offset - LEA used to compute address
mov rdi, [rax + 8]
; CHECK:      lea edi,[rax+0x8]
; CHECK-NEXT: mov rdi,qword ptr [r14+rdi*1]

; Absolute register (RSP) - no sandboxing needed
mov rdi, [rsp]
; CHECK: mov rdi,qword ptr [rsp]

; Absolute register (R14) - no sandboxing needed
mov rdi, [r14]
; CHECK:      mov r11,qword ptr [r15+0x30]
; CHECK-NEXT: mov r11d,r11d
; CHECK-NEXT: mov rdi,qword ptr [r14+r11*1]

; Index with absolute base - just clear index high bits
mov rdi, [r14 + rax]
; CHECK:      mov r11,qword ptr [r15+0x30]
; CHECK-NEXT: lea r11d,[r11+rax*1]
; CHECK-NEXT: mov rdi,qword ptr [r14+r11*1]

; Complex addressing with offset - LEA used
mov rdi, [rax + rcx*4 + 16]
; CHECK:      lea edi,[rax+rcx*4+0x10]
; CHECK-NEXT: mov rdi,qword ptr [r14+rdi*1]

; Store with offset
mov [rax + 8], rsi
; CHECK:      lea r11d,[rax+0x8]
; CHECK-NEXT: mov qword ptr [r14+r11*1],rsi
