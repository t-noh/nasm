; RUN: nasm -lfi-no-loads -lfi-no-stores %s

; Jumps-only mode: no memory sandboxing at all.

stosq
; CHECK:      stos qword ptr [rdi],rax
; (No mov/lea should precede it)

movsq
; CHECK:      movs qword ptr [rdi],qword ptr [rsi]
; (No mov/lea should precede it)

cmpsq
; CHECK:      cmps qword ptr [rsi],qword ptr [rdi]
; (No mov/lea should precede it)

rep stosq
; CHECK:      rep stos qword ptr [rdi],rax

rep movsq
; CHECK:      rep movs qword ptr [rdi],qword ptr [rsi]

repne cmpsb
; CHECK:      repnz cmps byte ptr [rsi],byte ptr [rdi]
