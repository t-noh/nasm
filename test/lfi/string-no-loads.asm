; RUN: nasm -lfi-no-loads %s

; Stores-only mode: loads are not sandboxed, stores are sandboxed.

; stosq - RDI is a store, should be sandboxed
stosq
; CHECK:      mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: stos qword ptr [rdi],rax

; movsq - RSI is a load (skip), RDI is a store (sandbox)
movsq
; CHECK:      mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: movs qword ptr [rdi],qword ptr [rsi]

; cmpsq - both RSI and RDI are loads (skip both)
cmpsq
; CHECK:      cmps qword ptr [rsi],qword ptr [rdi]
; (No mov/lea should precede it)

; rep variants
rep stosq
; CHECK:      mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: rep stos qword ptr [rdi],rax

rep movsq
; CHECK:      mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: rep movs qword ptr [rdi],qword ptr [rsi]

rep cmpsq
; CHECK:      repz cmps qword ptr [rsi],qword ptr [rdi]
