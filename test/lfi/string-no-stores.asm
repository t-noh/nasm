; RUN: nasm -lfi-no-stores %s

; Loads-only mode: stores are not sandboxed, loads are sandboxed.

; stosq - RDI is a store, should not be sandboxed
stosq
; CHECK:      stos qword ptr [rdi],rax
; (No mov/lea should precede it)

; movsq - RSI is a load (sandbox), RDI is a store (skip)
movsq
; CHECK:      mov esi,esi
; CHECK-NEXT: lea rsi,[r14+rsi*1]
; CHECK-NEXT: movs qword ptr [rdi],qword ptr [rsi]

; cmpsq - both RSI and RDI are loads (sandbox both)
cmpsq
; CHECK:      mov esi,esi
; CHECK-NEXT: lea rsi,[r14+rsi*1]
; CHECK-NEXT: mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: cmps qword ptr [rsi],qword ptr [rdi]

; rep variants
rep stosq
; CHECK:      rep stos qword ptr [rdi],rax
; (No mov/lea should precede it)

rep movsq
; CHECK:      mov esi,esi
; CHECK-NEXT: lea rsi,[r14+rsi*1]
; CHECK-NEXT: rep movs qword ptr [rdi],qword ptr [rsi]

rep cmpsq
; CHECK:      mov esi,esi
; CHECK-NEXT: lea rsi,[r14+rsi*1]
; CHECK-NEXT: mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: repz cmps qword ptr [rsi],qword ptr [rdi]
