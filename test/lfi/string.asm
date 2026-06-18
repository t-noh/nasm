; RUN: nasm -lfi %s

; stosq - sandbox RDI (destination)
stosq
; CHECK:      mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: stos qword ptr [rdi],rax

rep stosq
; CHECK:      mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: rep stos qword ptr [rdi],rax

; Different sizes
stosd
; CHECK:      mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: stos dword ptr [rdi],eax

stosw
; CHECK:      mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: stos word ptr [rdi],ax

stosb
; CHECK:      mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: stos byte ptr [rdi],al

; movsq - sandbox both RSI (source) and RDI (destination)
movsq
; CHECK:      mov esi,esi
; CHECK-NEXT: lea rsi,[r14+rsi*1]
; CHECK-NEXT: mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: movs qword ptr [rdi],qword ptr [rsi]

rep movsq
; CHECK:      mov esi,esi
; CHECK-NEXT: lea rsi,[r14+rsi*1]
; CHECK-NEXT: mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: rep movs qword ptr [rdi],qword ptr [rsi]

; Different sizes
movsd
; CHECK:      mov esi,esi
; CHECK-NEXT: lea rsi,[r14+rsi*1]
; CHECK-NEXT: mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: movs dword ptr [rdi],dword ptr [rsi]

movsw
; CHECK:      mov esi,esi
; CHECK-NEXT: lea rsi,[r14+rsi*1]
; CHECK-NEXT: mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: movs word ptr [rdi],word ptr [rsi]

movsb
; CHECK:      mov esi,esi
; CHECK-NEXT: lea rsi,[r14+rsi*1]
; CHECK-NEXT: mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: movs byte ptr [rdi],byte ptr [rsi]

; cmpsq - sandbox both RSI (source) and RDI (destination)
cmpsq
; CHECK:      mov esi,esi
; CHECK-NEXT: lea rsi,[r14+rsi*1]
; CHECK-NEXT: mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: cmps qword ptr [rsi],qword ptr [rdi]

rep cmpsq
; CHECK:      mov esi,esi
; CHECK-NEXT: lea rsi,[r14+rsi*1]
; CHECK-NEXT: mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: repz cmps qword ptr [rsi],qword ptr [rdi]

repne cmpsb
; CHECK:      mov esi,esi
; CHECK-NEXT: lea rsi,[r14+rsi*1]
; CHECK-NEXT: mov edi,edi
; CHECK-NEXT: lea rdi,[r14+rdi*1]
; CHECK-NEXT: repnz cmps byte ptr [rsi],byte ptr [rdi]
