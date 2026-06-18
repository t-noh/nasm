; RUN: nasm -lfi %s

; Basic return
ret
; CHECK:      pop r11
; CHECK-NEXT: and r11d,-32
; CHECK-NEXT: add r11,r14
; CHECK-NEXT: jmp r11

; Return with immediate (pop extra bytes)
ret 8
; CHECK:      pop r11
; CHECK-NEXT: add esp,0x8
; CHECK-NEXT: lea rsp,[rsp+r14*1]
; CHECK-NEXT: and r11d,-32
; CHECK-NEXT: add r11,r14
; CHECK-NEXT: jmp r11

ret 16
; CHECK:      pop r11
; CHECK-NEXT: add esp,0x10
; CHECK-NEXT: lea rsp,[rsp+r14*1]
; CHECK-NEXT: and r11d,-32
; CHECK-NEXT: add r11,r14
; CHECK-NEXT: jmp r11
