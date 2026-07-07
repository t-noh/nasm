; RUN: nasm -lfi -lfi-no-segue %s
bits 64
section .text
global _start
_start:
    ; 1. Gather dword values using XMM index and scale 4
    vpgatherdd xmm0, [rax + xmm1*4], xmm2
    ; CHECK:      mov r11d,eax
    ; CHECK-NEXT: add r11,r14
    ; CHECK-NEXT: vpgatherdd xmm0,dword ptr [r11+xmm1*4],xmm2

    ; 2. Gather qword values using XMM index and scale 8
    vpgatherqd xmm3, [rbx + xmm4*8], xmm5
    ; CHECK:      mov r11d,ebx
    ; CHECK-NEXT: add r11,r14
    ; CHECK-NEXT: vpgatherqd xmm3,dword ptr [r11+xmm4*8],xmm5
