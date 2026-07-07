; RUN: nasm -lfi %s
bits 64
section .text
global _start
_start:
    ; 1. Gather dword values using XMM index and scale 4
    vpgatherdd xmm0, [rax + xmm1*4], xmm2
    ; CHECK: vpgatherdd xmm0, dword ptr gs:[eax+xmm1*4], xmm2

    ; 2. Gather qword values using XMM index and scale 8
    vpgatherqd xmm3, [rbx + xmm4*8], xmm5
    ; CHECK: vpgatherqd xmm3, dword ptr gs:[ebx+xmm4*8], xmm5
