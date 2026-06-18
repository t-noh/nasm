; RUN: nasm -lfi %s

; Test x87 FPU register instructions - these don't need sandboxing and compile as-is
fadd st0, st1
; CHECK:      fadd st,st(1)

fadd st2, st0
; CHECK:      fadd st(2),st

fmul st0, st1
; CHECK:      fmul st,st(1)

fmul st3, st0
; CHECK:      fmul st(3),st

fdiv st0, st1
; CHECK:      fdiv st,st(1)

fdiv st2, st0
; CHECK:      fdiv st(2),st

fsub st0, st1
; CHECK:      fsub st,st(1)

fsub st2, st0
; CHECK:      fsub st(2),st

fdivr st0, st1
; CHECK:      fdivr st,st(1)

fsubr st0, st1
; CHECK:      fsubr st,st(1)

fadd st1, st0
; CHECK:      fadd st(1),st

fmul st2, st0
; CHECK:      fmul st(2),st

fdiv st1, st0
; CHECK:      fdiv st(1),st

fsub st1, st0
; CHECK:      fsub st(1),st

; x87 memory operations need sandboxing
fld dword [rax]
; CHECK:      fld DWORD PTR gs:[eax]

fld qword [rbx]
; CHECK:      fld QWORD PTR gs:[ebx]

fstp dword [rcx]
; CHECK:      fstp DWORD PTR gs:[ecx]

fstp qword [rdx]
; CHECK:      fstp QWORD PTR gs:[edx]

fadd dword [rax]
; CHECK:      fadd DWORD PTR gs:[eax]

fadd qword [rax]
; CHECK:      fadd QWORD PTR gs:[eax]

fmul dword [rax]
; CHECK:      fmul DWORD PTR gs:[eax]

fmul qword [rax]
; CHECK:      fmul QWORD PTR gs:[eax]

fdiv dword [rax]
; CHECK:      fdiv DWORD PTR gs:[eax]

fdiv qword [rax]
; CHECK:      fdiv QWORD PTR gs:[eax]

fsub dword [rax]
; CHECK:      fsub DWORD PTR gs:[eax]

fsub qword [rax]
; CHECK:      fsub QWORD PTR gs:[eax]

; x87 memory operations with RSP are safe (no sandboxing)
fld dword [rsp]
; CHECK:      fld DWORD PTR [rsp]

fstp dword [rsp]
; CHECK:      fstp DWORD PTR [rsp]

fadd dword [rsp + 8]
; CHECK:      fadd DWORD PTR [rsp+0x8]
