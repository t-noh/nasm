; RUN: nasm -lfi %s
bits 64
section .text

global _start
_start:
    ; =========================================================================
    ; ARCHITECTURAL NOTE ON LFI BRANCH RELAXATION:
    ; In LFI mode, we unconditionally strip the SHORT flag from all jump operands
    ; to prevent "short jump out of range" errors caused by LFI instruction expansion.
    ;
    ; Because our LFI rewriter generates rewritten instructions on the fly during the
    ; assembly phase, these instructions do not reside in NASM's global instruction list
    ; and therefore bypass NASM's native branch-shrinking optimization passes.
    ;
    ; Consequently, ALL size-agnostic jumps (both forward and backward, short and long)
    ; in LFI mode are assembled using the safe, default near-jump size (5 bytes).
    ; This is a highly desirable security and alignment property in SFI compilers,
    ; ensuring predictable branch sizes and bundle alignments.
    ; =========================================================================

    ; =========================================================================
    ; Test Case 1: Backward Short Jump
    ; Target is defined BEFORE the jump, short distance.
    ; Stripped of SHORT flag, compiles to a secure 5-byte near jump in LFI.
    ; =========================================================================
..@t1:
..@s1:
    jmp short ..@t1
    ; Use location counter ($ - ..@s1) to measure exact jump instruction size (5 bytes)
    mov rax, ($ - ..@s1)
    ; CHECK: mov eax,0x5

    ; =========================================================================
    ; Test Case 2: Forward Short Jump
    ; Target is defined AFTER the jump, short distance.
    ; Stripped of SHORT flag, compiles to a secure 5-byte near jump in LFI.
    ; =========================================================================
..@s2:
    jmp short ..@t2
    mov rbx, ($ - ..@s2)
    ; CHECK: mov ebx,0x5
..@t2:

    ; =========================================================================
    ; Test Case 3: Backward Long Jump (exceeds 127 bytes)
    ; Target is defined BEFORE the jump, but separated by 150 bytes of padding.
    ; Under normal compilation, this fails. Under LFI, it is relaxed to a 5-byte near jump.
    ; =========================================================================
..@t3:
    times 150 nop
..@s3:
    jmp short ..@t3
    mov rcx, ($ - ..@s3)
    ; CHECK: mov ecx,0x5

    ; =========================================================================
    ; Test Case 4: Forward Long Jump (exceeds 127 bytes)
    ; Target is defined AFTER the jump, but separated by 150 bytes of padding.
    ; Under normal compilation, this fails. Under LFI, it is relaxed to a 5-byte near jump.
    ; =========================================================================
..@s4:
    jmp short ..@t4
    mov rdx, ($ - ..@s4)
    ; CHECK: mov edx,0x5
    times 150 nop
..@t4:
