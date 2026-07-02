;; LFI Macro Package Test Case (Segue Mode)
;;
;; How to run:
;;   $ ./nasm -f elf64 test/lfi/test_lfi_segue.asm -o test/lfi/test_lfi_segue.o
;;   $ objdump -d test/lfi/test_lfi_segue.o
;;

%define LFI_USE_SEGUE 1
%use lfi

section .text
    ;; --- Memory Access (Segue Mode) ---
    mov [rax], rbx          ; Rewrite: mov [gs:eax], rbx
    mov rcx, [rdx]          ; Rewrite: mov rcx, [gs:edx]
    mov [rsp + 8], rax      ; Safe: rsp relative -> no rewrite
    mov rbx, [rbp - 4]      ; Safe: rbp relative -> no rewrite
    mov rdx, [rel label]    ; Safe: rip relative -> no rewrite
    mov [fs:rax], rcx       ; Rewrite: mov r11, [r15+32]; mov [gs:r11d+eax], rcx
    mov rcx, [fs:rdx]       ; Rewrite: mov r11, [r15+32]; mov rcx, [gs:r11d+edx]
    mov r8, [fs:0]          ; Rewrite: mov r8, [r15+32] (safe TLS read)
    mov [fs:0], r9          ; Rewrite: mov [r15+32], r9 (safe TLS write)
    xorpd xmm0, [rax]       ; Rewrite: xorpd xmm0, [gs:eax]
    movaps [rdx], xmm1      ; Rewrite: movaps [gs:edx], xmm1
    prefetcht0 [rax]        ; Rewrite: prefetcht0 [gs:eax]

    ;; Size prefix preservation
    mov dword [rax], ebx    ; Rewrite: mov dword [gs:eax], ebx
    mov qword [rax], rbx    ; Rewrite: mov qword [gs:eax], rbx
    inc dword [rax]         ; Rewrite: inc dword [gs:eax]

    ;; --- Stack Sandboxing (Same as No-Segue) ---
    add rsp, 8              ; Rewrite: add esp, 8; lea rsp, [rsp+r14] (via db)
    sub rsp, 16             ; Rewrite: sub esp, 16; lea rsp, [rsp+r14] (via db)
    pop rsp                 ; Rewrite: pop r11; mov esp, r11d; lea rsp, [rsp+r14]
    lea rsp, [rbp - 10]     ; Rewrite: lea esp, [rbp-10]; lea rsp, [rsp+r14]

    ;; --- Control Flow Sandboxing ---
    jmp rax                 ; Rewrite: and eax, -32; add rax, r14; jmp rax
    call rbx                ; Rewrite: and ebx, -32; add rbx, r14; call rbx
    jmp [rax]               ; Rewrite: mov r11, [gs:eax]; and r11d, -32; add r11, r14; jmp r11
    call [rbx]              ; Rewrite: mov r11, [gs:ebx]; and r11d, -32; add r11, r14; call r11
    jmp [fs:rax]            ; Rewrite: mov r11, [r15+32]; mov r11, [gs:r11d+eax]; and r11d, -32; ...
    jmp label               ; Safe: direct jump -> no rewrite

    ;; --- Returns ---
    ret                     ; Rewrite: pop r11; and r11d, -32; add r11, r14; jmp r11
    ret 8                   ; Rewrite: pop r11; ...; add esp, 8; lea rsp, ...; jmp r11

    ;; --- Syscalls ---
    syscall                 ; Rewrite: lea r11, [rel .ret]; jmp [r14]; .ret: (via db)

label:
    nop
