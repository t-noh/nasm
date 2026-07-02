;; LFI Macro Package Test Case
;;
;; How to run:
;;   $ ./nasm -f elf64 test/lfi/test_lfi.asm -o test/lfi/test_lfi.o
;;   $ objdump -d test/lfi/test_lfi.o
;;

%use lfi

section .text
    ;; --- Memory Access (No-Segue Mode) ---
    mov [rax], rbx          ; Rewrite: lea r11d, [rax]; mov [r14 + r11*1], rbx
    mov rcx, [rdx]          ; Rewrite: lea r11d, [rdx]; mov rcx, [r14 + r11*1]
    mov [rsp + 8], rax      ; Safe: rsp relative -> no rewrite
    mov rbx, [rbp - 4]      ; Safe: rbp relative -> no rewrite
    mov rdx, [rel label]    ; Safe: rip relative -> no rewrite
    mov [fs:rax], rcx       ; Safe: segment override -> no rewrite
    xorpd xmm0, [rax]       ; Rewrite: lea r11d, [rax]; xorpd xmm0, [r14 + r11*1]
    movaps [rdx], xmm1      ; Rewrite: lea r11d, [rdx]; movaps [r14 + r11*1], xmm1
    prefetcht0 [rax]        ; Rewrite: lea r11d, [rax]; prefetcht0 [r14 + r11*1]

    ;; Size prefix preservation
    mov dword [rax], ebx    ; Rewrite: lea r11d, [rax]; mov dword [r14 + r11*1], ebx
    mov qword [rax], rbx    ; Rewrite: lea r11d, [rax]; mov qword [r14 + r11*1], rbx
    inc dword [rax]         ; Rewrite: lea r11d, [rax]; inc dword [r14 + r11*1]

    ;; --- Stack Sandboxing ---
    add rsp, 8              ; Rewrite: add esp, 8; lea rsp, [rsp+r14] (via db)
    sub rsp, 16             ; Rewrite: sub esp, 16; lea rsp, [rsp+r14] (via db)
    pop rsp                 ; Rewrite: pop r11; mov esp, r11d; lea rsp, [rsp+r14]
    lea rsp, [rbp - 10]     ; Rewrite: lea esp, [rbp-10]; lea rsp, [rsp+r14]

    ;; --- Control Flow Sandboxing ---
    jmp rax                 ; Rewrite: and eax, -32; add rax, r14; jmp rax
    call rbx                ; Rewrite: and ebx, -32; add rbx, r14; call rbx
    jmp [rax]               ; Rewrite: lea r11d, [rax]; mov r11, [r14+r11]; ...
    call [rbx]              ; Rewrite: lea r11d, [rbx]; mov r11, [r14+r11]; ...
    jmp label               ; Safe: direct jump -> no rewrite

    ;; --- Returns ---
    ret                     ; Rewrite: pop r11; and r11d, -32; add r11, r14; jmp r11
    ret 8                   ; Rewrite: pop r11; ...; add esp, 8; lea rsp, ...; jmp r11

    ;; --- Syscalls ---
    syscall                 ; Rewrite: lea r11, [rel .ret]; jmp [r14]; .ret: (via db)

label:
    nop
