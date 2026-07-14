; RUN: nasm -lfi %s
bits 64
section .text

global _start
_start:
    nop

    ; =========================================================================
    ; LFI SELECTIVE LABEL ALIGNMENT POLICY DEMONSTRATION:
    ; 1. All user-defined global labels MUST be aligned to 32 bytes.
    ; 2. Any local label (including macro labels and .Ltmp labels) whose
    ;    address is TAKEN in a value/data expression MUST be aligned to 32 bytes.
    ; 3. Local labels that are ONLY target of direct branches MUST NOT be aligned,
    ;    eliminating code bloat in tight loops.
    ; 4. LFI internal compiler-generated labels (.Llfi_sys_ret_) MUST NOT be aligned.
    ; =========================================================================

global_label:
    nop
.local_label_address_taken:
    nop
..@macro_label_address_taken:
    nop
.local_macro_address_taken:
    nop
.Ltmp_user_address_taken:
    nop

    ; Direct branch target (address NOT taken)
    mov eax, 10
.Luntaken_loop:
    dec eax
    jnz .Luntaken_loop


    ; =========================================================================
    ; Case 1: Local Label whose address is TAKEN
    ; MUST be aligned to 32 bytes.
    ; =========================================================================
    mov rax, (.local_label_address_taken - global_label)
    ; CHECK: mov eax,0x20

    ; =========================================================================
    ; Case 2: Macro / Special Label whose address is TAKEN
    ; MUST be aligned to 32 bytes because its address is used as data.
    ; =========================================================================
    mov rbx, (..@macro_label_address_taken - .local_label_address_taken)
    ; CHECK: mov ebx,0x20

    ; =========================================================================
    ; Case 3: Label containing '@' whose address is TAKEN
    ; MUST be aligned to 32 bytes.
    ; =========================================================================
    mov r8, (.local_macro_address_taken - .local_label_address_taken)
    ; CHECK: mov r8d,0x40

    ; =========================================================================
    ; Case 4: Label starting with '.Ltmp' whose address is TAKEN
    ; MUST be aligned to 32 bytes.
    ; =========================================================================
    mov r9, (.Ltmp_user_address_taken - .local_macro_address_taken)
    ; CHECK: mov r9d,0x20


    ; =========================================================================
    ; Case 5: Global Label
    ; MUST be aligned to 32 bytes.
    ; =========================================================================
    mov rdx, rcx
    add rdx, 8

global_target:
    nop
    mov rcx, (global_target - global_label)
    ; CHECK: mov ecx,0xc0
