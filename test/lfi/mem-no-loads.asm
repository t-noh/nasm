; RUN: nasm -lfi -lfi-no-loads %s

; Stores-only mode: loads are not sandboxed, stores are sandboxed.

; Load - should NOT be sandboxed
mov ecx, [rax]
; CHECK: mov ecx,dword ptr [rax]
; CHECK-NOT: gs

; Store - should be sandboxed
mov [rax], ecx
; CHECK: mov dword ptr gs:[eax],ecx
