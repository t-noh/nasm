; RUN: nasm -lfi -lfi-no-stores %s

; Loads-only mode: stores are not sandboxed, loads are sandboxed.

; Load - should be sandboxed
mov ecx, [rax]
; CHECK: mov ecx,dword ptr gs:[eax]

; Store - should NOT be sandboxed
mov [rax], ecx
; CHECK: mov dword ptr [rax],ecx
; CHECK-NOT: gs
