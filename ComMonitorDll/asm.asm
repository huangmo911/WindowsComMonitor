
EXTERN originalShow : QWORD

extern MessageBoxA : proc
.code

Func proc

	mov rax, [rsp]
	sub rax, 1


	push rcx
	push rdx
	push r8
	push r9

	sub rsp, 28h
	mov rcx, 0
	mov rdx, 0
	mov r8, 0
	mov r9, 0
	call MessageBoxA
	add rsp, 28h
	pop r9
	pop r8
	pop rdx
	pop rcx

	; 通过jmp回到原函数
	mov rax, [originalShow]
	jmp rax
Func endp

end