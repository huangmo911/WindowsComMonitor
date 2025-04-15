extern Report : proc
.code

Func proc

	push rcx
	push rdx
	push r8
	push r9

	sub rsp, 28h
	mov rcx, 1234567812345678h
	mov rdx, 1234567812345678h
	mov r8, 1234567812345678h
	mov r9, 1234567812345678h
	mov rax, Report
	call rax
	add rsp, 28h
	pop r9
	pop r8
	pop rdx
	pop rcx

	; 通过jmp回到原函数
	mov rax, 1234567812345678h
	jmp rax
Func endp

end