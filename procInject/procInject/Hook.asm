
_DATA SEGMENT
_DATA ENDS
_TEXT SEGMENT
	getProcObj PROC
		mov rax, r14
		ret
	getProcObj ENDP

	setProcObj PROC obj:QWORD
		mov r14, obj
		ret
	setProcObj ENDP

_TEXT ENDS
END