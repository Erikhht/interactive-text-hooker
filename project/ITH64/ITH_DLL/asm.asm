;  Copyright (C) 2010-2011  kaosu (qiupf2000@gmail.com)
;  This file is part of the Interactive Text Hooker.

;  Interactive Text Hooker is free software: you can redistribute it and/or
;  modify it under the terms of the GNU General Public License as published
;  by the Free Software Foundation, either version 3 of the License, or
;  (at your option) any later version.

;  This program is distributed in the hope that it will be useful,
;  but WITHOUT ANY WARRANTY; without even the implied warranty of
;  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;  GNU General Public License for more details.

;  You should have received a copy of the GNU General Public License
;  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 

EXTRN	_wcsicmp:QWORD
EXTRN _wcslwr:QWORD

_TEXT	SEGMENT
GetModuleBaseByName	PROC
	push rbx
	push rbp
	push rsi
	push rdi
	mov rsi,rcx
	lea rdi,_wcsicmp
	sub rsp,020h
	mov rax,gs:[060h]
	mov rax,[rax+018h]
	mov rbp,[rax+010h]
_listfind:
	mov rbx,[rbp+060h]
	test rbx,rbx
	jz _notfound
	mov rcx,rsi
	mov rdx,rbx
	call rdi
	test rax,rax
	jz _found
	mov rbp,[rbp]
	jmp _listfind
_notfound:
	xor rax,rax
	jmp _termin
_found:
	mov rax,[rbp+030h]
_termin:
	add rsp,020h
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	ret
GetModuleBaseByName	ENDP

GetModuleBaseByHash	PROC
	push rbx
	push rbp
	push rsi
	push rdi
	sub rsp,020h
	mov rbp,rcx
	mov rax,gs:[060h]
	mov rax,[rax+018h]
	mov rsi,[rax+010h]
	lea rdi,_wcslwr
_hash_listfind:
	mov rbx,[rsi+060h]
	test rbx,rbx
	jz _hash_notfound
	mov rcx,rbx
	call rdi
	mov rdx,rax
	xor rax,rax
_hash_calc:
	movzx rcx, word ptr [rdx]
	test rcx,rcx
	jz _hash_fin
	rol rax,7
	add rax,rcx
	add rdx,2
	jmp _hash_calc
	_hash_fin:
	cmp rax,rbp
	jz _hash_found
	mov rsi,[rsi]
	jmp _hash_listfind
_hash_notfound:
	xor rax,rax
	jmp _hash_termin
_hash_found:
	mov rax,[rsi+030h]
_hash_termin:
	add rsp,020h
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	ret
GetModuleBaseByHash	ENDP
_TEXT	ENDS
END