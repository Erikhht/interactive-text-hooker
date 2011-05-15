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

EXTRN	LeadByteTable:QWORD
EXTRN	code_page:QWORD
EXTRN	share_mask:QWORD
_TEXT	SEGMENT
GetPebAndTeb	PROC
	mov rax, gs:[030h]
	mov [rdx],rax
	mov rax,[rax+060h]
	mov [rcx],rax
	ret
GetPebAndTeb	ENDP

GetShareMemory	PROC
	mov rax, gs:[060h]
	mov rax, [rax+088h]
	ret
GetShareMemory	ENDP

GetHashCStr	PROC
	xor rax,rax
_hashc_calc:
	movzx rdx, byte ptr [rcx]
	test dl,dl
	jz _hashc_fin
	rol rax,7
	add rax,rdx
	inc rcx
	jmp _hashc_calc
_hashc_fin:
	ret
GetHashCStr	ENDP

GetHashWStr	PROC
	xor rax,rax
_hashw_calc:
	movzx rdx, byte ptr [rcx]
	test dl,dl
	jz _hashw_fin
	rol rax,7
	add rax,rdx
	add rcx,2
	jmp _hashw_calc
_hashw_fin:
	ret
GetHashWStr	ENDP

GetModulePath	PROC
	mov rax, gs:[060h]
	mov rax, [rax+018h]
	mov rax, [rax+010h]
	mov rax, [rax+050h]
	ret
GetModulePath	ENDP	

GetTimeBias	PROC
	mov rax, 07ffe0020h
	ret
GetTimeBias	ENDP

SearchPattern PROC
		mov rax,r9
		mov [rbp+10h],rcx
		mov [rbp+18h],rdx
alloc:
		push 0
		sub rax,1
		jnz alloc

		mov r11,r8
		mov rdx,r9 
		mov rcx,1
		xor r10,r10
build_table:
		mov al,byte ptr [r11+r10]
		cmp al,byte ptr [r11+rcx]
		sete al
		test r10,r10
		jz pre
		test al,al
		jnz pre
		mov r10,[rsp+r10*8-8]
		jmp build_table
pre:
		test al,al
		jz write_table
		add r10,1
write_table:
		mov [rsp+rcx*8],r10

		add rcx,1
		cmp rcx,rdx
		jb build_table

		mov r10,[rbp+10h]
		xor rdx,rdx
		mov rcx,rdx
matcher:
		mov al,byte ptr [r11+rcx]
		cmp al,byte ptr [r10+rdx]
		sete al
		test rcx,rcx
		jz match
		test al,al
		jnz match
		mov rcx, [rsp+rcx*8-8]
		jmp matcher
match:
		test al,al
		jz pre2
		add rcx,1
		cmp rcx,r9
		je finish
pre2:
		add rdx,1
		cmp rdx,[rbp+18h]
		jb matcher
		mov rdx,r9
		sub rdx,1
finish:
		mov rcx,r9
		sub rdx,rcx
		lea rax,[rdx+1]
		lea rcx,[rcx*8]
		add rsp,rcx
		ret
SearchPattern ENDP

MB_WC	PROC
	push rbx
	xor rbx,rbx
	lea r8,LeadByteTable
	mov r9,code_page
	add r9,0220h
	mov r10,rdx
_mb_translate:
	movzx eax,word ptr [rcx]
	test al,al
	jz _mb_fin
	movzx r11,al
	mov al,byte ptr [r8+r11]
	test al,1
	cmovnz bx, word ptr [r11*2+r9-0204h]
	jnz _mb_next
	mov bx, word ptr [r11*2+r9]
	mov bl,ah
	mov bx, word ptr [rbx*2+r9]
_mb_next:
	mov word ptr [rdx], bx
	add rdx,2
	and rax,3
	add rcx,rax
	jmp _mb_translate
_mb_fin:
	mov rax,rdx
	sub rax,r10
	shr rax,1
	pop rbx
	ret
MB_WC	ENDP

MB_WC_count PROC
	xor rax,rax
	xor r9,r9
	lea r8,LeadByteTable
_mbc_count:
	mov r9b,byte ptr [rcx]
	movzx r10,byte ptr [r8+r9]
	add rcx,r10
	add rax,1
	sub rdx,r10
	ja _mbc_count
	ret
MB_WC_count ENDP

WC_MB	PROC
	mov r8,code_page
	add r8,07C22h
	mov r9,rcx
	mov r10,rdx
	mov r11,1
_wc_translate:
	movzx rax, word ptr[r9]
	test rax,rax
	jz _wc_fin
	mov cx, word ptr[rax*2+r8]
	test ch,ch
	jz _wc_single
	mov byte ptr [rdx],ch
	add rdx,r11
_wc_single:
	mov byte ptr [rdx],cl
	add rdx,r11
	lea r9,[r9+r11*2]
	jmp _wc_translate
_wc_fin:
	mov rax,rdx
	sub rax,r10
	ret
WC_MB	ENDP

GetMemory PROC

	push rbx
	push rsi
	push rdi
	push r12
	push r13
	push r14
	push r15

	mov rbx,[rcx]
	mov rsi,rcx
	lea rdi,[rsi+rbx*8]
	mov rax,0100h

	xor r8,r8
	xor r9,r9
	xor r10,r10
	xor r11,r11
	pxor xmm12,xmm12
	pxor xmm13,xmm13
	pxor xmm14,xmm14
	pxor xmm15,xmm15

	lea rbx,share_mask
sse_calc:
	movapd xmm0,[rsi]
	movapd xmm1,[rsi+010h]
	movapd xmm2,[rsi+020h]
	movapd xmm3,[rsi+030h]
	movapd xmm4,[rsi+040h]
	movapd xmm5,[rsi+050h]
	movapd xmm6,[rsi+060h]
	movapd xmm7,[rsi+070h]
	add rsi,080h
	movapd xmm8,[rsi]
	movapd xmm9,[rsi+010h]
	movapd xmm10,[rsi+020h]
	movapd xmm11,[rsi+030h]
	mov r12,[rsi+040h]
	mov r13,[rsi+048h]
	mov r14,[rsi+050h]
	mov r15,[rsi+058h]

	andpd xmm0,[rbx]
	andpd xmm1,[rbx]
	andpd xmm2,[rbx]
	andpd xmm3,[rbx]
	and r12,rax
	and r13,rax
	and r14,rax
	and r15,rax

	andpd xmm4,[rbx]
	andpd xmm5,[rbx]
	andpd xmm6,[rbx]
	andpd xmm7,[rbx]
	add r8,r12
	add r9,r13
	add r10,r14
	add r11,r15

	andpd xmm8,[rbx]
	andpd xmm9,[rbx]
	andpd xmm10,[rbx]
	andpd xmm11,[rbx]
	mov r12,[rsi+060h]
	mov r13,[rsi+068h]
	mov r14,[rsi+070h]
	mov r15,[rsi+078h]

	addpd xmm12,xmm0
	addpd xmm13,xmm1
	addpd xmm14,xmm2
	addpd xmm15,xmm3
	and r12,rax
	and r13,rax
	and r14,rax
	and r15,rax

	addpd xmm12,xmm4
	addpd xmm13,xmm5
	addpd xmm14,xmm6
	addpd xmm15,xmm7
	add r8,r12
	add r9,r13
	add r10,r14
	add r11,r15

	addpd xmm12,xmm8
	addpd xmm13,xmm9
	addpd xmm14,xmm10
	addpd xmm15,xmm11
	add rsi,080h
	cmp rsi,rdi
	jb sse_calc
	add r8,r9
	add r10,r11
	mov rax,r8
	add rax,r10
	addpd xmm12,xmm13
	addpd xmm14,xmm15
	movupd [rsp+40h], xmm12
	movupd [rsp+50h], xmm14
	add rax,[rsp+40h]
	add rax,[rsp+48h]
	add rax,[rsp+50h]
	add rax,[rsp+58h]
	shr rax,8
	mov rbx,[rcx]
	bt rbx,8
	sbb rax,0
	sub rbx,rax
	lea rax,[rbx*4]
	mov [rdx],rax

	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx
	ret
GetMemory ENDP
_TEXT	ENDS
END