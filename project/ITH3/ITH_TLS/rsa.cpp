/*  Copyright (C) 2010-2012  kaosu (qiupf2000@gmail.com)
 *  This file is part of the Interactive Text Hooker.

 *  Interactive Text Hooker is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.

 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "rsa.h"
#include <windows.h>
#include <intrin.h>
/*

// Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography
// http://tools.ietf.org/html/rfc3447

// PKCS #10: Certification Request Syntax Specification
// http://tools.ietf.org/html/rfc2986

*/


u32 small_primes[]={
	3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,
	79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,
	157,163,167,173,179,181,191,193,197,199,211,223,227,229,
	233,239,241,251,257,263,269,271,277,281,283,293,307,311,
	313,317,331,337,347,349,353,359,367,373,379,383,389,397,
	401,409,419,421,431,433,439,443,449,457,461,463,467,479,
	487,491,499,503,509,521,523,541,547,557,563,569,571,577,
	587,593,599,601,607,613,617,619,631,641,643,647,653,659,
	661,673,677,683,691,701,709,719,727,733,739,743,751,757,
	761,769,773,787,797,809,811,821,823,827,829,839,853,857,
	859,863,877,881,883,887,907,911,919,929,937,941,947,953,
	967,971,977,983,991,997,1009,1013,1019,1021,1031,1033,
	1039,1049,1051,1061,1063,1069,1087,1091,1093,1097,1103,
	1109,1117,1123,1129,1151,1153,1163,1171,1181,1187,1193,
	1201,1213,1217,1223,1229,1231,1237,1249,1259,1277,1279,
	1283,1289,1291,1297,1301,1303,1307,1319,1321,1327,1361,
	1367,1373,1381,1399,1409,1423,1427,1429,1433,1439,1447,
	1451,1453,1459,1471,1481,1483,1487,1489,1493,1499,1511,
	1523,1531,1543,1549,1553,1559,1567,1571,1579,1583,1597,
	1601,1607,1609,1613,1619,1621,1627,1637,1657,1663,1667,
	1669,1693,1697,1699,1709,1721,1723,1733,1741,1747,1753,
	1759,1777,1783,1787,1789,1801,1811,1823,1831,1847,1861,
	1867,1871,1873,1877,1879,1889,1901,1907,1913,1931,1933,
	1949,1951,1973,1979,1987,1993,1997,1999,2003,2011,2017,
	2027,2029,2039,2053,2063,2069,2081,2083,2087,2089,2099,
	2111,2113,2129,2131,2137,2141,2143,2153,2161,2179,2203,
	2207,2213,2221,2237,2239,2243,2251,2267,2269,2273,2281,
	2287,2293,2297,2309,2311,2333,2339,2341,2347,2351,2357,
	2371,2377,2381,2383,2389,2393,2399,2411,2417,2423,2437,
	2441,2447,2459,2467,2473,2477,2503,2521,2531,2539,2543,
	2549,2551,2557,2579,2591,2593,2609,2617,2621,2633,2647,
	2657,2659,2663,2671,2677,2683,2687,2689,2693,2699,2707,
	2711,2713,2719,2729,2731,2741,2749,2753,2767,2777,2789,
	2791,2797,2801,2803,2819,2833,2837,2843,2851,2857,2861,
	2879,2887,2897,2903,2909,2917,2927,2939,2953,2957,2963,
	2969,2971,2999,3001,3011,3019,3023,3037,3041,3049,3061,
	3067,3079,3083,3089,3109,3119,3121,3137,3163,3167,3169,
	3181,3187,3191,3203,3209,3217,3221,3229,3251,3253,3257,
	3259,3271,3299,3301,3307,3313,3319,3323,3329,3331,3343,
	3347,3359,3361,3371,3373,3389,3391,3407,3413,3433,3449,
	3457,3461,3463,3467,3469,3491,3499,3511,3517,3527,3529,
	3533,3539,3541,3547,3557,3559,3571,3581,3583,3593,3607,
	3613,3617,3623,3631,3637,3643,3659,3671,3673,3677};
u32 test_prime_small_factor_asm(u8* number, u32 _size)
{
	__asm
	{
		push ebx
		mov edi,_size
		mov eax,0x200
		add edi,edi
		cmp edi,eax
		cmova edi,eax
		
		mov ecx,number
		push ebp

		mov ebp,_size
		sub ebp,4
		push ebp
		xor ebp,ebp
		std
_test_loop:
		xor edx,edx
		mov esi,[esp]
		add esi,ecx
		mov ebx,[small_primes+ebp*4]
_div_loop:
		lodsd
		div ebx
		lodsd
		div ebx
		lodsd
		div ebx
		lodsd
		div ebx
		cmp esi,ecx
		jae _div_loop
		test edx,edx
		je _final_retn
		add ebp,1
		cmp ebp,edi
		jne _test_loop
_final_retn:
		cld
		mov eax,edx
		pop ecx
		pop ebp
		pop ebx
	}
}
u32 test_prime_small_factor(u8* number, u32 size)
{
	u32 i,test_case;
	int s;
	unsigned __int64 remain;
	test_case=(size>0x100)?0x100:size;
	u32* n=(u32*)number;
	size>>=2;
	for (i=0;i<test_case;i++)
	{
		remain=0;
		for (s=size-1;s>=0;s--)
		{
			remain<<=32;
			remain+=n[s];
			remain=remain%small_primes[i];
		}
		if (remain==0) return false;
	}
	return true;
}
u32 test_prime(u8* number, u32 size, u8 count)
{
	u32 i,j,k,s,original_size;
	u8 t,flag;
	u8 *d,*x,*a,*q,*temp;
	u32* ptrx,*ptrn;
	__declspec(align(16)) PRNGContext ctx;
	if ((number[0]&1)==0) return false;
	if (test_prime_small_factor_asm(number,size)==0) return false;
	//putchar('+');
	number[0]&=~1;
	original_size=size;
	while (number[size-1]==0) size--;
	d=(u8*)alloca(original_size*8);
	x=d+original_size;
	a=x+original_size;
	q=a+original_size*2;
	temp=q+original_size*2;
	memset(d,0,original_size*8);
	for (i=0;i<size&&number[i]==0;i++);
	t=1;
	for (j=0;j<8;j++)
	{
		if (number[i]&t) break;
		t<<=1;
	}
	s=i*8+j;
	for (k=0;i<size-1;i++,k++)
	{
		d[k]=(number[i]>>j)|(number[i+1]<<(8-j));
	}
	d[k]=number[i]>>j;
	for(k++;k<original_size;d[k++]=0);
	number[0]|=1;
	//memset(x,0,original_size);
	//memset(q,0,2*original_size);
	PRNGInit(&ctx);
	ptrx=(u32*)x;
	ptrn=(u32*)number;
	//Miller-Rabin test
	for (;count;count--)
	{
		memset(temp,0,2*original_size);
		PRNGGen(&ctx, a,size);
		if (a[size-1]>number[size-1]) a[size-1]-=number[size-1];	//ensure a<n
		a[0]|=2; //ensure 2<a
		exp_mod(a,d,number,x,original_size,original_size,original_size);
		if (ptrx[0]==1) 
		{
			flag=0;
			for (i=1;i<size/4;i++)
				if (ptrx[i]) 
				{
					flag=1;break;
				}
				if (flag==0) continue; //x=1
		}
		flag=0;
		for (i=1;i<size/4;i++)
		{
			if (ptrn[i]!=ptrx[i])
			{
				flag=1;break;
			}
		}
		if (flag&&ptrn[0]!=ptrx[0]-1)
		{
			//x!=n-1
			for (i=0;i<s;i++)
			{
				mulmnu(temp,x,x,original_size,original_size);
				div_long(q,x,temp,number,original_size*2,original_size);
				flag=0;
				if (ptrx[0]==1)
				{
					for (j=1;j<original_size/4;j++) 
					{
						if (ptrx[j]) {flag=1;break;}
					}
				}
				if (flag==1) return false; //x=1
				for (j=0;j<size/4;j++)
					if (ptrx[j]!=ptrn[j]) return false; //x!=n-1
			}
		}
	}
	return true;
}
struct find_data_set
{
	//CRITICAL_SECTION cs;
	DWORD found, key_length,tried,goal;
	BYTE** prime_out;
};

DWORD WINAPI find_thread(LPVOID f)
{
	find_data_set *set = (find_data_set*)f;
	u32 temp,tm;
	__declspec(align(16)) u8 prime[0x100];
	__declspec(align(16)) PRNGContext ctx;
	PRNGInit(&ctx);
	for(tm = 0;;tm++)
	{
		if (set->found >= set->goal) break;
		PRNGGen(&ctx,prime,set->key_length);
		prime[0]|=1;
		prime[set->key_length-1]|=0x80;
		_InterlockedExchangeAdd((volatile long*)&set->tried,1);
		if (test_prime(prime,set->key_length,25))
		{
			temp = _InterlockedExchangeAdd((volatile long*)&set->found,1);
			if (temp>=set->goal) break;
			//printf("\nFound %d\n",GetCurrentThreadId());
			memcpy(set->prime_out[temp],prime,set->key_length);
		}
	}
	//printf("\nTested[%d] %d\n", GetCurrentThreadId(), tm);
	return 0;
}
void find_prime_mt(u8** prime_out, u32 key_length, u32 to_find)
{
	u32 key_length_round,temp;
	
	//InitializeCriticalSection(&set.cs);
	//u8 prime[0x100];
	//PRNGContext ctx;
	temp=key_length;
	key_length_round=1;
	while (1)
	{
		temp>>=1;
		if (temp==0) break;
		key_length_round<<=1;
	}
	find_data_set set = {0, key_length, 0, to_find, prime_out};
	HANDLE h1 = CreateThread(0,0,find_thread,&set,0,0);
	HANDLE h2 = CreateThread(0,0,find_thread,&set,0,0);
	set.prime_out = prime_out;
	WaitForSingleObject(h1,-1);
	WaitForSingleObject(h2,-1);
	/*__asm rdtsc
	__asm mov pm, eax
	PRNGInit(&ctx, pm);
	pm = 0;
	do{
	PRNGGen(&ctx,prime,key_length_round);
	prime[0]|=1;
	prime[key_length_round-1]|=0x80;
	pm++;
	putchar('+');
	}
	while (test_prime(prime,key_length_round,40)==0);
	memcpy(prime_out,prime,key_length_round);*/
	//printf("\n%d\n",set.tried);
}
void find_prime(u8** prime_out, u32 key_length, u32 to_find)
{
	find_prime_mt(prime_out,key_length, to_find);
	return;
	/*u32 key_length_round,pm,temp;
	u8 prime[0x100];
	PRNGContext ctx;
	__asm rdtsc
	__asm mov pm, eax
	PRNGInit(&ctx, pm);
	pm = 0;
	temp=key_length;
	key_length_round=1;
	while (1)
	{
		temp>>=1;
		if (temp==0) break;
		key_length_round<<=1;
	}
	while(1)
	{
		PRNGGen(&ctx,prime,key_length_round);
		prime[0]|=1;
		prime[key_length_round-1]&=0x7F;
		prime[key_length_round-1]|=0x40;
		pm++;
		putchar('+');
	}
	while (test_prime(prime,key_length_round,40)==0);
	memcpy(prime_out,prime,key_length_round);*/
}
/*void add_mp_asm(u8* dest, u8* src, u32 bsize)
{
	__asm
	{
		xor ecx,ecx
		xor edx,edx
		mov esi,src
		mov edi,dest

_loop_add:
		mov eax,[esi+ecx]
		bt edx,0
		adc [edi+ecx],eax
		mov ebx,[esi+ecx+4]
		adc [edi+ecx+4],ebx
		mov eax,[esi+ecx+8]
		adc [edi+ecx+8],eax
		mov ebx,[esi+ecx+0xC]
		adc [edi+ecx+0xC],ebx
		setc dl
		add ecx,0x10
		cmp ecx,bsize
		jb _loop_add
	}
}*/
void add_mp_c(u8* dest, u8* src, u32 bsize)
{
	u32 temp,i;
	u16* left=(u16*)dest;
	u16* right=(u16*)src;
	bsize>>=1;
	temp=0;
	for (i=0;i<bsize;i++)
	{
		temp += right[i];
		temp += left[i];
		left[i] = temp & 0xFFFF;
		temp >>= 16;
	}
}
/*void sub_mp_asm(u8* dest, u8* src, u32 bsize)
{
	__asm
	{
		mov esi,src
		mov edi,dest
		xor ecx,ecx
		xor edx,edx
_loop_sub:
		mov eax,[esi+ecx]
		bt edx,0
		sbb [edi+ecx],eax
		mov ebx,[esi+ecx+4]
		sbb [edi+ecx+4],ebx
		mov eax,[esi+ecx+8]
		sbb [edi+ecx+8],eax
		mov ebx,[esi+ecx+0xC]
		sbb [edi+ecx+0xC],ebx
		setc dl
		add ecx,0x10
		cmp ecx,bsize
		jne _loop_sub
	}
}*/
void sub_mp_c(u8* dest, u8* src, u32 bsize)
{
	u32 i;
	int temp;
	u16* left=(u16*)dest;
	u16* right=(u16*)src;
	bsize>>=1;
	temp=0;
	for (i=0;i<bsize;i++)
	{
		temp += left[i];
		temp -= right[i];
		left[i] = temp & 0xFFFF;
		temp >>= 16;
	}
}
/*u32 div_single_asm(u8* left, u32 right, u8* q, u32 sizen)
{
	__asm
	{
		pushfd
		std
		mov ebx,sizen
		sub ebx,4
		xor edx,edx
		mov esi,left
		mov ecx,right
		add esi,ebx
		mov edi,q
		add edi,ebx

_loop_sdiv:
		lodsd
		div ecx
		stosd
		lodsd
		div ecx
		stosd
		lodsd
		div ecx
		stosd
		lodsd
		div ecx
		stosd
		sub ebx,0x10
		jns _loop_sdiv
		popfd
		mov eax,edx
	}
}*/
u32 div_single_c(u8* left, u32 right, u8* q, u32 sizen)
{
	u32 temp;
	u16* ptrl, *ptrq;
	ptrl=(u16*)left;
	ptrq=(u16*)q;
	sizen>>=1;
	sizen--;
	temp=ptrl[sizen];
	while (--sizen)
	{
		temp = (temp << 16) | ptrl[sizen];
		ptrq[sizen] = temp / right;
		temp = temp % right;
	}
	temp = (temp << 16) | ptrl[sizen];
	ptrq[0] = temp / right;
	return temp % right;
}
/*u32 mul_single_asm(u8* left, u32 right, u8* dest, u32 sizen)
{
	__asm
	{
		mov ecx,sizen
		shr ecx,2
		xor eax,eax
		mov edi,dest
		rep stosd

		mov esi,left
		mov edi,dest
		mov ecx,sizen
		add ecx,edi
_loop_muls:
		lodsd
		mul right
		add [edi],eax
		adc [edi+4],edx
		lodsd
		mul right
		add [edi+4],eax
		adc [edi+8],edx
		add edi,8
		cmp edi,ecx
		jb _loop_muls
	}
}*/
u32 mul_single_c(u8* left, u32 right, u8* dest, u32 sizen)
{
	u32 i,temp,res;
	u16* ptrl,*ptrd;
	ptrl=(u16*)left;
	ptrd=(u16*)dest;
	sizen>>=1;
	temp=0;
	for (i=0;i<sizen;i++)
	{
		res = ptrl[i];
		temp += res*right;
		ptrd[i] = temp & 0xFFFF;
		temp >>= 16;
	}
	return 0;
}
void mul_single_asm(u8* left, u32 right, u8* dest, u32 sizen)
{
	__asm
	{
		mov edi,dest
		xor eax,eax
		mov ecx,sizen
		mov esi,left
		lea ebx,[esi+ecx]
		shr ecx,2
		repne stosd
		mov edi,dest
		mov ecx,right
_mul_loop:
		lodsd
		mul ecx
		add [edi],eax
		adc [edi+4],edx
		add edi,4
		cmp esi,ebx
		jb _mul_loop
	}
}
void mulinv_small(u32 e, u8* m, u8* dest, u32 sizem)
{
	u8 *y[5];
	u8*block;
	u32 ind,alloc_size;
	u32 q,d0,d1,d2,flag;
	alloc_size=sizem;
	block=(u8*)alloca(alloc_size*4);
	memset(block,0,alloc_size*4);
	y[0]=y[3]=block; y[1]=y[4]=block+alloc_size; y[2]=block+2*alloc_size;
	// y:  [y0, y1, y2, y0, y1], cyclic queue
	d0=e;

	d1=div_single_c(m,e,y[2],sizem); //d1 = m % a ; y[2] = m / a;
	y[1][0]=1;
	ind=3;
	flag=0;
	while(1)
	{
		q=d0/d1;
		d2=d0%d1;
		//mul_single_asm(y[ind-1],q,y[ind],sizem);
		mul_single_c(y[ind-1],q,y[ind],sizem);
		add_mp_c(y[ind],y[ind-2],sizem); //y[n] = y[n-2] + y[n-1] * q;
		if (d2==0) break;
		if (d2==1)
		{
			if (flag==1) // ax = -y mod m <=> ax = (m-y) mod m
			{
				memcpy(dest,m,sizem);
				sub_mp_c(dest,y[ind],sizem);
			}
			else memcpy(dest,y[ind],sizem);
			break;
		}
		flag^=1;
		d0=d1; d1=d2;
		ind++;
		if (ind==5) ind=2;
	}
}
void mulinv_full(u8* e, u8* m, u8* dest, u32 sizem)
{
	u8 *y[5], *d[5];
	u8 *block;
	union {
		u8 *q;
		u32 *qd;
	};
	u32 i,ind1,ind2,alloc_size,flag,l1,l2,l0,lc;

	alloc_size=sizem;
	block=(u8*)alloca(alloc_size * 16);
	memset(block,0,alloc_size * 16);
	// y:  [y0, y1, y2, y0, y1], cyclic queue
	y[0] = y[3] = block; 
	y[1] = y[4] = block + 2 * alloc_size; 
	y[2] = block + 4 * alloc_size;
	// d:  [d0, d1, d2, d0, d1], cyclic queue
	d[0] = d[3] = block + 6 * alloc_size;
	d[1] = d[4] = block + 8 * alloc_size;
	d[2] = block + 10 * alloc_size;
	
	q = block + 12 * alloc_size;
	memcpy(d[0],e,sizem);
	y[1][0]=1; //y0 = 0, y1 = 1
	div_long(y[2],d[1],m,e,sizem,sizem); //y2 = m / e ; d1 = m % e;
	
	ind1 = 3;
	ind2 = 2;
	flag = 0;
	l0=l1=l2=sizem;
	lc = 0;
	while(1)
	{
		//memset(d[ind2],0,sizem);
		memset(d[ind2]+l2,0,sizem-l2);
		//for (;l2>l1;l2-=4) *(u32*)(d[ind2]+l2-4) = 0;
		div_long(q,d[ind2],d[ind2-2],d[ind2-1],l0,l1); // q = d0 / d1; d2 = d0 % d1;
		while (*(u32*)(d[ind2]+l2-4)==0) l2-=4;
		l0 = l1; l1 = l2;
		lc = (l0 - l1)>>2;
		for (i = 1; i < lc; i++) if (qd[i]) break;
		if (i >= lc)
			mul_single_asm(y[ind1-1],qd[0],y[ind1],sizem);
		else
			mulmnu(y[ind1],q,y[ind1-1],sizem,sizem);

		//q=d0/d1;
		//d2=d0%d1;
		//mul_single_asm(y[ind-1],q,y[ind],sizem);
		//mul_single_c(y[ind1-1],q,y[ind1],sizem);
		add_mp_c(y[ind1],y[ind1-2],sizem); //y[n] = y[n-2] + y[n-1] * q;
		if (d[ind2][0] == 0)
		{
			for (i = 0; i<sizem; i++) if (d[ind2][i]) break;
			if (i == sizem) break;
		}	
		//if (d2==0) break;
		if (d[ind2][0] == 1)
		{
			for (i = 1; i<sizem; i++) if (d[ind2][i]) break;
			if (i == sizem)
			{
				if (flag==1) // ax = -y mod m <=> ax = (m-y) mod m
				{
					memcpy(dest,m,sizem);
					sub_mp_c(dest,y[ind1],sizem);
				}
				else memcpy(dest,y[ind1],sizem);
				break;
			}
		}
		flag^=1;
		if (++ind1 == 5) ind1 = 2;
		if (++ind2 == 5) ind2 = 2;
	}
}
void generate_keypair(RSA_KeyPair *key)
{
	u32 size=key->modulus_size/2;
	u8* prime[2] = {key->p,key->q};
	find_prime(prime,size,2);
	//find_prime(&q,size,1);
	key->p[0]--;
	key->q[0]--;
	mulmnu(key->m,key->p,key->q,size,size); //phi=(p-1)(q-1)
	mulinv_small(0x10001,key->m,key->d,key->modulus_size); //d = 0x10001^-1 (mod phi)
	if (key->e1&&key->e2&&key->co)
	{
		u8* buffer = (u8*)alloca(key->modulus_size);
		div_long(buffer,key->e1,key->d,key->p,key->modulus_size,size); //e1 = d (mod p-1)
		div_long(buffer,key->e2,key->d,key->q,key->modulus_size,size); //e2 = d (mod q-1)
		key->p[0]++;
		key->q[0]++;
		mulinv_full(key->q,key->p,key->co,size);
	}
	else
	{
		key->p[0]++;
		key->q[0]++;
	}
	mulmnu(key->m,key->p,key->q,size,size); //m=p*q;
}
void rsa_encrypt(u8* message, u8* cipher, u8* pub_mod, u32 crypt_size)
{
	u8 pub_exp[4]={1,0,1,0};
	exp_mod(message,pub_exp,pub_mod,cipher,crypt_size,4,crypt_size);
}
void rsa_decrypt(u8* cipher, u8* plain_text, u8* private_exp, u8* pub_mod, u32 crypt_size)
{
	exp_mod(cipher,private_exp,pub_mod,plain_text,crypt_size,crypt_size,crypt_size);
}
