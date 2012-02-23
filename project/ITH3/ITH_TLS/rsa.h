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
#ifndef ITH_RSA
#define ITH_RSA
#include "arithmetic.h"
#include "prng.h"
#include "sizedef.h"
struct RSA_KeyPair
{
	u8* p;
	u8* q;
	u8* m;
	u8* d;
	u8* e1;
	u8* e2;
	u8* co;
	u32 modulus_size;
};
void find_prime(u8** prime_out, u32 key_length, u32 to_find);
void mulinv_small(u32 a, u8* m, u8* dest, u32 sizem);
void generate_keypair(RSA_KeyPair* key);
#endif