/*  Copyright (C) 2010-2011  kaosu (qiupf2000@gmail.com)
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

#pragma once
#include <windows.h>
template <typename T> 
void Release(const T& p) {delete p;}
#define MK_FUNDA_TYPE(T) \
template<> \
 void Release<T>(const T& p) {}
template<class T>
class BinaryEqual
{
public:
	bool operator ()(const T& a, const T& b, DWORD) {return a==b;}
};
template<class T, size_t default_size, class fComp=BinaryEqual<T> >
class MyVector
{
public:
	MyVector()
	{
		InitializeCriticalSection(&cs_store);
		size=default_size;
		used=0;
		storage=new T[size];
	}
	virtual ~MyVector()
	{
		delete []storage;
		DeleteCriticalSection(&cs_store);
	}
	void Reset()
	{
		EnterCriticalSection(&cs_store);
		for (size_t i=0;i<used;i++)
		{
			Release<T>(storage[i]);
			storage[i]=T();
		}
		used=0;
		LeaveCriticalSection(&cs_store);
	}
	void Remove(size_t index)
	{
		if (index>=used) return;
		Release<T>(storage[index]);
		for (size_t i=index;i<used;i++)
			storage[i]=storage[i+1];
		used--;
	}
	void ClearMemory(size_t index, size_t count)
	{
		if (index+count<=used)
		{
			memset(storage+index,0,sizeof(T)*count);
		}
	}
	void AddToStore(T* con,size_t amount)
	{
		if (amount<=0||con==0) return;
		EnterCriticalSection(&cs_store);
		if (amount+used+2>=size)
		{
			while (amount+used+2>=size) size<<=1;
			T* temp;
			if (size*sizeof(T)<0x100000)
			{
				temp=new T[size];
				memcpy(temp,storage,used*sizeof(T));
			}
			else
			{
				size=default_size;
				temp=new T[size];
				used=0;
			}
			delete []storage;
			storage=temp;
		}
		memcpy(storage+used,con,amount*sizeof(T));
		used+=amount;
		LeaveCriticalSection(&cs_store);
	}
	size_t Find(const T& item, size_t start=0, DWORD control=0)
	{
		size_t c=-1;
		for (size_t i=start;i<used;i++)
			if (fCmp(storage[i],item,control)) {c=i;break;}
			//if (storage[i]==item) {c=i;break;}
		return c;
	}
	inline size_t Used() const {return used;}
	inline T* Storage() const {return storage;}
protected:
	CRITICAL_SECTION cs_store;
	size_t size, used;
	T *storage;
	fComp fCmp;
};

#ifndef ITH_STACK
#define ITH_STACK
template<class T, size_t default_size>
class MyStack
{
public:
	MyStack(): index(0) {}
	void push_back(const T& e)
	{
		if (index<default_size)
		s[index++]=e;
	}
	void pop_back()
	{
		index--;
	}
	T& back()
	{
		return s[index-1];
	}
	T& operator[](size_t i) {return s[i];}
	size_t size() {return index;}
private:
	size_t index;
	T s[default_size];
};
#endif