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


#include <winsock2.h>
#include <intrin.h>
#include "socket.h"
#include <ITH\IHF_SYS.h>
TransportSocket::~TransportSocket()
{
	close();
}
int TransportSocket::socket()
{
	int s = _InterlockedExchange((long*)&sock,1);
	if (s == 0)
	{
		s = ::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
		if (s != INVALID_SOCKET) sock = s;
		return s;
	}
	else sock = 0;
	return -1;
}

int TransportSocket::connect( char* server, int port )
{
	if (port == 0) port = 80;

	unsigned long addr = 0;
	if (dns) addr = dns->GetAddress(server);
	if (addr == 0)
	{
		unsigned long ip1,ip2,ip3,ip4;
		if (sscanf(server,"%d.%d.%d.%d",&ip1,&ip2,&ip3,&ip4) == 4)
		{
			addr |= ip4;
			addr <<= 8;
			addr |= ip3;
			addr <<= 8;
			addr |= ip2;
			addr <<= 8;
			addr |= ip1;
		}
		else
		{
			hostent* host = gethostbyname(server);
			if (host == 0) return -1;
			addr = *(ULONG*)host->h_addr_list[0];
			dns->Insert(server,addr);
		}
	}
	sockaddr_in remote;
	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = addr;
	remote.sin_port = htons(port);
	return ::connect(sock, (struct sockaddr *)&remote, sizeof(struct sockaddr));
}

int TransportSocket::close()
{
	int s = _InterlockedExchange((long*)&sock,0);
	if (s == 0) return 0;
	shutdown(s, SD_BOTH);
	//Wait for gracefully shutdown. In normal network condition TCP should shutdown in 1 sec.
	//As only (20(IP) + 20(TCP)) * 2(FIN&ACK, ACK) = 80 bytes needed to be transmitted.
	LARGE_INTEGER sleep_time = {-10000000, -1};
	NtDelayExecution(0,&sleep_time);
	return closesocket(s);
}

int TransportSocket::send( void* data, int len )
{
	return ::send(sock,(char*)data,len,0);
}

int TransportSocket::recv( void* data, int len )
{
	return ::recv(sock,(char*)data,len,0);
}

void DNSCache::SetAddress(char* server, unsigned long addr)
{
	Insert(server, addr);
}

unsigned long DNSCache::GetAddress(char* server)
{
	TreeNode<char*,unsigned long>* node;
	node = Search(server);
	if (node == 0) return 0;
	return node->data;
}