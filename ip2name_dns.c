/*
 * SARG Squid Analysis Report Generator      http://sarg.sourceforge.net
 *                                                            1998, 2015
 *
 * SARG donations:
 *      please look at http://sarg.sourceforge.net/donations.php
 * Support:
 *     http://sourceforge.net/projects/sarg/forums/forum/363374
 * ---------------------------------------------------------------------
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "include/conf.h"
#include "include/defs.h"
#include "include/ip2name.h"
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h> //define getnameinfo on windows
#endif

static enum ip2name_retcode ip2name_dns(char *ip,int ip_len);

//! The functions to resolve an IP address through tne dns.
struct Ip2NameProcess Ip2NameDns=
{
	"dns",
	NULL,//no next item yet
	NULL,//no configuration
	ip2name_dns
};

/*!
Resolve the IP address using a reverse DNS entry.

\param ip The IP address. It is replaced by the corresponding name if one
can be found.
\param ip_len The length of the \c ip buffer.

\return One of the ::ip2name_retcode value.
*/
static enum ip2name_retcode ip2name_dns(char *ip,int ip_len)
{
#ifdef HAVE_GETNAMEINFO
	struct sockaddr_storage sa;
	int sockaddr_size;
	char host[NI_MAXHOST];
	int n1,n2,n3,n4,next=0;
	int error;

	memset(&sa,0,sizeof(sa));
	if (sscanf(ip,"%d.%d.%d.%d%n",&n1,&n2,&n3,&n4,&next)==4 && ip[next]=='\0') {
		struct sockaddr_in *s4=(struct sockaddr_in *)&sa;
		if (inet_pton(AF_INET,ip,&s4->sin_addr)!=1) return(INRC_Error);
		sa.ss_family=AF_INET;
		sockaddr_size=sizeof(*s4);
	} else {
		struct sockaddr_in6 *s6=(struct sockaddr_in6 *)&sa;
		if (inet_pton(AF_INET6,ip,&s6->sin6_addr)!=1) return(INRC_Error);
		sa.ss_family=AF_INET6;
		sockaddr_size=sizeof(*s6);
	}
#ifdef HAVE_SOCKADDR_SA_LEN
	sa.ss_len=sockaddr_size;
#endif
	error=getnameinfo((struct sockaddr *)&sa,sockaddr_size,host,sizeof(host),NULL,0,NI_NAMEREQD);
	if (error==EAI_AGAIN) {
		/*
		This is a temporary failure. According to the man page we should try again but
		it doesn't say if the program should wait before trying again nor how many attempts
		before it becomes a fatal error. I could find no clues on internet so I try once and
		leave it at that. Considering the number of IP addresses to resolve and the absence
		of serious consequences should some IP fail to be resolved properly, it is best
		not waste too much time on this.
		*/
		error=getnameinfo((struct sockaddr *)&sa,sizeof(sa),host,sizeof(host),NULL,0,NI_NAMEREQD);
	}
	if (error==EAI_NONAME)
		return(INRC_NotFound);
	if (error!=0) {
		debuga(__FILE__,__LINE__,_("IP to name resolution (getnameinfo) on IP address \"%s\" failed with error %d - %s\n"),ip,error,gai_strerror(error));
		return(INRC_Error);
	}
	safe_strcpy(ip,host,ip_len);
#else //HAVE_GETNAMEINFO
	struct in_addr addr;
	struct hostent *hp;
	char **p;
#ifdef __linux
	extern int h_errno;
#endif

#ifdef HAVE_INET_ATON
	if (inet_aton(ip,&addr) == 0)
		return(INRC_Error);
#else
	addr.s_addr=inet_addr(ip);
	if (addr.s_addr==-1) return(INRC_Error);
#endif

	hp = gethostbyaddr((void *)&addr, sizeof (addr), AF_INET);
	if (hp == NULL) {
		if (h_errno==HOST_NOT_FOUND)
			return(INRC_NotFound);
		return(INRC_Error);
	}

	for (p = hp->h_addr_list; *p != 0; p++) {
		struct in_addr in;

		(void) memcpy(&in.s_addr, *p, sizeof (in.s_addr));
		safe_strcpy(ip,hp->h_name,ip_len);
	}
#endif
	return(INRC_Found);
}

