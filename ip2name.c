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
#include "include/dichotomic.h"

//! Associate a name or alias to a module.
struct Ip2NameModules
{
	//! The name of the module
	const char *Name;
	//! The structure to access the module functions.
	struct Ip2NameProcess *Process;
};

extern struct Ip2NameProcess Ip2NameDns;
extern struct Ip2NameProcess Ip2NameExec;

//! The list of the modules available to resolve an IP address into a name.
static const struct Ip2NameModules ModulesList[]=
{
	{"dns",&Ip2NameDns},
	{"exec",&Ip2NameExec},
	{"yes",&Ip2NameDns},//for historical compatibility
	{"no",NULL},//does nothing for compatibility with previous versions
};

//! The chain of the configured modules to try to resolve an IP.
static struct Ip2NameProcess *FirstModule=NULL;
//! The list of the names found so far.
static DichotomicObject KnownIp=NULL;

/*!
Add a new module to the list of the configured modules.
*/
static void ip2name_chainmodule(struct Ip2NameProcess *Module)
{
	struct Ip2NameProcess *Chain;
	struct Ip2NameProcess *Last;

	if (debug) debuga(__FILE__,__LINE__,_("Chaining IP resolving module \"%s\"\n"),Module->Name);

	Last=NULL;
	for (Chain=FirstModule ; Chain ; Chain=Chain->Next) {
		if (Chain==Module) {
			debuga(__FILE__,__LINE__,_("Ignoring duplicate module \"%s\" to resolve an IP address\n"),Module->Name);
			return;
		}
		Last=Chain;
	}

	if (Last)
		Last->Next=Module;
	else {
		FirstModule=Module;
		Ip2Name=true;
	}
}

/*!
Add a new module to the list of the configured modules.

\param list The list of the modules name to chain.
*/
static void ip2name_buildmoduleslist(const char *list)
{
	const char *candidate;
	int length;
	int ModuleIdx;

	while (*list) {
		candidate=list;
		while (*candidate && (unsigned char)*candidate<=' ') candidate++;
		for (length=0 ; (unsigned char)candidate[length]>' ' ; length++);
		for (ModuleIdx=0 ; ModuleIdx<sizeof(ModulesList)/sizeof(*ModulesList) ; ModuleIdx++) {
			if (strncasecmp(candidate,ModulesList[ModuleIdx].Name,length)==0 && ModulesList[ModuleIdx].Name[length]=='\0') {
				// module found
				if (ModulesList[ModuleIdx].Process)
					ip2name_chainmodule(ModulesList[ModuleIdx].Process);
				break;
			}
		}
		if (ModuleIdx>=sizeof(ModulesList)/sizeof(*ModulesList)) {
			debuga(__FILE__,__LINE__,_("Unknown module \"%.*s\" to resolve the IP addresses\n"),length,candidate);
			exit(EXIT_FAILURE);
		}
		list=candidate+length;
	}
}

/*!
Configure a module whose name is given as an argument. The parameters to configure
follow the module name after one or more space or tabs.

\param module The name of the module, a space and the configuration options.
*/
static void ip2name_configmodule(const char *module)
{
	int length;
	unsigned int ModuleIdx;

	for (length=0 ; module[length] && (unsigned char)module[length]>' ' ; length++);
	for (ModuleIdx=0 ; ModuleIdx<sizeof(ModulesList)/sizeof(*ModulesList) ; ModuleIdx++) {
		if (strncasecmp(module,ModulesList[ModuleIdx].Name,length)==0 && ModulesList[ModuleIdx].Name[length]=='\0') {
			// module found
			if (ModulesList[ModuleIdx].Process) {
				if (!ModulesList[ModuleIdx].Process->Configure) {
					debuga(__FILE__,__LINE__,_("No option to configure for module %s\n"),ModulesList[ModuleIdx].Name);
					exit(EXIT_FAILURE);
				}
				while (module[length] && (unsigned char)module[length]<=' ') length++;
				ModulesList[ModuleIdx].Process->Configure(ModulesList[ModuleIdx].Name,module+length);
			}
			break;
		}
	}
}

/*!
Configure a module to resolve an IP address into a name.

\param param The parameter found in the configuration file.
It always begins after the "resolv_ip".

\retval 1 Parameter processed.
\retval 0 Parameter ignored.
*/
int ip2name_config(const char *param)
{
	// module to add to the list
	if (*param==' ') {
		ip2name_buildmoduleslist(param);
		return(1);
	}

	// parameter for a module?
	if (*param=='_') {
		ip2name_configmodule(param+1);
		return(1);
	}

	return(0);
}

/*!
Require the use of the DNS to resolve the IP addresses.
*/
void ip2name_forcedns(void)
{
	struct Ip2NameProcess *DnsModule=NULL;
	int i;
	struct Ip2NameProcess *Chain;
	struct Ip2NameProcess *Last;

	// find the dns module
	for (i=0 ; i<sizeof(ModulesList)/sizeof(*ModulesList) ; i++) {
		if (strcmp("dns",ModulesList[i].Name)==0) {
			// module found
			DnsModule=ModulesList[i].Process;
			break;
		}
	}
	if (!DnsModule) {
		debuga(__FILE__,__LINE__,_("No known module to resolve an IP address using the DNS\n"));
		exit(EXIT_FAILURE);
	}

	// add the module to the list if it isn't there yet
	Last=NULL;
	for (Chain=FirstModule ; Chain && Chain!=DnsModule ; Chain=Chain->Next) {
		Last=Chain;
	}
	if (debug) debuga(__FILE__,__LINE__,_("Chaining IP resolving module \"%s\"\n"),DnsModule->Name);
	if (Last)
		Last->Next=DnsModule;
	else {
		FirstModule=DnsModule;
		Ip2Name=true;
	}
}

/*!
Convert an IP address into a name.

\param ip The IP address. It is replaced by the corresponding name if one
can be found.
\param ip_len The length of the \c ip buffer.

The function does nothing if no module are configured.
*/
void ip2name(char *ip,int ip_len)
{
	struct Ip2NameProcess *Module;
	enum ip2name_retcode Status;
	const char *Name;
	char OrigIp[80];

	if (!KnownIp) {
		KnownIp=Dichotomic_Create();
		if (!KnownIp) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store the names corresponding to the IP address\n"));
			exit(EXIT_FAILURE);
		}
	}

	Name=Dichotomic_Search(KnownIp,ip);
	if (Name) {
		safe_strcpy(ip,Name,ip_len);
		return;
	}

	safe_strcpy(OrigIp,ip,sizeof(OrigIp));
	for (Module=FirstModule ; Module ; Module=Module->Next) {
		if (Module->Resolve) {
			Status=Module->Resolve(ip,ip_len);
			if (Status==INRC_Found) break;
		}
	}
	Dichotomic_Insert(KnownIp,OrigIp,ip);
}

/*!
Release the memory allocated to resolve the IP addresses
into names.
*/
void ip2name_cleanup(void)
{
	Dichotomic_Destroy(&KnownIp);
}

void name2ip(char *name,int name_size)
{
#ifdef HAVE_GETADDRINFO
	int error;
	char *port;
	struct addrinfo *res=NULL;
	char *addr;

	addr=name;
	if (name[0]=='[') { //IPv6 address
		port=strchr(name,']');
		if (port) { //confirmed IPv6 address
			*port='\0';
			addr++;
		}
	} else { //IPv4 address
		port=strchr(name,':');
		if (port) *port='\0';
	}

	error=getaddrinfo(addr,NULL,NULL,&res);
	if (error) {
		if (res) freeaddrinfo(res);
		debuga(__FILE__,__LINE__,_("Cannot resolve host name \"%s\": %s\n"),name,gai_strerror(error));
	} else {
		if (res->ai_family==AF_INET) {
			struct sockaddr_in *s4=(struct sockaddr_in *)res->ai_addr;
			struct in_addr *sa=&s4->sin_addr;
			if (res->ai_addrlen<sizeof(*s4)) {
				debuga(__FILE__,__LINE__,_("Short structure returned by getaddrinfo for an IPv4 address: %d bytes instead of %d\n"),res->ai_addrlen,(int)sizeof(*s4));
				exit(EXIT_FAILURE);
			}
			inet_ntop(res->ai_family,sa,name,name_size);
		} else if (res->ai_family==AF_INET6) {
			struct sockaddr_in6 *s6=(struct sockaddr_in6 *)res->ai_addr;
			struct in6_addr *sa6=&s6->sin6_addr;
			if (res->ai_addrlen<sizeof(*s6)) {
				debuga(__FILE__,__LINE__,_("Short structure returned by getaddrinfo for an IPv6 address: %d bytes instead of %d\n"),res->ai_addrlen,(int)sizeof(*s6));
				exit(EXIT_FAILURE);
			}
			inet_ntop(res->ai_family,sa6,name,name_size);
		} else {
			debuga(__FILE__,__LINE__,_("Invalid address type %d returned when resolving host name \"%s\"\n"),res->ai_family,name);
		}
		freeaddrinfo(res);
	}
#else
	struct in_addr ia;
	struct hostent *hp;
	char *port;
	char n1[4];
	char n2[4];
	char n3[4];
	char n4[4];
	struct getwordstruct gwarea;

	port=strchr(name,':');
	if (port) *port='\0';

	if ((hp=gethostbyname(name))==NULL)
		return;

	memcpy(&ia.s_addr,hp->h_addr_list[0],sizeof(ia.s_addr));
	ia.s_addr=ntohl(ia.s_addr);
	getword_start(&gwarea,inet_ntoa(ia));
	if (getword(n4,sizeof(n4),&gwarea,'.')<0 || getword(n3,sizeof(n3),&gwarea,'.')<0 ||
	    getword(n2,sizeof(n2),&gwarea,'.')<0 || getword(n1,sizeof(n1),&gwarea,0)<0) {
		debuga(__FILE__,__LINE__,_("Invalid IPv4 address \"%s\"\n"),gwarea.beginning);
		exit(EXIT_FAILURE);
	}
	snprintf(name,name_size,"%s.%s.%s.%s",n1,n2,n3,n4);
#endif

	return;
}
