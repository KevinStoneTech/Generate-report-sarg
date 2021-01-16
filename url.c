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
#ifdef HAVE_PCRE_H
#include <pcre.h>
#define USE_PCRE
#endif

/*!
A host name and the name to report.
*/
struct hostalias_name
{
	//! The next host name in the list or NULL for the last item.
	struct hostalias_name *Next;
	//! The minimum length of a candidate host name.
	int MinLen;
	//! The length of the constant part at the beginning of the mask.
	int PrefixLen;
	//! The length of the constant part at the end of the mask.
	int SuffixLen;
	//! The first part of the mask of the host name.
	const char *HostName_Prefix;
	//! The second part of the mask of the host name.
	const char *HostName_Suffix;
	//! The replacement name.
	const char *Alias;
};

/*!
An IPv4 address and the name to report.
*/
struct hostalias_ipv4
{
	//! The next host name in the list or NULL for the last item.
	struct hostalias_ipv4 *Next;
	//! The IP address.
	unsigned char Ip[4];
	//! The number of bits in the prefix.
	int NBits;
	//! The replacement name.
	const char *Alias;
};

/*!
An IPv6 address and the name to report.
*/
struct hostalias_ipv6
{
	//! The next host name in the list or NULL for the last item.
	struct hostalias_ipv6 *Next;
	//! The IP address.
	unsigned short Ip[8];
	//! The number of bits in the prefix.
	int NBits;
	//! The replacement name.
	const char *Alias;
};

#ifdef USE_PCRE
/*!
A regular expression.
*/
struct hostalias_regex
{
	//! The next regular expression to test.
	struct hostalias_regex *Next;
	//! The regular expression to match against the host name.
	pcre *Re;
	//! The replacement name.
	const char *Alias;
	//! \c True if this regular expression contains at least one subpattern
	bool SubPartern;
};
#endif

//! The first host name.
static struct hostalias_name *FirstAliasName=NULL;
//! The first IPv4 address.
static struct hostalias_ipv4 *FirstAliasIpv4=NULL;
//! The first IPv§ address.
static struct hostalias_ipv6 *FirstAliasIpv6=NULL;

#ifdef USE_PCRE
static struct hostalias_regex *FirstAliasRe=NULL;
#endif

/*!
  Store a name to alias.

  \param name The name to match including the wildcard.
  \param next A pointer to the first character after the name.

  \retval 1 Alias added.
  \retval 0 Ignore the line.
  \retval -1 Error.
 */
static int Alias_StoreName(const char *name,const char *next)
{
	const char *NameBegin;
	const char *NameBeginE;
	const char *NameEnd;
	const char *NameEndE;
	const char *Replace;
	const char *ReplaceE;
	const char *str;
	char sep;
	struct hostalias_name *alias;
	struct hostalias_name *new_alias;
	struct hostalias_name *prev_alias;
	char *tmp;
	int len;

	if (*name=='#' || *name==';') return(0);

	// get host name and split at the wildcard
	NameBegin=name;
	for (str=NameBegin ; str<next && (unsigned char)*str>' ' && *str!='*' ; str++);
	NameBeginE=str;
	if (NameBegin==NameBeginE) NameBegin=NULL;
	if (str<next && *str=='*') {
		NameEnd=++str;
		while (str<next && (unsigned char)*str>' ') {
			if (*str=='*') {
				debuga(__FILE__,__LINE__,_("Host name alias \"%s*%s\" contains too many wildcards (*)\n"),NameBegin,NameEnd);
				return(-1);
			}
			str++;
		}
		NameEndE=str;
		if (NameEnd==NameEndE) {
			debuga(__FILE__,__LINE__,_("Host name alias \"%*s\" must not end with a wildcard\n"),(int)(next-name),name);
			return(-1);
		}
	} else {
		NameEnd=NULL;
	}
	while (str<next && (unsigned char)*str<=' ') str++;
	if (!NameBegin && !NameEnd) return(0);

	// get the alias
	sep=*next;
	if (sep==' ' || sep=='\t') {
		Replace=next;
		while (*Replace==' ' || *Replace=='\t') Replace++;
		if ((unsigned char)*Replace<' ') {
			Replace=NULL;
		} else {
			for (str=Replace ; *str && (unsigned char)*str>=' ' ; str++);
			ReplaceE=str;
		}
	} else
		Replace=NULL;

	if (NameBegin) {
		len=(int)(NameBeginE-NameBegin);
		tmp=malloc(len+1);
		if (!tmp) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
			return(-1);
		}
		memcpy(tmp,NameBegin,len);
		tmp[len]='\0';
		NameBegin=tmp;
	}
	if (NameEnd) {
		len=(int)(NameEndE-NameEnd);
		tmp=malloc(len+1);
		if (!tmp) {
			if (NameBegin) free((void*)NameBegin);
			debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
			return(-1);
		}
		memcpy(tmp,NameEnd,len);
		tmp[len]='\0';
		NameEnd=tmp;
	}

	// ignore duplicates
	prev_alias=NULL;
	for (alias=FirstAliasName ; alias ; alias=alias->Next) {
		if (((NameBegin && alias->HostName_Prefix && !strcmp(NameBegin,alias->HostName_Prefix)) || (!NameBegin && !alias->HostName_Prefix)) &&
		    ((NameEnd && alias->HostName_Suffix && !strcmp(NameEnd,alias->HostName_Suffix)) || (!NameEnd && !alias->HostName_Suffix))) {
			if (NameBegin) free((void*)NameBegin);
			return(0);
		}
		prev_alias=alias;
	}

	// insert into the list
	new_alias=malloc(sizeof(*new_alias));
	if (!new_alias) {
		if (NameBegin) free((void*)NameBegin);
		if (NameEnd) free((void*)NameEnd);
		debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
		return(-1);
	}
	new_alias->MinLen=0;
	if (NameBegin) {
		new_alias->HostName_Prefix=NameBegin;
		new_alias->MinLen+=strlen(NameBegin);
		new_alias->PrefixLen=strlen(NameBegin);
	} else {
		new_alias->HostName_Prefix=NULL;
		new_alias->PrefixLen=0;
	}
	if (NameEnd) {
		new_alias->HostName_Suffix=NameEnd;
		new_alias->MinLen+=strlen(NameEnd)+1;
		new_alias->SuffixLen=strlen(NameEnd);
	} else {
		new_alias->HostName_Suffix=NULL;
		new_alias->SuffixLen=0;
	}
	if (Replace) {
		len=(int)(ReplaceE-Replace);
		tmp=malloc(len+2);
		if (!tmp) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
			return(-1);
		}
		tmp[0]=ALIAS_PREFIX;
		memcpy(tmp+1,Replace,len);
		tmp[len+1]='\0';
		new_alias->Alias=tmp;
	} else {
		tmp=malloc(new_alias->MinLen+2);
		if (!tmp) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
			return(-1);
		}
		tmp[0]=ALIAS_PREFIX;
		if (new_alias->HostName_Prefix) strcpy(tmp+1,new_alias->HostName_Prefix);
		if (new_alias->HostName_Suffix) {
			tmp[new_alias->PrefixLen+1]='*';
			strcpy(tmp+new_alias->PrefixLen+2,new_alias->HostName_Suffix);
		}
		new_alias->Alias=tmp;
	}

	new_alias->Next=NULL;
	if (prev_alias)
		prev_alias->Next=new_alias;
	else
		FirstAliasName=new_alias;
	return(1);
}

/*!
  Store a IPv4 to alias.

  \param ipv4 The IPv4 to match.
  \param nbits The number of bits in the prefix
  \param next A pointer to the first character after the address.

  \retval 1 Alias added.
  \retval 0 Ignore the line.
  \retval -1 Error.
 */
static int Alias_StoreIpv4(unsigned char *ipv4,int nbits,const char *next)
{
	const char *Replace;
	const char *ReplaceE;
	const char *str;
	struct hostalias_ipv4 *alias;
	struct hostalias_ipv4 *new_alias;
	struct hostalias_ipv4 *prev_alias;
	int i;
	char *tmp;
	int len;

	// get the alias
	Replace=next;
	while (*Replace==' ' || *Replace=='\t') Replace++;
	if ((unsigned char)*Replace<' ') {
		Replace=NULL;
	} else {
		for (str=Replace ; *str && (unsigned char)*str>=' ' ; str++);
		ReplaceE=str;
	}

	// store more restrictive range first
	prev_alias=NULL;
	for (alias=FirstAliasIpv4 ; alias ; alias=alias->Next) {
		i=(nbits<alias->NBits) ? nbits : alias->NBits;
		if ((i<8 || memcmp(ipv4,alias->Ip,i/8)==0) && ((i%8)==0 || (ipv4[i/8] ^ alias->Ip[i/8]) & (0xFFU<<(8-i%8)))==0) {
			break;
		}
		prev_alias=alias;
	}

	// insert into the list
	new_alias=malloc(sizeof(*new_alias));
	if (!new_alias) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
		return(-1);
	}
	memcpy(new_alias->Ip,ipv4,4);
	new_alias->NBits=nbits;
	if (Replace) {
		len=(int)(ReplaceE-Replace);
		tmp=malloc(len+2);
		if (!tmp) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
			return(-1);
		}
		tmp[0]=ALIAS_PREFIX;
		memcpy(tmp+1,Replace,len);
		tmp[len+1]='\0';
		new_alias->Alias=tmp;
	} else {
		tmp=malloc(5*4+1);
		if (!tmp) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
			return(-1);
		}
		sprintf(tmp,"%c%d.%d.%d.%d/%d",ALIAS_PREFIX,ipv4[0],ipv4[1],ipv4[2],ipv4[3],nbits);
		new_alias->Alias=tmp;
	}

	if (prev_alias) {
		new_alias->Next=prev_alias->Next;
		prev_alias->Next=new_alias;
	} else {
		new_alias->Next=NULL;
		FirstAliasIpv4=new_alias;
	}
	return(1);
}

/*!
  Store a IPv6 to alias.

  \param ipv6 The IPv6 to match.
  \param nbits The number of bits in the prefix
  \param next A pointer to the first character after the address.

  \retval 1 Alias added.
  \retval 0 Ignore the line.
  \retval -1 Error.
 */
static int Alias_StoreIpv6(unsigned short *ipv6,int nbits,const char *next)
{
	const char *Replace;
	const char *ReplaceE;
	const char *str;
	struct hostalias_ipv6 *alias;
	struct hostalias_ipv6 *new_alias;
	struct hostalias_ipv6 *prev_alias;
	int i;
	char *tmp;
	int len;

	// get the alias
	Replace=next;
	while (*Replace==' ' || *Replace=='\t') Replace++;
	if ((unsigned char)*Replace<' ') {
		Replace=NULL;
	} else {
		for (str=Replace ; *str && (unsigned char)*str>=' ' ; str++);
		ReplaceE=str;
	}

	// store more restrictive range first
	prev_alias=NULL;
	for (alias=FirstAliasIpv6 ; alias ; alias=alias->Next) {
		i=(nbits<alias->NBits) ? nbits : alias->NBits;
		if ((i<16 || memcmp(ipv6,alias->Ip,i/16*2)==0) && ((i%16)==0 || (ipv6[i/16] ^ alias->Ip[i/16]) & (0xFFFFU<<(16-i%16)))==0) {
			break;
		}
		prev_alias=alias;
	}

	// insert into the list
	new_alias=malloc(sizeof(*new_alias));
	if (!new_alias) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
		return(-1);
	}
	memcpy(new_alias->Ip,ipv6,8*sizeof(unsigned short int));
	new_alias->NBits=nbits;
	if (Replace) {
		len=ReplaceE-Replace;
		tmp=malloc(len+2);
		if (!tmp) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
			return(-1);
		}
		tmp[0]=ALIAS_PREFIX;
		memcpy(tmp+1,Replace,len);
		tmp[len+1]='\0';
		new_alias->Alias=tmp;
	} else {
		tmp=malloc(5*8+5);
		if (!tmp) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
			return(-1);
		}
		sprintf(tmp,"%c%x:%x:%x:%x:%x:%x:%x:%x/%d",ALIAS_PREFIX,ipv6[0],ipv6[1],ipv6[2],ipv6[3],ipv6[4],ipv6[5],ipv6[6],ipv6[7],nbits);
		new_alias->Alias=tmp;
	}

	if (prev_alias) {
		new_alias->Next=prev_alias->Next;
		prev_alias->Next=new_alias;
	} else {
		new_alias->Next=NULL;
		FirstAliasIpv6=new_alias;
	}
	return(1);
}

#ifdef USE_PCRE
/*!
Store a regular expression to match the alias.

\retval 1 Alias added.
\retval 0 Ignore the line.
\retval -1 Error.
*/
static int Alias_StoreRegexp(char *buf)
{
	char Delimiter;
	char *End;
	struct hostalias_regex *alias;
	struct hostalias_regex *new_alias;
	struct hostalias_regex **prev_alias;
	const char *PcreError;
	int ErrorOffset;
	char *Replace;
	int len;
	char *tmp;
	int i;

	// find the pattern
	Delimiter=*buf++;
	for (End=buf ; *End && *End!=Delimiter ; End++) {
		if (*End=='\\') {
			if (End[1]=='\0') {
				debuga(__FILE__,__LINE__,_("Invalid NUL character found in regular expression\n"));
				return(-1);
			}
			End++; //ignore the escaped character
		}
	}
	if (*End!=Delimiter) {
		debuga(__FILE__,__LINE__,_("Unterminated regular expression\n"));
		return(-1);
	}
	*End++='\0';

	// find the alias
	for (Replace=End ; *Replace==' ' || *Replace=='\t' ; Replace++);
	for (End=Replace ; *End && (unsigned char)*End>' ' ; End++);
	*End='\0';

	// store it
	new_alias=malloc(sizeof(*new_alias));
	if (!new_alias) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
		return(-1);
	}
	new_alias->Next=NULL;
	new_alias->Re=pcre_compile(buf,0,&PcreError,&ErrorOffset,NULL);
	if (new_alias->Re==NULL) {
		debuga(__FILE__,__LINE__,_("Failed to compile the regular expression \"%s\": %s\n"),buf,PcreError);
		free(new_alias);
		return(-1);
	}
	len=strlen(Replace);
	tmp=malloc(len+2);
	if (!tmp) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
		pcre_free(new_alias->Re);
		return(-1);
	}
	tmp[0]=ALIAS_PREFIX;
	memcpy(tmp+1,Replace,len);
	tmp[len+1]='\0';
	new_alias->Alias=tmp;

	new_alias->SubPartern=false;
	for (i=1 ; tmp[i] ; i++)
		// both the sed \1 and the perl $1 replacement operators are accepted
		if ((tmp[i]=='\\' || tmp[i]=='$') && isdigit(tmp[i+1])) {
			new_alias->SubPartern=true;
			break;
		}

	// chain it
	prev_alias=&FirstAliasRe;
	for (alias=FirstAliasRe ; alias ; alias=alias->Next)
		prev_alias=&alias->Next;
	*prev_alias=new_alias;

	return(1);
}
#endif

/*!
Store an alias in the corresponding list.

\param buf The string to parse and store.

\retval 0 No error.
\retval -1 Error in file.
\retval -2 Unknown string type to store.
*/
static int Alias_Store(char *buf)
{
	int type;
	const char *name;
	unsigned char ipv4[4];
	unsigned short int ipv6[8];
	int nbits;
	const char *next;
	int Error=-2;

	if (strncasecmp(buf,"re:",3)==0) {
#ifdef USE_PCRE
		if (Alias_StoreRegexp(buf+3)<0)
			return(-1);
		return(0);
#else
		debuga(__FILE__,__LINE__,_("PCRE not compiled in therefore the regular expressions are not available in the host alias file\n"));
		return(-1);
#endif
	}
	type=extract_address_mask(buf,&name,ipv4,ipv6,&nbits,&next);
	if (type<0) {
		return(-1);
	}

	if (type==1) {
		Error=Alias_StoreName(name,next);
	} else if (type==2) {
		Error=Alias_StoreIpv4(ipv4,nbits,next);
	} else if (type==3) {
		Error=Alias_StoreIpv6(ipv6,nbits,next);
	}
	if (Error<0) return(-1);
	return(0);
}

/*!
Read the file containing the host names to alias in the report.

\param Filename The name of the file.
*/
void read_hostalias(const char *Filename)
{
	FileObject *fi;
	longline line;
	char *buf;

	if (debug) debuga(__FILE__,__LINE__,_("Reading host alias file \"%s\"\n"),Filename);
	fi=FileObject_Open(Filename);
	if (!fi) {
		debuga(__FILE__,__LINE__,_("Cannot read host name alias file \"%s\": %s\n"),Filename,FileObject_GetLastOpenError());
		exit(EXIT_FAILURE);
	}

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),Filename);
		exit(EXIT_FAILURE);
	}

	while ((buf=longline_read(fi,line)) != NULL) {
		if (Alias_Store(buf)<0) {
			debuga(__FILE__,__LINE__,_("While reading \"%s\"\n"),Filename);
			exit(EXIT_FAILURE);
		}
	}

	longline_destroy(&line);
	if (FileObject_Close(fi)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),Filename,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}

	if (debug) {
		struct hostalias_name *alias1;
		struct hostalias_ipv4 *alias4;
		struct hostalias_ipv6 *alias6;

		debuga(__FILE__,__LINE__,_("List of host names to alias:\n"));
		for (alias1=FirstAliasName ; alias1 ; alias1=alias1->Next) {
			if (alias1->HostName_Prefix && alias1->HostName_Suffix)
				debuga(__FILE__,__LINE__,_("  %s*%s => %s\n"),alias1->HostName_Prefix,alias1->HostName_Suffix,alias1->Alias);
			else if (alias1->HostName_Prefix)
				debuga(__FILE__,__LINE__,_("  %s => %s\n"),alias1->HostName_Prefix,alias1->Alias);
			else
				debuga(__FILE__,__LINE__,_("  *%s => %s\n"),alias1->HostName_Suffix,alias1->Alias);
		}
		for (alias4=FirstAliasIpv4 ; alias4 ; alias4=alias4->Next) {
			debuga(__FILE__,__LINE__,_("  %d.%d.%d.%d/%d => %s\n"),alias4->Ip[0],alias4->Ip[1],alias4->Ip[2],alias4->Ip[3],alias4->NBits,alias4->Alias);
		}
		for (alias6=FirstAliasIpv6 ; alias6 ; alias6=alias6->Next) {
			debuga(__FILE__,__LINE__,_("  %x:%x:%x:%x:%x:%x:%x:%x/%d => %s\n"),alias6->Ip[0],alias6->Ip[1],alias6->Ip[2],alias6->Ip[3],
				alias6->Ip[4],alias6->Ip[5],alias6->Ip[6],alias6->Ip[7],alias6->NBits,alias6->Alias);
		}
	}
}

/*!
Free the memory allocated by read_hostalias().
*/
void free_hostalias(void)
{
	{
		struct hostalias_name *alias1;
		struct hostalias_name *next1;

		for (alias1=FirstAliasName ; alias1 ; alias1=next1) {
			next1=alias1->Next;
			if (alias1->HostName_Prefix) free((void *)alias1->HostName_Prefix);
			if (alias1->HostName_Suffix) free((void *)alias1->HostName_Suffix);
			free((void *)alias1->Alias);
			free(alias1);
		}
		FirstAliasName=NULL;
	}
	{
		struct hostalias_ipv4 *alias4;
		struct hostalias_ipv4 *next4;

		for (alias4=FirstAliasIpv4 ; alias4 ; alias4=next4) {
			next4=alias4->Next;
			free((void *)alias4->Alias);
			free(alias4);
		}
		FirstAliasIpv4=NULL;
	}
	{
		struct hostalias_ipv6 *alias6;
		struct hostalias_ipv6 *next6;

		for (alias6=FirstAliasIpv6 ; alias6 ; alias6=next6) {
			next6=alias6->Next;
			free((void *)alias6->Alias);
			free(alias6);
		}
		FirstAliasIpv6=NULL;
	}
#ifdef USE_PCRE
	{
		struct hostalias_regex *alias;
		struct hostalias_regex *next;

		for (alias=FirstAliasRe ; alias ; alias=next) {
			next=alias->Next;
			pcre_free(alias->Re);
			free((void *)alias->Alias);
			free(alias);
		}
		FirstAliasRe=NULL;
	}
#endif
}

/*!
Replace the host name by its alias if it is in our list.

\param url The host name.

\return The pointer to the host name or its alias.
*/
static const char *alias_url_name(const char *url,const char *next)
{
	struct hostalias_name *alias;
	int len;

	len=(int)(next-url);
	for (alias=FirstAliasName ; alias ; alias=alias->Next) {
		if (len<alias->MinLen) continue;
		if (alias->HostName_Prefix) {
			if (alias->HostName_Suffix) {
				if (strncasecmp(url,alias->HostName_Prefix,alias->PrefixLen)==0 &&
				    strncasecmp(url+(len-alias->SuffixLen),alias->HostName_Suffix,len)==0) {
					return(alias->Alias);
				}
			} else {
				if (len==alias->PrefixLen && strncasecmp(url,alias->HostName_Prefix,len)==0) {
					return(alias->Alias);
				}
			}
		} else if (strncasecmp(url+(len-alias->SuffixLen),alias->HostName_Suffix,len)==0) {
			return(alias->Alias);
		}
	}
	return(url);
}

/*!
Replace the IPv4 address by its alias if it is in our list.

\param url The host name.
\param ipv4 The address.

\return The pointer to the host name or its alias.
*/
static const char *alias_url_ipv4(const char *url,unsigned char *ipv4)
{
	struct hostalias_ipv4 *alias;
	int len;

	for (alias=FirstAliasIpv4 ; alias ; alias=alias->Next) {
		len=alias->NBits;
		if ((len<8 || memcmp(ipv4,alias->Ip,len/8)==0) && ((len%8)==0 || (ipv4[len/8] ^ alias->Ip[len/8]) & (0xFFU<<(8-len%8)))==0) {
			return(alias->Alias);
		}
	}
	return(url);
}

/*!
Replace the IPv6 address by its alias if it is in our list.

\param url The host name.
\param ipv6 The address.

\return The pointer to the host name or its alias.
*/
static const char *alias_url_ipv6(const char *url,unsigned short int *ipv6)
{
	struct hostalias_ipv6 *alias;
	int len;
	int i;

	for (alias=FirstAliasIpv6 ; alias ; alias=alias->Next) {
		len=alias->NBits;
		for (i=len/16-1 ; i>=0 && ipv6[i]==alias->Ip[i] ; i--);
		if (i>=0) continue;
		i=len/16;
		if (i>=8 || len%16==0 || ((ipv6[i] ^ alias->Ip[i]) & (0xFFFF<<(len-i*16)))==0) {
			return(alias->Alias);
		}
	}
	return(url);
}

#ifdef USE_PCRE
/*!
Replace the host name by its alias if it is in our list.

\param url_ptr A pointer to the host name to match. It is replaced
by a pointer to the alias if a match is found.

\return \c True if a match is found or \c false if it failed.

\warning The function is not thread safe as it may return a static
internal buffer.
*/
static bool alias_url_regex(const char **url_ptr)
{
	struct hostalias_regex *alias;
	int nmatches;
	const char *url;
	int url_len;
	int ovector[30];//size must be a multiple of 3
	static char Replacement[1024];
	const char *str;
	int i;
	int sub;
	int repl_idx;

	url=*url_ptr;
	url_len=strlen(url);
	for (alias=FirstAliasRe ; alias ; alias=alias->Next) {
		nmatches=pcre_exec(alias->Re,NULL,url,url_len,0,0,ovector,sizeof(ovector)/sizeof(ovector[0]));
		if (nmatches>=0) {
			if (nmatches==0) nmatches=(int)(sizeof(ovector)/sizeof(ovector[0]))/3*2; //only 2/3 of the vector is used by pcre_exec
			if (nmatches==1 || !alias->SubPartern) { //no subpattern to replace
				*url_ptr=alias->Alias;
			} else {
				repl_idx=0;
				str=alias->Alias;
				for (i=0 ; str[i] ; i++) {
					// both the sed \1 and the perl $1 replacement operators are accepted
					if ((str[i]=='\\' || str[i]=='$') && isdigit(str[i+1])) {
						sub=str[++i]-'0';
						if (sub>=1 && sub<=nmatches) {
							/*
							 * ovector[sub] is the start position of the match.
							 * ovector[sub+1] is the end position of the match.
							 */
							sub<<=1;
							if (repl_idx+ovector[sub+1]-ovector[sub]>=sizeof(Replacement)-1) break;
							memcpy(Replacement+repl_idx,url+ovector[sub],ovector[sub+1]-ovector[sub]);
							repl_idx+=ovector[sub+1]-ovector[sub];
							continue;
						}
					}
					if (repl_idx>=sizeof(Replacement)-1) break;
					Replacement[repl_idx++]=str[i];
				}
				Replacement[repl_idx]='\0';
				*url_ptr=Replacement;
			}
			return(true);
		}
	}
	return(false);
}
#endif

/*!
Find the beginning of the URL beyond the scheme://

\param url The url possibly containing a scheme.

\return The beginning of the url beyond the scheme.
*/
const char *skip_scheme(const char *url)
{
	const char *str;

	/*
	Skip any scheme:// at the beginning of the URL (see rfc2396 section 3.1).
	The underscore is not part of the standard but is found in the squid logs as cache_object://.
	*/
	for (str=url ; *str && (isalnum(*str) || *str=='+' || *str=='-' || *str=='.' || *str=='_') ; str++);
	if (str[0]==':' && str[1]=='/' && str[2]=='/') {
		url=str+3;
		while (*url=='/') url++;
	}
	return(url);
}

/*!
Get the part of the URL necessary to generate the report.

\param url The URL as extracted from the report.
\param full_url \c True to keep the whole URL. If \c false,
the URL is truncated to only keep the host name and port number.
*/
const char *process_url(const char *url,bool full_url)
{
	static char short_url[1024];
	int i;
	const char *start;
	int type;
	unsigned char ipv4[4];
	unsigned short int ipv6[8];
	const char *next;

	start=skip_scheme(url);
	if (!full_url) {
		for (i=0 ; i<sizeof(short_url)-1 && start[i] && start[i]!='/' && start[i]!='?' ; i++)
			short_url[i]=start[i];
		short_url[i]='\0';
		start=short_url;
#ifdef USE_PCRE
		if (FirstAliasRe) {
			if (alias_url_regex(&start)) return(start);
		}
#endif
		type=extract_address_mask(start,NULL,ipv4,ipv6,NULL,&next);
		if (type==1) {
			if (FirstAliasName)
				start=alias_url_name(start,next);
		} else if (type==2) {
			if (FirstAliasIpv4)
				start=alias_url_ipv4(start,ipv4);
		} else if (type==3) {
			if (FirstAliasIpv6)
				start=alias_url_ipv6(start,ipv6);
		}
	}
	return(start);
}

/*!
Extract the host name from the URL.

\param url The url whose host name must be extracted.
\param hostname The buffer to store the host name.
\param hostsize The size of the host name buffer.

\note The function is stupid at this time. It just searches for the first slash
in the URL and truncates the URL there. It doesn't take the protocol into account
nor the port number nor any user or password information.
*/
void url_hostname(const char *url,char *hostname,int hostsize)
{
	int i;

	hostsize--;
	for (i=0 ; i<hostsize && url[i] && url[i]!='/' ; i++)
		hostname[i]=url[i];
	hostname[i]='\0';
}

