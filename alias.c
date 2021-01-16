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
#include "include/stringbuffer.h"
#include "include/alias.h"
#ifdef HAVE_PCRE_H
#include <pcre.h>
#define USE_PCRE 1
#endif

//! Longest alias name length including the terminating zero.
#define MAX_ALIAS_LEN 256

/*!
A host name and the name to report.
*/
struct aliasitem_name
{
	//! The minimum length of a candidate user name.
	int MinLen;
	//! Number of wildcards in the mask.
	int Wildcards;
	//! The mask of the user name.
	const char *Mask;
};

/*!
An IPv4 address and the name to report.
*/
struct aliasitem_ipv4
{
	//! The IP address.
	unsigned char Ip[4];
	//! The number of bits in the prefix.
	int NBits;
};

/*!
An IPv6 address and the name to report.
*/
struct aliasitem_ipv6
{
	//! The IP address.
	unsigned short Ip[8];
	//! The number of bits in the prefix.
	int NBits;
};

#ifdef USE_PCRE
/*!
A regular expression.
*/
struct aliasitem_regex
{
	//! The regular expression to match against the name.
	pcre *Re;
	//! \c True if this regular expression contains at least one subpattern
	bool SubPartern;
};
#endif

//! Type of grouping criterion.
enum aliasitem_type
{
	ALIASTYPE_Name,
	ALIASTYPE_Ipv4,
	ALIASTYPE_Ipv6,
	ALIASTYPE_Pcre
};

//! \brief One item to group.
struct AliasItemStruct
{
	//! The next item in the list or NULL for the last item.
	struct AliasItemStruct *Next;
	//! What criterion to use to group the item.
	enum aliasitem_type Type;
	union
	{
		//! The alias of a name.
		struct aliasitem_name Name;
		//! The alias of an IPv4 address.
		struct aliasitem_ipv4 Ipv4;
		//! The alias of an IPv6 address.
		struct aliasitem_ipv6 Ipv6;
#ifdef USE_PCRE
		//! The alias of regular expression.
		struct aliasitem_regex Regex;
#endif
	};
	//! The replacement name.
	const char *Alias;
};

//! Object to group items together.
struct AliasStruct
{
	//! First item in the list.
	struct AliasItemStruct *First;
	//! Buffer to store the strings.
	StringBufferObject StringBuffer;
};

/*!
  Create an object to alias items.

  \return A pointer to the object or NULL if the
  creation failed.

  The returned pointer must be freed by Alias_Destroy().
 */
AliasObject Alias_Create(void)
{
	struct AliasStruct *Alias;

	Alias=calloc(1,sizeof(struct AliasStruct));
	if (!Alias) return(NULL);

	Alias->StringBuffer=StringBuffer_Create();
	if (!Alias->StringBuffer)
	{
		free(Alias);
		return(NULL);
	}

	return(Alias);
}

/*!
  Destroy the object created by Alias_Create().

  \param AliasPtr Pointer to the variable containing
  the alias. It is reset to NULL to prevent subsequent
  use of the pointer.
 */
void Alias_Destroy(AliasObject *AliasPtr)
{
	struct AliasStruct *Alias;
	struct AliasItemStruct *Item;

	if (!AliasPtr || !*AliasPtr) return;
	Alias=*AliasPtr;
	*AliasPtr=NULL;

	for (Item=Alias->First ; Item ; Item=Item->Next)
	{
		switch (Item->Type)
		{
			case ALIASTYPE_Name:
			case ALIASTYPE_Ipv4:
			case ALIASTYPE_Ipv6:
				break;

			case ALIASTYPE_Pcre:
#ifdef USE_PCRE
				pcre_free(Item->Regex.Re);
#endif
				break;
		}
	}

	StringBuffer_Destroy(&Alias->StringBuffer);
	free(Alias);
}


/*!
  Store a name to alias.

  \param name The name to match including the wildcard.
  \param next A pointer to the first character after the name.

  \retval 1 Alias added.
  \retval 0 Ignore the line.
  \retval -1 Error.
 */
static int Alias_StoreName(struct AliasStruct *AliasData,const char *name,const char *next)
{
	char Name[MAX_ALIAS_LEN];
	const char *Replace;
	const char *ReplaceE;
	const char *str;
	struct AliasItemStruct *alias;
	struct AliasItemStruct *new_alias;
	struct AliasItemStruct *prev_alias;
	int len;
	int minlen=0;
	int wildcards=0;
	bool in_wildcard=false;

	// get user name and count the wildcards
	len=0;
	for (str=name ; len<sizeof(Name)-1 && str<next ; str++)
	{
		if (*str=='*')
		{
			if (!in_wildcard)
			{
				Name[len++]=*str;
				wildcards++;
				in_wildcard=true;
			}
		}
		else
		{
			Name[len++]=tolower(*str);
			minlen++;
			in_wildcard=false;
		}
	}
	if (len==0) return(0);
	Name[len]='\0';

	// get the alias
	while (*str==' ' || *str=='\t') str++;
	Replace=str;
	while ((unsigned char)*str>=' ') str++;
	ReplaceE=str;
	if (Replace==ReplaceE) return(0);

	// ignore duplicates
	prev_alias=NULL;
	for (alias=AliasData->First ; alias ; alias=alias->Next) {
		if (alias->Type==ALIASTYPE_Name && !strcmp(Name,alias->Name.Mask)) {
			debuga(__FILE__,__LINE__,_("Duplicate aliasing directive for name %s\n"),Name);
			return(0);
		}
		prev_alias=alias;
	}

	// insert into the list
	new_alias=malloc(sizeof(*new_alias));
	if (!new_alias) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store the user name aliasing directives\n"));
		return(-1);
	}
	new_alias->Type=ALIASTYPE_Name;
	new_alias->Name.MinLen=minlen;
	new_alias->Name.Wildcards=wildcards;
	new_alias->Name.Mask=StringBuffer_Store(AliasData->StringBuffer,Name);
	if (!new_alias->Name.Mask) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store the user name aliasing directives\n"));
		free(new_alias);
		return(-1);
	}

	len=(int)(ReplaceE-Replace);
	new_alias->Alias=StringBuffer_StoreLength(AliasData->StringBuffer,Replace,len);
	if (!new_alias->Alias) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store the user name aliasing directives\n"));
		free(new_alias);
		return(-1);
	}

	new_alias->Next=NULL;
	if (prev_alias)
		prev_alias->Next=new_alias;
	else
		AliasData->First=new_alias;
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
static int Alias_StoreIpv4(struct AliasStruct *AliasData,unsigned char *ipv4,int nbits,const char *next)
{
	const char *Replace;
	const char *ReplaceE;
	const char *str;
	struct AliasItemStruct *alias;
	struct AliasItemStruct *new_alias;
	struct AliasItemStruct *prev_alias;
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

	// check for duplicate or broader range
	prev_alias=NULL;
	for (alias=AliasData->First ; alias ; alias=alias->Next) {
		if (alias->Type==ALIASTYPE_Ipv4 && nbits>=alias->Ipv4.NBits) {
			int byte=alias->Ipv4.NBits/8;
			int bit=alias->Ipv4.NBits%8;
			if ((byte<1 || memcmp(ipv4,alias->Ipv4.Ip,byte)==0) && (bit==0 || (ipv4[byte] ^ alias->Ipv4.Ip[byte]) & (0xFFU<<(8-bit)))==0) {
				if (nbits==alias->Ipv4.NBits)
					debuga(__FILE__,__LINE__,_("Duplicate aliasing directive for IPv4 address %d.%d.%d.%d/%d\n"),
						   ipv4[0],ipv4[1],ipv4[2],ipv4[3],nbits);
				else
					debuga(__FILE__,__LINE__,_("IPv4 aliasing directive ignored for IPv4 address %d.%d.%d.%d/%d as it is"
							 " narrower than a previous one (%d.%d.%d.%d/%d\n"),
						   ipv4[0],ipv4[1],ipv4[2],ipv4[3],nbits,
							alias->Ipv4.Ip[0],alias->Ipv4.Ip[1],alias->Ipv4.Ip[2],alias->Ipv4.Ip[3],
							alias->Ipv4.NBits);
				return(0);
			}
		}
		prev_alias=alias;
	}

	// insert into the list
	new_alias=malloc(sizeof(*new_alias));
	if (!new_alias) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
		return(-1);
	}
	new_alias->Type=ALIASTYPE_Ipv4;
	memcpy(new_alias->Ipv4.Ip,ipv4,4);
	new_alias->Ipv4.NBits=nbits;
	if (Replace) {
		char *tmp;

		len=(int)(ReplaceE-Replace);
		tmp=malloc(len+2);
		if (!tmp) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
			free(new_alias);
			return(-1);
		}
		tmp[0]=ALIAS_PREFIX;
		memcpy(tmp+1,Replace,len);
		tmp[len+1]='\0';
		new_alias->Alias=StringBuffer_Store(AliasData->StringBuffer,tmp);
		free(tmp);
	} else {
		char tmp[5*4+1];
		sprintf(tmp,"%c%d.%d.%d.%d/%d",ALIAS_PREFIX,ipv4[0],ipv4[1],ipv4[2],ipv4[3],nbits);
		new_alias->Alias=StringBuffer_Store(AliasData->StringBuffer,tmp);
	}
	if (!new_alias->Alias) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store the IPv4 aliasing directives\n"));
		free(new_alias);
		return(-1);
	}

	new_alias->Next=NULL;
	if (prev_alias)
		prev_alias->Next=new_alias;
	else
		AliasData->First=new_alias;
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
static int Alias_StoreIpv6(struct AliasStruct *AliasData,unsigned short *ipv6,int nbits,const char *next)
{
	const char *Replace;
	const char *ReplaceE;
	const char *str;
	struct AliasItemStruct *alias;
	struct AliasItemStruct *new_alias;
	struct AliasItemStruct *prev_alias;
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

	// check for duplicate or broader range
	prev_alias=NULL;
	for (alias=AliasData->First ; alias ; alias=alias->Next) {
		if (alias->Type==ALIASTYPE_Ipv6 && nbits>=alias->Ipv6.NBits) {
			int word=alias->Ipv6.NBits/16;
			int bit=alias->Ipv6.NBits%16;
			if ((word<1 || memcmp(ipv6,alias->Ipv6.Ip,word*2)==0) && (bit==0 || (ipv6[word] ^ alias->Ipv6.Ip[word]) & (0xFFFFU<<(16-bit)))==0) {
				if (nbits==alias->Ipv6.NBits)
					debuga(__FILE__,__LINE__,_("Duplicate aliasing directive for IPv6 address %x:%x:%x:%x:%x:%x:%x:%x/%d\n"),
						   ipv6[0],ipv6[1],ipv6[2],ipv6[3],ipv6[4],ipv6[5],ipv6[6],ipv6[7],nbits);
				else
					debuga(__FILE__,__LINE__,_("IPv6 aliasing directive ignored for IPv6 address %x:%x:%x:%x:%x:%x:%x:%x/%d as it is"
							 " narrower than a previous one (%x:%x:%x:%x:%x:%x:%x:%x/%d\n"),
						   ipv6[0],ipv6[1],ipv6[2],ipv6[3],ipv6[4],ipv6[5],ipv6[6],ipv6[7],nbits,
							alias->Ipv6.Ip[0],alias->Ipv6.Ip[1],alias->Ipv6.Ip[2],alias->Ipv6.Ip[3],alias->Ipv6.Ip[4],
							alias->Ipv6.Ip[5],alias->Ipv6.Ip[6],alias->Ipv6.Ip[7],alias->Ipv6.NBits);
				return(0);
			}
		}
		prev_alias=alias;
	}

	// insert into the list
	new_alias=malloc(sizeof(*new_alias));
	if (!new_alias) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
		return(-1);
	}
	new_alias->Type=ALIASTYPE_Ipv6;
	memcpy(new_alias->Ipv6.Ip,ipv6,8*sizeof(unsigned short int));
	new_alias->Ipv6.NBits=nbits;
	if (Replace) {
		char *tmp;
		len=ReplaceE-Replace;
		tmp=malloc(len+2);
		if (!tmp) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
			free(new_alias);
			return(-1);
		}
		tmp[0]=ALIAS_PREFIX;
		memcpy(tmp+1,Replace,len);
		tmp[len+1]='\0';
		new_alias->Alias=StringBuffer_Store(AliasData->StringBuffer,tmp);
		free(tmp);
	} else {
		char tmp[5*8+5];
		sprintf(tmp,"%c%x:%x:%x:%x:%x:%x:%x:%x/%d",ALIAS_PREFIX,ipv6[0],ipv6[1],ipv6[2],ipv6[3],ipv6[4],ipv6[5],ipv6[6],ipv6[7],nbits);
		new_alias->Alias=StringBuffer_Store(AliasData->StringBuffer,tmp);
	}
	if (!new_alias->Alias) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store the IPv6 aliasing directives\n"));
		free(new_alias);
		return(-1);
	}

	new_alias->Next=NULL;
	if (prev_alias)
		prev_alias->Next=new_alias;
	else
		AliasData->First=new_alias;
	return(1);
}

#ifdef USE_PCRE
/*!
Store a regular expression to match the alias.

\retval 1 Alias added.
\retval 0 Ignore the line.
\retval -1 Error.
*/
static int Alias_StoreRegexp(struct AliasStruct *AliasData,char *buf)
{
	char Delimiter;
	char *End;
	struct AliasItemStruct *alias;
	struct AliasItemStruct *new_alias;
	struct AliasItemStruct **prev_alias;
	const char *PcreError;
	int ErrorOffset;
	char *Replace;
	int len;
	char *tmp;
	int i;
	int ReOption=0;

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

	// get option: currently supported: i=case insensitive
	while (*End && isalpha(*End)) {
		if (*End=='i') {
			ReOption|=PCRE_CASELESS;
		} else {
			debuga(__FILE__,__LINE__,_("Invalid option character %c found after regular expression\n"),*End);
			return(-1);
		}
		End++;
	}

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
	new_alias->Type=ALIASTYPE_Pcre;
	new_alias->Next=NULL;
	new_alias->Regex.Re=pcre_compile(buf,ReOption,&PcreError,&ErrorOffset,NULL);
	if (new_alias->Regex.Re==NULL) {
		debuga(__FILE__,__LINE__,_("Failed to compile the regular expression \"%s\": %s\n"),buf,PcreError);
		free(new_alias);
		return(-1);
	}
	len=strlen(Replace);
	tmp=malloc(len+2);
	if (!tmp) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store the host name aliasing directives\n"));
		pcre_free(new_alias->Regex.Re);
		return(-1);
	}
	tmp[0]=ALIAS_PREFIX;
	memcpy(tmp+1,Replace,len);
	tmp[len+1]='\0';
	new_alias->Alias=StringBuffer_Store(AliasData->StringBuffer,tmp);
	free(tmp);
	if (!new_alias->Alias) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store the regex aliasing directives\n"));
		free(new_alias);
		return(-1);
	}

	new_alias->Regex.SubPartern=false;
	for (i=0 ; Replace[i] ; i++)
		// both the sed \1 and the perl $1 replacement operators are accepted
		if ((Replace[i]=='\\' || Replace[i]=='$') && isdigit(Replace[i+1])) {
			new_alias->Regex.SubPartern=true;
			break;
		}

	// chain it
	prev_alias=&AliasData->First;
	for (alias=AliasData->First ; alias ; alias=alias->Next)
		prev_alias=&alias->Next;
	*prev_alias=new_alias;

	return(1);
}
#endif

/*!
Store an alias in the corresponding list.

\param String The string to parse and store.

\retval 0 No error.
\retval -1 Error in file.
\retval -2 Unknown string type to store.
*/
int Alias_Store(struct AliasStruct *AliasData,char *String)
{
	int type;
	const char *name;
	unsigned char ipv4[4];
	unsigned short int ipv6[8];
	int nbits;
	const char *next;
	int Error=-2;

	if (*String=='#' || *String==';') return(0);

	if (strncasecmp(String,"re:",3)==0) {
#ifdef USE_PCRE
		if (Alias_StoreRegexp(AliasData,String+3)<0)
			return(-1);
#else
		debuga(__FILE__,__LINE__,_("PCRE not compiled in therefore the regular expressions are not available to alias items\n"));
		return(-1);
#endif
	}
	else
	{
		type=extract_address_mask(String,&name,ipv4,ipv6,&nbits,&next);
		if (type==1) {
			Error=Alias_StoreName(AliasData,name,next);
		} else if (type==2) {
			Error=Alias_StoreIpv4(AliasData,ipv4,nbits,next);
		} else if (type==3) {
			Error=Alias_StoreIpv6(AliasData,ipv6,nbits,next);
		} else {
			return(-1);
		}
		if (Error<0) return(-1);
	}
	return(0);
}

/*!
  Print the list of the aliases stored in the object.

  \param AliasData Object created by Alias_Create() and
  containing the aliases stored by Alias_Store().
 */
void Alias_PrintList(struct AliasStruct *AliasData)
{
	struct AliasItemStruct *alias;

	for (alias=AliasData->First ; alias ; alias=alias->Next) {
		switch (alias->Type)
		{
			case ALIASTYPE_Name:
				debuga(__FILE__,__LINE__,_("  %s => %s\n"),alias->Name.Mask,alias->Alias);
				break;
			case ALIASTYPE_Ipv4:
				debuga(__FILE__,__LINE__,_("  %d.%d.%d.%d/%d => %s\n"),alias->Ipv4.Ip[0],alias->Ipv4.Ip[1],alias->Ipv4.Ip[2],
						alias->Ipv4.Ip[3],alias->Ipv4.NBits,alias->Alias);
				break;
			case ALIASTYPE_Ipv6:
				debuga(__FILE__,__LINE__,_("  %x:%x:%x:%x:%x:%x:%x:%x/%d => %s\n"),alias->Ipv6.Ip[0],alias->Ipv6.Ip[1],alias->Ipv6.Ip[2],
						alias->Ipv6.Ip[3],alias->Ipv6.Ip[4],alias->Ipv6.Ip[5],alias->Ipv6.Ip[6],alias->Ipv6.Ip[7],
						alias->Ipv6.NBits,alias->Alias);
				break;
			case ALIASTYPE_Pcre:
				debuga(__FILE__,__LINE__,_("  Re => %s\n"),alias->Alias);
				break;
		}
	}
}

/*!
Replace the name by its alias if it is in our list.

\param name The name to find in the list.

\return The pointer to the name or its alias.
*/
static bool Alias_MatchName(struct AliasItemStruct *alias,const char *name,int len)
{
	int k;
	const char *Searched;
	const char *Candidate;

	if (!alias->Name.Wildcards)
	{
		if (len!=alias->Name.MinLen) return(false);
		return(strcmp(name,alias->Name.Mask)==0);
	}
	if (len<alias->Name.MinLen) return(false);
	Candidate=name;
	Searched=alias->Name.Mask;
	if (Searched[0]!='*')
	{
		while (*Searched && *Candidate && *Searched!='*')
		{
			if (Searched[0]!=Candidate[0]) return(false);
			Searched++;
			Candidate++;
		}
	}
	if (Searched[0]=='*') Searched++;
	while (Searched[0] && Candidate[0])
	{
		while (Candidate[0] && Candidate[0]!=Searched[0]) Candidate++;
		for (k=0 ; Candidate[k] && Searched[k] && Searched[k]!='*' && Searched[k]==Candidate[k] ; k++);
		if (Candidate[k]=='\0')
		{
			return(Searched[k]=='\0' || (Searched[k]=='*' && Searched[k+1]=='\0'));
		}
		if (Searched[k]=='\0') return(false);
		if (Searched[k]=='*')
		{
			Searched+=k+1;
			Candidate+=k;
		}
		else
			Candidate++;
	}
	return(Searched[0]=='\0');
}

/*!
Replace the IPv4 address by its alias if it is in our list.

\param url The host name.
\param ipv4 The address.

\return The pointer to the host name or its alias.
*/
static bool Alias_MatchIpv4(struct AliasItemStruct *alias,unsigned char *ipv4)
{
	int len;
	int n,m;

	len=alias->Ipv4.NBits;
	n=len/8;
	m=len%8;
	if (n>0 && memcmp(ipv4,alias->Ipv4.Ip,n)!=0) return(false);
	if (m!=0 && ((ipv4[n] ^ alias->Ipv4.Ip[n]) & (0xFFU<<(8-m)))!=0) return(false);
	return(true);
}

/*!
Replace the IPv6 address by its alias if it is in our list.

\param url The host name.
\param ipv6 The address.

\return The pointer to the host name or its alias.
*/
static bool Alias_MatchIpv6(struct AliasItemStruct *alias,unsigned short int *ipv6)
{
	int len;
	int i;

	len=alias->Ipv6.NBits;
	for (i=len/16-1 ; i>=0 && ipv6[i]==alias->Ipv6.Ip[i] ; i--);
	if (i<0) {
		i=len/16;
		if (i>=8 || len%16==0 || ((ipv6[i] ^ alias->Ipv6.Ip[i]) & (0xFFFF<<(len-i*16)))==0) {
			return(true);
		}
	}
	return(false);
}

#ifdef USE_PCRE
/*!
Replace the host name by its alias if it is in our list.

\param url_ptr A pointer to the host name to match. It is replaced
by a pointer to the alias if a match is found.

\return A pointer to the replacement string or NULL if the regex
doesn't match.

\warning The function is not thread safe as it may return a static
internal buffer.
*/
static const char *Alias_MatchRegex(struct AliasItemStruct *alias,const char *name)
{
	int nmatches;
	int len;
	int ovector[30];//size must be a multiple of 3
	static char Replacement[1024];
	const char *str;
	int i;
	int sub;
	int repl_idx;

	len=strlen(name);
	nmatches=pcre_exec(alias->Regex.Re,NULL,name,len,0,0,ovector,sizeof(ovector)/sizeof(ovector[0]));
	if (nmatches<0) return(NULL);

	if (nmatches==0) nmatches=(int)(sizeof(ovector)/sizeof(ovector[0]))/3*2; //only 2/3 of the vector is used by pcre_exec
	if (nmatches==1 || !alias->Regex.SubPartern) { //no subpattern to replace
		return(alias->Alias);
	}

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
				memcpy(Replacement+repl_idx,name+ovector[sub],ovector[sub+1]-ovector[sub]);
				repl_idx+=ovector[sub+1]-ovector[sub];
				continue;
			}
		}
		if (repl_idx>=sizeof(Replacement)-1) break;
		Replacement[repl_idx++]=str[i];
	}
	Replacement[repl_idx]='\0';
	return(Replacement);
}
#endif

const char *Alias_Replace(struct AliasStruct *AliasData,const char *Name)
{
	struct AliasItemStruct *alias;
	int type;
	unsigned char ipv4[4];
	unsigned short int ipv6[8];
	int len;
	char lname[MAX_ALIAS_LEN];

	if (!AliasData) return(Name);
	for (len=0 ; len<sizeof(lname)-1 && Name[len] ; len++) lname[len]=tolower(Name[len]);
	lname[len]='\0';

	type=extract_address_mask(Name,NULL,ipv4,ipv6,NULL,NULL);

	for (alias=AliasData->First ; alias ; alias=alias->Next) {
		if (type==2) {
			if (alias->Type==ALIASTYPE_Ipv4 && Alias_MatchIpv4(alias,ipv4))
				return(alias->Alias);
		}
		if (type==3) {
			if (alias->Type==ALIASTYPE_Ipv6 && Alias_MatchIpv6(alias,ipv6))
				return(alias->Alias);
		}
#ifdef USE_PCRE
		if (alias->Type==ALIASTYPE_Pcre) {
			const char *Result=Alias_MatchRegex(alias,Name);
			if (Result) return(Result);
		}
#endif
		if (alias->Type==ALIASTYPE_Name && Alias_MatchName(alias,lname,len))
			return(alias->Alias);
	}
	return(Name);
}
