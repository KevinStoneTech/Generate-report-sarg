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

struct hostip4struct
{
	//! The IP address.
	unsigned long int address;
	//! The mask to match the address of the URL.
	unsigned long int mask;
};

struct hostip6struct
{
	//! The IP address.
	unsigned short int address[8];
	//! The number of bits in the prefix.
	int nbits;
};

struct hostnamestruct
{
	//! The URL to match without any leading wildcard.
	char *url;
	//! The number of dots in the url if a wildcard is present or -1 if the address is complete (no wildcard)
	int ndots;
};

static struct hostip4struct *exclude_ip4=NULL;
static int num_exclude_ip4=0;
static struct hostip6struct *exclude_ip6=NULL;
static int num_exclude_ip6=0;
static struct hostnamestruct *exclude_name=NULL;
static int num_exclude_name=0;
static int ip4allocated=0;
static int ip6allocated=0;
static int nameallocated=0;

static char *excludeuser=NULL;

/*!
  Store a IPv4 address to exclude from the reported URL.

  \param addr The 4 char of the address.
  \param nbits The number of bits to keep in the prefix.
 */
static void store_exclude_ip4(unsigned char *addr,int nbits)
{
	int i;

	if (num_exclude_ip4>=ip4allocated) {
		struct hostip4struct *temp;

		ip4allocated+=5;
		temp=realloc(exclude_ip4,ip4allocated*sizeof(*temp));
		if (temp==NULL) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store the exlcluded IP addresses\n"));
			exit(EXIT_FAILURE);
		}
		exclude_ip4=temp;
	}
	exclude_ip4[num_exclude_ip4].address=0UL;
	for (i=0 ; i<4 ; i++)
		exclude_ip4[num_exclude_ip4].address=(exclude_ip4[num_exclude_ip4].address<<8) | (unsigned char)(addr[i] & 0xFFU);
	exclude_ip4[num_exclude_ip4].mask=(0xFFFFFFFFUL << (32-nbits));
	num_exclude_ip4++;
}

/*!
  Store a IPv6 address to exclude from the reported URL.

  \param addr The 8 short int of the address.
  \param nbits The number of bits to keep in the prefix.
 */
static void store_exclude_ip6(unsigned short *addr,int nbits)
{
	int i;

	if (num_exclude_ip6>=ip6allocated) {
		struct hostip6struct *temp;

		ip6allocated+=5;
		temp=realloc(exclude_ip6,ip6allocated*sizeof(*temp));
		if (temp==NULL) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store the exlcluded IP addresses\n"));
			exit(EXIT_FAILURE);
		}
		exclude_ip6=temp;
	}
	for (i=0 ; i<8 ; i++)
		exclude_ip6[num_exclude_ip6].address[i]=addr[i];
	exclude_ip6[num_exclude_ip6].nbits=nbits;
	num_exclude_ip6++;
}

/*!
  Store a host name to exclude from the report.

  \param url The host name to exclude.
 */
static void store_exclude_url(const char *url,const char *next)
{
	int start;
	int i;
	int length;
	int ndots, firstdot;
	struct hostnamestruct *item;

	start=0;
	ndots=-1;
	firstdot=0;
	length=next-url;
	for (i=0 ; i<length ; i++)
		if (url[i]=='*') {
			firstdot=1;
		} else if (url[i]=='.') {
			if (firstdot) {
				firstdot=0;
				ndots=1;
				start=i+1;
			} else if (ndots>=0)
				ndots++;
		}
	if (start>=length || firstdot) return;
	if (start>0) {
		url+=start;
		length-=start;
	}

	if (num_exclude_name>=nameallocated) {
		struct hostnamestruct *temp;

		nameallocated+=5;
		temp=realloc(exclude_name,nameallocated*sizeof(*temp));
		if (temp==NULL) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store the excluded URLs\n"));
			exit(EXIT_FAILURE);
		}
		exclude_name=temp;
	}

	item=exclude_name+num_exclude_name;
	num_exclude_name++;
	item->url=malloc(length+1);
	if (!item->url) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store the excluded URLs\n"));
		exit(EXIT_FAILURE);
	}
	safe_strcpy(item->url,url,length+1);
	item->ndots=(ndots>0) ? ndots : -1;
}

/*!
  Read the file listing the host to exclude from the report.

  \param hexfile The name of the file.
  \param debug \c True to print debug information.
 */
void gethexclude(const char *hexfile, int debug)
{
	FILE *fp_ex;
	char buf[255];
	int type;
	const char *name;
	unsigned char ipv4[4];
	unsigned short int ipv6[8];
	int nbits;
	const char *next;

	if (access(hexfile, R_OK) != 0) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),hexfile,strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (debug)
		debuga(__FILE__,__LINE__,_("Loading exclude host file from \"%s\"\n"),hexfile);

	if ((fp_ex = fopen(hexfile, "r")) == NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),hexfile,strerror(errno));
		exit(EXIT_FAILURE);
	}

	while(fgets(buf,sizeof(buf),fp_ex)!=NULL){
		if (buf[0]=='#')
			continue;
		fixendofline(buf);

		type=extract_address_mask(buf,&name,ipv4,ipv6,&nbits,&next);
		if (type<0) {
			debuga(__FILE__,__LINE__,_("While reading \"%s\"\n"),hexfile);
			exit(EXIT_FAILURE);
		}

		if (type==1) {
			store_exclude_url(name,next);
		} else if (type==2) {
				store_exclude_ip4(ipv4,nbits);
		} else if (type==3) {
				store_exclude_ip6(ipv6,nbits);
		}
	}

	if (fclose(fp_ex)==EOF) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),hexfile,strerror(errno));
		exit(EXIT_FAILURE);
	}
	return;
}

/*!
  Check if the URL is excluded as per the host exclusion list.

  \param url The URL to check.

  \retval 1 Keep the URL.
  \retval 0 Exclude the URL.
 */
int vhexclude(const char *url)
{
	int i, j;
	int length;
	int type;
	const char *name;
	unsigned char ipv4[4];
	unsigned short int ipv6[8];
	unsigned long int addr4;
	int dotpos[50];
	int ndots;

	type=extract_address_mask(url,&name,ipv4,ipv6,NULL,NULL);
	if (type==1) {
		if (exclude_name == NULL) return(1);
		ndots=0;
		for (length=0 ; (unsigned char)name[length]>' ' && name[length]!=':' && name[length]!='/' && name[length]!='?' ; length++)
			if (name[length]=='.') {
				/*
				We store the position of each dots of the URL to match it against any
				wildcard in the excluded list. The size of dotpos is big enough for the most
				ambitious URL but we have a safety mechanism that shift the positions should there be too
				many dots in the URL.
				*/
				if (ndots<sizeof(dotpos)/sizeof(dotpos[0]))
					dotpos[ndots++]=length+1;
				else {
					for (j=1 ; j<ndots ; j++) dotpos[j-1]=dotpos[j];
					dotpos[ndots-1]=length+1;
				}
			}
		if (length>0) {
			for (i=0 ; i<num_exclude_name ; i++) {
				if (exclude_name[i].ndots>0) {
					const char *wurl=name;
					int len=length;
					if (exclude_name[i].ndots<=ndots) {
						wurl+=dotpos[ndots-exclude_name[i].ndots];
						len-=dotpos[ndots-exclude_name[i].ndots];
					}
					if (strncmp(exclude_name[i].url,wurl,len)==0 && exclude_name[i].url[len]=='\0') return(0);
				} else {
					if (strncmp(exclude_name[i].url,url,length)==0 && exclude_name[i].url[length]=='\0') return(0);
				}
			}
		}
	} else if (type==2) {
		if (exclude_ip4 == NULL) return(1);
		addr4=0UL;
		for (i=0 ; i<4 ; i++) addr4=(addr4 << 8) | ipv4[i];
		for (i=0 ; i<num_exclude_ip4 ; i++) {
			if (((exclude_ip4[i].address ^ addr4) & exclude_ip4[i].mask)==0) return(0);
		}
	} else if (type==3) {
		if (exclude_ip6 == NULL) return(1);
		for (i=0 ; i<num_exclude_ip6 ; i++) {
			length=exclude_ip6[i].nbits;
			for (j=length/16-1 ; j>=0 && ipv6[j]==exclude_ip6[i].address[j] ; j--);
			if (j>=0) return(1);
			j=length/16;
			if (j>=8 || length%16==0 || ((ipv6[j] ^ exclude_ip6[i].address[j]) & (0xFFFF<<(length-j*16)))==0)
				return(0);
		}
	}
	return(1);
}


void getuexclude(const char *uexfile, int debug)
{
	FILE *fp_ex;
	char buf[255];
	long int nreg=0;

	if (debug)
		debuga(__FILE__,__LINE__,_("Loading exclude file from \"%s\"\n"),uexfile);

	if ((fp_ex = fopen(uexfile, "r")) == NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),uexfile,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (fseek(fp_ex, 0, SEEK_END)==-1) {
		debuga(__FILE__,__LINE__,_("Failed to move till the end of file \"%s\": %s\n"),uexfile,strerror(errno));
		exit(EXIT_FAILURE);
	}
	nreg = ftell(fp_ex);
	if (nreg<0) {
		debuga(__FILE__,__LINE__,_("Cannot get the size of file \"%s\"\n"),uexfile);
		exit(EXIT_FAILURE);
	}
	nreg += 11;
	if (fseek(fp_ex, 0, SEEK_SET)==-1) {
		debuga(__FILE__,__LINE__,_("Failed to rewind file \"%s\": %s\n"),uexfile,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((excludeuser=(char *) malloc(nreg))==NULL){
		debuga(__FILE__,__LINE__,_("malloc error (%ld bytes required)\n"),nreg);
		exit(EXIT_FAILURE);
	}

	memset(excludeuser,0,nreg);

	while(fgets(buf,sizeof(buf),fp_ex)!=NULL){
		if (strchr(buf,'#') != NULL)
			continue;
		fixendofline(buf);
		strcat(excludeuser,buf);
		strcat(excludeuser," ");
	}

	strcat(excludeuser,"*END* ");

	if (fclose(fp_ex)==EOF) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),uexfile,strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}

int vuexclude(const char *user)
{
	const char *wuser;
	int len;

	if (excludeuser) {
		len=strlen(user);
		wuser=excludeuser;
		while ((wuser=strstr(wuser,user))!=NULL) {
			if (wuser[len]==' ') return(0);
			wuser+=len;
		}
	}

	return(1);
}

bool is_indexonly(void)
{
	if (excludeuser==NULL) return(false);
	return(strstr(excludeuser,"indexonly") != NULL);
}

void free_exclude(void)
{
	int i;

	if (exclude_ip4) {
		free(exclude_ip4);
		exclude_ip4=NULL;
	}

	if (exclude_name) {
		for (i=0 ; i<num_exclude_name ; i++)
			if (exclude_name[i].url) free(exclude_name[i].url);
		free(exclude_name);
		exclude_name=NULL;
	}

	if (excludeuser) {
		free(excludeuser);
		excludeuser=NULL;
	}
}
