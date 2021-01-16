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
/*!\file
\brief Provide a meanigfull name instead of the user ID or IP address shown in the
reports.
*/

#include "include/conf.h"
#include "include/defs.h"

#ifdef HAVE_LDAP_H
#define LDAP_DEPRECATED 1

#include <ldap.h>
#include <ldap_cdefs.h>
#include <ldap_features.h>

#if defined(HAVE_ICONV_H)
#include <iconv.h>
#define USE_ICONV 1
#endif //HAVE_ICONV_H

#endif //HAVE_LDAP_H

/*!
The possible sources to map the user ID or IP address to the name to display
in the reports.
*/
enum UserTabEnum
{
	//! Users matched against the ::UserTabFile file.
	UTT_File,
	//! Users matched agains a LDAP.
	UTT_Ldap,
	//! No user matching performed.
	UTT_None
};

/*!
Tell the database source to use to map the user ID or IP address to a meaningfull
name.
*/
enum UserTabEnum which_usertab=UTT_None;

static char *userfile=NULL;

#ifdef HAVE_LDAP_H
static LDAP *ldap_handle=NULL;
#endif //HAVE_LDAP_H

#ifdef USE_ICONV
//! iconv conversion descriptor to convert the string returned by LDAP.
static iconv_t ldapiconv=(iconv_t)-1;
//! Buffer to store the converted string.
static char *ldapconvbuffer=NULL;
//! Size of the converted string buffer.
static int ldapconvbuffersize=0;
#endif

/*!
Read the \a UserTabFile database.

The file contains the IP address or ID of the user then some spaces and
the real name of the user to show in the report.

Any trailing space or tabulation is removed from the real name. The user ID or IP cannot contain
a space or a tabulation but it may contain any other character, including the colon that was
forbidden in the past. That change was made to allow IPv6 addresses.

The file may contain comments if the line starts with a #.

\param UserTabFile The name of the file to read.
*/
static void init_file_usertab(const char *UserTabFile)
{
	FILE *fp_usr;
	long int nreg;
	char buf[MAXLEN];
	int z1, z2;

	if ((fp_usr=fopen(UserTabFile,"r"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),UserTabFile,strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (fseek(fp_usr, 0, SEEK_END)==-1) {
		debuga(__FILE__,__LINE__,_("Failed to move till the end of file \"%s\": %s\n"),UserTabFile,strerror(errno));
		exit(EXIT_FAILURE);
	}
	nreg = ftell(fp_usr);
	if (nreg<0) {
		debuga(__FILE__,__LINE__,_("Cannot get the size of file \"%s\"\n"),UserTabFile);
		exit(EXIT_FAILURE);
	}
	nreg += 100;
	if (fseek(fp_usr, 0, SEEK_SET)==-1) {
		debuga(__FILE__,__LINE__,_("Failed to rewind file \"%s\": %s\n"),UserTabFile,strerror(errno));
		exit(EXIT_FAILURE);
	}
	if ((userfile=(char *) malloc(nreg))==NULL){
		debuga(__FILE__,__LINE__,_("ERROR: Cannot load. Memory fault\n"));
		exit(EXIT_FAILURE);
	}
	userfile[0]='\t';
	z2=1;
	while(fgets(buf,sizeof(buf),fp_usr)!=NULL) {
		if (buf[0]=='#') continue;
		fixendofline(buf);
		z1=0;
		while(buf[z1] && (unsigned char)buf[z1]>' ') {
			if (z2+3>=nreg) { //need at least 3 additional bytes for the minimum string "\n\t\0"
				debuga(__FILE__,__LINE__,_("The list of users is too long in file \"%s\"\n"),UserTabFile);
				exit(EXIT_FAILURE);
			}
			userfile[z2++]=buf[z1++];
		}
		while(buf[z1] && (unsigned char)buf[z1]<=' ') z1++;
		userfile[z2++]='\n';
		while(buf[z1] && (unsigned char)buf[z1]>=' ') {
			if (z2+2>=nreg) { //need at least 2 additional bytes for "\t\0"
				debuga(__FILE__,__LINE__,_("The list of users is too long in file \"%s\"\n"),UserTabFile);
				exit(EXIT_FAILURE);
			}
			userfile[z2++]=buf[z1++];
		}
		while(userfile[z2-1]==' ') z2--;
		userfile[z2++]='\t';
	}
	userfile[z2]='\0';
	if (fclose(fp_usr)==EOF) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),UserTabFile,strerror(errno));
		exit(EXIT_FAILURE);
	}
}

/*!
Get the real name of the user from the usertab file read by init_file_usertab().

\param user The user ID or IP address to search.
\param name The buffer to store the real name of the user.
\param namelen The size of the \a name buffer.

If the user ID or IP address isn't found, the output buffer \a name contains
the unmatched input string.
*/
static void get_usertab_name(const char *user,char *name,int namelen)
{
	char warea[MAXLEN];
	char *str;

	sprintf(warea,"\t%s\n",user);
	if ((str=(char *) strstr(userfile,warea)) == (char *) NULL ) {
		safe_strcpy(name,user,namelen);
	} else {
		str=strchr(str+1,'\n');
		str++;
		namelen--;
		for (z1=0; *str != '\t' && z1<namelen ; z1++) {
			name[z1]=*str++;
		}
		name[z1]='\0';
	}
}

#ifdef HAVE_LDAP_H
/*!
 * \brief Connect to the LDAP server
 */
static void connect_ldap(void)
{
	char *ldapuri;
	LDAPURLDesc url;
	int rc;

	if (ldap_handle)
		ldap_unbind(ldap_handle);

	/* Setting LDAP connection and initializing cache */
	memset(&url,0,sizeof(url));
	url.lud_scheme = "ldap";
	url.lud_host = LDAPHost;
	url.lud_port = LDAPPort;
	url.lud_scope = LDAP_SCOPE_DEFAULT;
	ldapuri = ldap_url_desc2str(&url);
	if (ldapuri==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot prepare ldap URI for server %s on port %d\n"),LDAPHost,LDAPPort);
		exit(EXIT_FAILURE);
	}

	rc = ldap_initialize(&ldap_handle, ldapuri);
	if (rc != LDAP_SUCCESS) {
		debuga(__FILE__,__LINE__,_("Unable to connect to LDAP server %s on port %d: %d (%s)\n"), LDAPHost, LDAPPort, rc, ldap_err2string(rc));
		exit(EXIT_FAILURE);
	}
	ldap_memfree(ldapuri);

	if (ldap_set_option(ldap_handle, LDAP_OPT_REFERRALS, LDAP_OPT_OFF) != LDAP_OPT_SUCCESS) {
		debuga(__FILE__,__LINE__,_("Could not disable LDAP_OPT_REFERRALS\n"));
		exit(EXIT_FAILURE);
	}
	int ldap_protocol_version = LDAPProtocolVersion;
	if (ldap_set_option(ldap_handle, LDAP_OPT_PROTOCOL_VERSION, &ldap_protocol_version) != LDAP_SUCCESS) {
		debuga(__FILE__,__LINE__,_("Could not set LDAP protocol version %d\n"), ldap_protocol_version);
		exit(EXIT_FAILURE);
	}

	/* Bind to the LDAP server. */
	rc = ldap_simple_bind_s( ldap_handle, LDAPBindDN, LDAPBindPW );
	if ( rc != LDAP_SUCCESS ) {
		debuga(__FILE__,__LINE__,_("Cannot bind to LDAP server: %s\n"), ldap_err2string(rc));
		exit(EXIT_FAILURE);
	}
}

/*!
Initialize the communication with the LDAP server whose name is in
::LDAPHost and connect to port ::LDAPPort.
*/
static void init_ldap_usertab(void)
{
	ldap_handle = NULL;
	connect_ldap();

#ifdef USE_ICONV
	// prepare for the string conversion
	if (LDAPNativeCharset[0]!='\0') {
		ldapiconv = iconv_open( LDAPNativeCharset, "UTF-8" );
		if (ldapiconv==(iconv_t)-1) {
			debuga(__FILE__,__LINE__,_("iconv cannot convert from UTF-8 to %s: %s\n"),LDAPNativeCharset,strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	ldapconvbuffer=NULL;
	ldapconvbuffersize=0;
#endif

	/* Initializing cache */
	init_cache();
}

const char * charset_convert( const char * str_in, const char * charset_to )
{
#ifdef USE_ICONV
	size_t return_value;
	const char * str_in_orig;
	char * str_out;
	size_t str_in_len;
	size_t str_out_len;

	str_in_len = strlen( str_in ) + 1;//process the terminating NUL too
	str_out_len = ( 2 * str_in_len );
	if (ldapconvbuffer==NULL || ldapconvbuffersize<str_out_len) {
		ldapconvbuffersize=str_out_len;
		str_out = realloc(ldapconvbuffer,ldapconvbuffersize);
		if (!str_out) {
			debuga(__FILE__,__LINE__,_("Not enough memory to convert a LDAP returned string: %lu bytes required\n"),(unsigned long int)str_out_len);
			exit(EXIT_FAILURE);
		}
		ldapconvbuffer = str_out;
	} else {
		str_out = ldapconvbuffer;
		str_out_len = ldapconvbuffersize;
	}
	str_in_orig = str_in;
	return_value = iconv(ldapiconv, (ICONV_CONST char **)&str_in, &str_in_len, &str_out, &str_out_len );
	if ( return_value == ( size_t ) -1 ) {
		/* TRANSLATORS: The message is followed by the reason for the failure. */
		debuga(__FILE__,__LINE__,_("iconv failed on string \"%s\":\n"),str_in_orig);
		switch ( errno ) {
			/* See "man 3 iconv" for an explanation. */
			case EILSEQ:
				debuga(__FILE__,__LINE__,_("Invalid multibyte sequence.\n"));
				break;
			case EINVAL:
				debuga(__FILE__,__LINE__,_("Incomplete multibyte sequence.\n"));
				break;
			case E2BIG:
				debuga(__FILE__,__LINE__,_("No more room.\n"));
				break;
			default:
				debuga(__FILE__,__LINE__,_("Error: %s.\n"),strerror( errno ));
		}
		exit(EXIT_FAILURE);
	}
	return(ldapconvbuffer);
#else //USE_ICONV
	return(str_in);
#endif //USE_ICONV
}

/*!
Get the real name of a user by searching the userlogin (user ID) in a LDAP.

\param userlogin The user ID to search.
\param name The buffer to store the real name of the user.
\param namelen The size of the \a name buffer.

If the user ID isn't found in the LDAP, the output buffer \a name contains
the unmatched input string.
*/
static void get_ldap_name(const char *userlogin,char *mappedname,int namelen)
{
	/* Start searching username in cache */
	// According to rfc2254 section 4, only *()\ and NUL must be escaped. This list is rather conservative !
	const char strictchars[] = " ~!@^&(){}|<>?:;\"\'\\[]`,\r\n\0";
	char filtersearch[256], *searched_in_cache;
	char searchloginname[3*MAX_USER_LEN];
	char *attr, **vals;
	const char *attr_out;
	const char *ptr;
	LDAPMessage *result, *e;
	BerElement *ber;
	int i;
	int slen;
	int rc;
	char *attrs[2];

	searched_in_cache = search_in_cache(userlogin);
	if (searched_in_cache!=NULL) {
		safe_strcpy(mappedname, searched_in_cache,namelen);
		return;
	}

	// escape characters according to rfc2254 section 4
	for (slen=0 , ptr=userlogin ; slen<sizeof(searchloginname)-1 && *ptr ; ptr++) {
		if (strchr(strictchars,*ptr)) {
			if (slen+3>=sizeof(searchloginname)-1) break;
			slen+=sprintf(searchloginname+slen,"\\%02X",*ptr);
		} else {
			searchloginname[slen++]=*ptr;
		}
	}
	searchloginname[slen]='\0';

	i=0;
	ptr=LDAPFilterSearch;
	while (i<sizeof(filtersearch)-1 && *ptr) {
		if (ptr[0]=='%' && ptr[1]=='s') {
			if (i+slen>=sizeof(filtersearch)) break;
			memcpy(filtersearch+i,searchloginname,slen);
			i+=slen;
			ptr+=2;
		} else {
			filtersearch[i++]=*ptr++;
		}
	}
	filtersearch[i]='\0';

	/* Search record(s) in LDAP base */
	attrs[0]=LDAPTargetAttr;
	attrs[1]=NULL;
	rc=ldap_search_ext_s(ldap_handle, LDAPBaseSearch, LDAP_SCOPE_SUBTREE, filtersearch, attrs, 0, NULL, NULL, NULL, -1, &result);
	if (rc != LDAP_SUCCESS) {
		/*
		 * We know the connection was successfully established once. If it fails now,
		 * it may be because the server timed out between two requests or because
		 * there is an error in the request.
		 *
		 * Just in case the failure is due to a timeout, we try to connect and send
		 * the query again.
		 */
		connect_ldap();
		rc=ldap_search_ext_s(ldap_handle, LDAPBaseSearch, LDAP_SCOPE_SUBTREE, filtersearch, attrs, 0, NULL, NULL, NULL, -1, &result);
		if (rc != LDAP_SUCCESS) {
			debuga(__FILE__,__LINE__,_("LDAP search failed: %s\nlooking for \"%s\" at or below \"%s\"\n"), ldap_err2string(rc),filtersearch,LDAPBaseSearch);
			safe_strcpy(mappedname,userlogin,namelen);
			return;
		}
	}

	if (!(e = ldap_first_entry(ldap_handle, result))) {
		insert_to_cache(userlogin, userlogin);
		safe_strcpy(mappedname, userlogin,namelen);
		return;
	}

	for (attr = ldap_first_attribute(ldap_handle, e, &ber); attr != NULL; attr = ldap_next_attribute(ldap_handle, e, ber)) {
		if (!strcasecmp(attr, LDAPTargetAttr)) {
			if ((vals = (char **)ldap_get_values(ldap_handle, e, attr))!=NULL) {
				attr_out = charset_convert( vals[0], LDAPNativeCharset );
				insert_to_cache(userlogin, attr_out);
				safe_strcpy(mappedname, attr_out, namelen);
				ldap_memfree(vals);
			}
			ldap_memfree(attr);
			break;
		}
		ldap_memfree(attr);
	}
	ldap_msgfree(result);
}
#endif //HAVE_LDAP_H

/*!
Initialize the data used by user_find().

If \a UserTabFile is ldap, the user ID is fetched from a LDAP server.

\param UserTabFile The name of the file to read or ldap. If it is empty, the function does nothing.

\note The memory and resources allocated by this function must be released by
a call to close_usertab().
*/
void init_usertab(const char *UserTabFile)
{
	if (strcmp(UserTabFile, "ldap") == 0) {
		if (debug) {
			/* TRANSLATORS: The %s may be the string "ldap" or a file name.*/
			debuga(__FILE__,__LINE__,_("Loading User table from \"%s\"\n"),UserTabFile);
		}
#ifdef HAVE_LDAP_H
		which_usertab=UTT_Ldap;
		init_ldap_usertab();
#else
		debuga(__FILE__,__LINE__,_("LDAP module not compiled in sarg\n"));
		exit(EXIT_FAILURE);
#endif //HAVE_LDAP_H
	} else if (UserTabFile[0] != '\0') {
		if (debug)
			debuga(__FILE__,__LINE__,_("Loading User table from \"%s\"\n"),UserTabFile);
		which_usertab=UTT_File;
		init_file_usertab(UserTabFile);
	} else {
		which_usertab=UTT_None;
	}
}

/*!
Find the real name of the user with the ID or IP address in \a userlogin. The name is fetched
from the source initialized by init_usertab().

The usertab data must have been initialized by init_usertab().

\param mappedname A buffer to write the real name of the user.
\param namelen The size of the buffer.
\param userlogin The ID or IP address of the user.
*/
void user_find(char *mappedname, int namelen, const char *userlogin)
{
	if (which_usertab==UTT_File) {
		get_usertab_name(userlogin,mappedname,namelen);
	}
#ifdef HAVE_LDAP_H
	else if (which_usertab==UTT_Ldap) {
		get_ldap_name(userlogin,mappedname,namelen);
	}
#endif //HAVE_LDAP_H
	else {
		safe_strcpy(mappedname,userlogin,namelen);
	}
}

/*!
Free the memory and resources allocated by init_usertab().
*/
void close_usertab(void)
{
#ifdef HAVE_LDAP_H
	if (ldap_handle) {
		destroy_cache();
		ldap_unbind(ldap_handle);
		ldap_handle=NULL;
	}
#endif //HAVE_LDAP_H
#ifdef USE_ICONV
	if (ldapiconv!=(iconv_t)-1) {
		iconv_close (ldapiconv);
		ldapiconv=(iconv_t)-1;
	}
	if (ldapconvbuffer) {
		free(ldapconvbuffer);
		ldapconvbuffer=NULL;
	}
#endif // USE_ICONV
	if (userfile) {
		free(userfile);
		userfile=NULL;
	}
}

