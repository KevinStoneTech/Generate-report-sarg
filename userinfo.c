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

//! The number of users to group in one unit.
#define USERS_PER_GROUP 50

/*! \brief Group the users in one allocation unit.
Structure to store a group of users and reduce the number of memory
allocations.
*/
struct usergroupstruct
{
	//! The next group of users.
	struct usergroupstruct *next;
	//! A group of users.
	struct userinfostruct list[USERS_PER_GROUP];
	//! The number of users stored in the list.
	int nusers;
};

/*! \brief Hold pointer to scan through the user list.
*/
struct userscanstruct
{
	//! The group containing the user.
	struct usergroupstruct *group;
	//! The index of the user in the group.
	int index;
};

//! The first group of users.
static struct usergroupstruct *first_user_group=NULL;
//! The counter to generate unique user number when ::AnonymousOutputFiles is set.
static int AnonymousCounter=0;
//! String buffer to store the user's related constants.
static StringBufferObject UserStrings=NULL;
//! User aliases.
static AliasObject UserAliases=NULL;

extern struct ReadLogDataStruct ReadFilter;
extern char StripUserSuffix[MAX_USER_LEN];
extern int StripSuffixLen;
extern char *userfile;

struct userinfostruct *userinfo_create(const char *userid,const char *ip)
{
	struct usergroupstruct *group, *last;
	struct userinfostruct *user;
	int i, j, lastuser;
	int skip;
	int flen;
	int count, clen;
	char cstr[9];
	char filename[MAX_USER_FNAME_LEN];

	if (!UserStrings) {
		UserStrings=StringBuffer_Create();
		if (!UserStrings) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store the user's strings\n"));
			exit(EXIT_FAILURE);
		}
	}

	last=NULL;
	for (group=first_user_group ; group ; group=group->next) {
		if (group->nusers<USERS_PER_GROUP) break;
		last=group;
	}

	if (!group) {
		group=malloc(sizeof(*group));
		if (!group) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store user \"%s\"\n"),userid);
			exit(EXIT_FAILURE);
		}
		memset(group,0,sizeof(*group));
		if (last)
			last->next=group;
		else
			first_user_group=group;
	}
	user=group->list+group->nusers++;

	user->id=StringBuffer_Store(UserStrings,userid);
	if (!user->id) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store user ID \"%s\"\n"),userid);
		exit(EXIT_FAILURE);
	}
	user->label=user->id; //assign a label to avoid a NULL pointer in case none is provided
	if (ip) {
		/*
		 * IP address is not the same as the user's ID. A separate buffer
		 * must be allocated.
		 */
		user->id_is_ip=false;
		user->ip=StringBuffer_Store(UserStrings,ip);
	} else {
		/*
		 * User's IP address share the same buffer as the user's ID.
		 */
		user->id_is_ip=true;
		user->ip=user->id;
	}

	if (AnonymousOutputFiles) {
		snprintf(filename,sizeof(filename),"%d",AnonymousCounter++);
	} else {
		skip=0;
		j=0;
		for (i=0 ; userid[i] && j<MAX_USER_FNAME_LEN-1 ; i++) {
			if (isalnum(userid[i]) || userid[i]=='-' || userid[i]=='_') {
				filename[j++]=userid[i];
				skip=0;
			} else {
				if (!skip) {
					filename[j++]='_';
					skip=1;
				}
			}
		}
		if (j==0) filename[j++]='_'; //don't leave a file name empty
		flen=j;
		filename[j]='\0';

		count=0;
		for (group=first_user_group ; group ; group=group->next) {
			lastuser=(group->next) ? group->nusers : group->nusers-1;
			for (i=0 ; i<lastuser ; i++) {
				if (strcasecmp(filename,group->list[i].filename)==0) {
					clen=sprintf(cstr,"+%X",count++);
					if (flen+clen<MAX_USER_FNAME_LEN)
						strcpy(filename+flen,cstr);
					else
						strcpy(filename+MAX_USER_FNAME_LEN-clen,cstr);
				}
			}
		}
	}
	user->filename=StringBuffer_Store(UserStrings,filename);
	if (!user->filename)
	{
		debuga(__FILE__,__LINE__,_("Not enough memory to store the file name for user \"%s\"\n"),user->id);
		exit(EXIT_FAILURE);
	}

	return(user);
}

void userinfo_free(void)
{
	struct usergroupstruct *group, *next;

	for (group=first_user_group ; group ; group=next) {
		next=group->next;
		free(group);
	}
	first_user_group=NULL;
	StringBuffer_Destroy(&UserStrings);
}

/*!
 * Store the user's label.
 * \param uinfo The user info structure created by userinfo_create().
 * \param label The string label to store.
 */
void userinfo_label(struct userinfostruct *uinfo,const char *label)
{
	if (!uinfo) return;
	if (!UserStrings) return;
	uinfo->label=StringBuffer_Store(UserStrings,label);
	if (!uinfo->label) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store label \"%s\" of user \"%s\"\n"),label,uinfo->id);
		exit(EXIT_FAILURE);
	}
}

struct userinfostruct *userinfo_find_from_file(const char *filename)
{
	struct usergroupstruct *group;
	int i;

	for (group=first_user_group ; group ; group=group->next) {
		for (i=0 ; i<group->nusers ; i++)
			if (strcmp(filename,group->list[i].filename)==0)
				return(group->list+i);
	}
	return(NULL);
}

struct userinfostruct *userinfo_find_from_id(const char *id)
{
	struct usergroupstruct *group;
	int i;

	for (group=first_user_group ; group ; group=group->next) {
		for (i=0 ; i<group->nusers ; i++)
			if (strcmp(id,group->list[i].id)==0)
				return(group->list+i);
	}
	return(NULL);
}

struct userinfostruct *userinfo_find_from_ip(const char *ip)
{
	struct usergroupstruct *group;
	int i;

	for (group=first_user_group ; group ; group=group->next) {
		for (i=0 ; i<group->nusers ; i++)
			if (strcmp(ip,group->list[i].ip)==0)
				return(group->list+i);
	}
	return(NULL);
}

/*!
Start the scanning of the user list.

\return The object to pass to subsequent scanning functions or NULL
if it failed. The object must be freed with a call to userinfo_stop().
*/
userscan userinfo_startscan(void)
{
	userscan uscan;

	uscan=malloc(sizeof(*uscan));
	if (!uscan) return(NULL);
	uscan->group=first_user_group;
	uscan->index=0;
	return(uscan);
}

/*!
Free the memory allocated by userinfo_start().

\param uscan The object created by userinfo_start().
*/
void userinfo_stopscan(userscan uscan)
{
	free(uscan);
}

/*!
Get the user pointed to by the object and advance the object
to the next user.

\param uscan The object created by userinfo_start().

\return The user in the list or NULL if the end of the list
is reached.
*/
struct userinfostruct *userinfo_advancescan(userscan uscan)
{
	struct userinfostruct *uinfo;

	if (!uscan) return(NULL);
	if (!uscan->group) return(NULL);
	if (uscan->index<0 || uscan->index>=uscan->group->nusers) return(NULL);

	uinfo=uscan->group->list+uscan->index;

	++uscan->index;
	if (uscan->index>=uscan->group->nusers) {
		uscan->group=uscan->group->next;
		uscan->index=0;
	}
	return(uinfo);
}

/*!
Clear the general purpose flag from all the user's info.
*/
void userinfo_clearflag(void)
{
	struct usergroupstruct *group;
	int i;

	for (group=first_user_group ; group ; group=group->next) {
		for (i=0 ; i<group->nusers ; i++)
			group->list[i].flag=0;
	}
}

/*!
Read the file containing the user names to alias in the report.

\param Filename The name of the file.
*/
void read_useralias(const char *Filename)
{
	FileObject *fi;
	longline line;
	char *buf;

	if (debug) debuga(__FILE__,__LINE__,_("Reading user alias file \"%s\"\n"),Filename);

	UserAliases=Alias_Create();
	if (!UserAliases) {
		debuga(__FILE__,__LINE__,_("Cannot store user's aliases\n"));
		exit(EXIT_FAILURE);
	}

	fi=FileObject_Open(Filename);
	if (!fi) {
		debuga(__FILE__,__LINE__,_("Cannot read user name alias file \"%s\": %s\n"),Filename,FileObject_GetLastOpenError());
		exit(EXIT_FAILURE);
	}

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),Filename);
		exit(EXIT_FAILURE);
	}

	while ((buf=longline_read(fi,line)) != NULL) {
		if (Alias_Store(UserAliases,buf)<0) {
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
		debuga(__FILE__,__LINE__,_("List of user names to alias:\n"));
		Alias_PrintList(UserAliases);
	}
}

/*!
Free the memory allocated by read_useralias().
*/
void free_useralias(void)
{
	Alias_Destroy(&UserAliases);
}

/*!
Replace the user's name or ID by an alias if one is defined.

\param user The user's name or ID as extracted from the report.

\retval USERERR_NoError No error.
\retval USERERR_NameTooLong User name too long.
*/
enum UserProcessError process_user(const char **UserPtr,const char *IpAddress,bool *IsIp)
{
	const char *user=*UserPtr;
	static char UserBuffer[MAX_USER_LEN];
	const char *auser;

	if (UserIp) {
		user=IpAddress;
		*IsIp=true;
	} else {
		*IsIp=false;

		if (StripSuffixLen>0)
		{
			int x=strlen(user);
			if (x>StripSuffixLen && strcasecmp(user+(x-StripSuffixLen),StripUserSuffix)==0)
			{
				if (x-StripSuffixLen>=sizeof(UserBuffer))
					return(USERERR_NameTooLong);
				safe_strcpy(UserBuffer,user,x-StripSuffixLen+1);
				user=UserBuffer;
			}
		}
		if (strlen(user)>MAX_USER_LEN)
			return(USERERR_NameTooLong);

		if (testvaliduserchar(user))
			return(USERERR_InvalidChar);

		if ((user[0]=='\0') || (user[1]=='\0' && (user[0]=='-' || user[0]==' '))) {
			if (RecordsWithoutUser == RECORDWITHOUTUSER_IP) {
				user=IpAddress;
				*IsIp=true;
			}
			if (RecordsWithoutUser == RECORDWITHOUTUSER_IGNORE)
				return(USERERR_EmptyUser);
			if (RecordsWithoutUser == RECORDWITHOUTUSER_EVERYBODY)
				user="everybody";
		} else {
			if (NtlmUserFormat == NTLMUSERFORMAT_USER) {
				const char *str;
				if ((str=strchr(user,'+'))!=NULL || (str=strchr(user,'\\'))!=NULL || (str=strchr(user,'_'))!=NULL) {
					user=str+1;
				}
			}
		}
	}

	if (us[0]!='\0' && strcmp(user,us)!=0)
		return(USERERR_Untracked);

	if (ReadFilter.SysUsers) {
		char wuser[MAX_USER_LEN+2]=":";

		strcat(wuser,user);
		strcat(wuser,":");
		if (strstr(userfile, wuser) == 0)
			return(USERERR_SysUser);
	}

	if (ReadFilter.UserFilter) {
		if (!vuexclude(user)) {
			if (debugz>=LogLevel_Process) debuga(__FILE__,__LINE__,_("Excluded user: %s\n"),user);
			return(USERERR_Ignored);
		}
	}

	auser=Alias_Replace(UserAliases,user);
	if (auser!=user) {
		if (*auser==ALIAS_PREFIX) auser++;//no need for that indicator for a user name
		user=auser;
		*IsIp=false;
	}

	// include_users
	if (IncludeUsers[0] != '\0') {
		char wuser[MAX_USER_LEN+2]=":";
		char *str;

		strcat(wuser,user);
		strcat(wuser,":");
		str=strstr(IncludeUsers,wuser);
		if (!str)
			return(USERERR_Excluded);
	}

	if (user[0]=='\0' || (user[1]=='\0' && (user[0]=='-' || user[0]==' ' || user[0]==':')))
		return(USERERR_EmptyUser);

	*UserPtr=user;
	return(USERERR_NoError);
}
