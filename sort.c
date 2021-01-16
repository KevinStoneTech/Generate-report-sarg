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

/*!
Sort all the \c utmp files form the temporary directory. The sort can be made according to the
number of connections, the accessed sites or the time of the access depending on the value of
::UserSortField. The sorting is either made in increasing or decreasing order as specified by
the value of ::UserSortOrder.
*/
void tmpsort(const struct userinfostruct *uinfo)
{
	int cstatus;
	char csort[MAXLEN];
	char arqou[MAXLEN], arqin[MAXLEN];
	const char *field1="2,2";
	const char *field2="1,1";
	const char *field3="3,3";
	const char *order;

	if ((UserSort & USER_SORT_CONNECT) != 0) {
		field1="1,1";
		field2="2,2";
		field3="3,3";
	} else if ((UserSort & USER_SORT_SITE) != 0) {
		field1="3,3";
		field2="2,2";
		field3="1,1";
	} else if ((UserSort & USER_SORT_TIME) != 0) {
		field1="5,5";
		field2="2,2";
		field3="1,1";
	}

	if ((UserSort & USER_SORT_REVERSE) == 0)
		order="";
	else
		order="-r";

	if (snprintf(arqin,sizeof(arqin),"%s/%s.utmp",tmp,uinfo->filename)>=sizeof(arqin)) {
		debuga(__FILE__,__LINE__,_("Path too long: "));
		debuga_more("%s/%s.utmp\n",tmp,uinfo->filename);
		exit(EXIT_FAILURE);
	}
	if (snprintf(arqou,sizeof(arqou),"%s/htmlrel.txt",tmp)>=sizeof(arqou)) {
		debuga(__FILE__,__LINE__,_("Path too long: "));
		debuga_more("%s/htmlrel.txt\n",tmp);
		exit(EXIT_FAILURE);
	}

	if (debug) {
		debuga(__FILE__,__LINE__,_("Sorting file \"%s\"\n"),arqin);
	}

	if (snprintf(csort,sizeof(csort),"sort -n -T \"%s\" -t \"\t\" %s -k %s -k %s -k %s -o \"%s\" \"%s\"",tmp,order,field1,field2,field3,arqou,arqin)>=sizeof(csort)) {
		debuga(__FILE__,__LINE__,_("Sort command too long when sorting file \"%s\" to \"%s\"\n"),arqin,arqou);
		exit(EXIT_FAILURE);
	}
	cstatus=system(csort);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(__FILE__,__LINE__,_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}
	if (!KeepTempLog && unlink(arqin)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),arqin,strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}

/*!
The function sorts the \c unsort file in the temporary directory. These files correspond
to the format described in \ref UserUnsortLog.

\param tmp The temorary directory of the sarg files.
\param debug \c True to output debug information.
\param uinfo The user whose log must be sorted.

The user's files are sorted by columns 5, 1 and 2 that are the columns of the number of bytes transfered,
the date of the access and the time of the access.

The sorted files are written in files with the extension \c log and the name of the unsorted
file without the \c unsort extension. The unsorted file is deleted just after the sorting.
*/
void sort_users_log(const char *tmp, int debug,struct userinfostruct *uinfo)
{
	char csort[MAXLEN];
	const char *user;
	int cstatus;
	int clen;

	if (debug) {
		snprintf(csort,sizeof(csort),"%s/%s.user_unsort",tmp,uinfo->filename);
		debuga(__FILE__,__LINE__,_("Sorting file \"%s\"\n"),csort);
	}

	user=uinfo->filename;
	clen=snprintf(csort,sizeof(csort),"sort -T \"%s\" -t \"\t\" -k 4,4 -k 1,1 -k 2,2 -o \"%s/%s.user_log\" \"%s/%s.user_unsort\"",
			tmp, tmp, user, tmp, user);
	if (clen>=sizeof(csort)) {
		/* TRANSLATORS: The message is followed by the command that is too long. */
		debuga(__FILE__,__LINE__,_("User name too long to sort with command "));
		debuga_more("sort -T \"%s\" -t \"\t\" -k 4,4 -k 1,1 -k 2,2 -o \"%s/%s.user_log\" \"%s/%s.user_unsort\"",
					tmp, tmp, user, tmp, user);
		exit(EXIT_FAILURE);
	}
	cstatus=system(csort);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(__FILE__,__LINE__,_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}
	if (snprintf(csort,sizeof(csort),"%s/%s.user_unsort",tmp,user)>=sizeof(csort)) {
		debuga(__FILE__,__LINE__,_("User name too long to manufacture file name "));
		debuga_more("%s/%s.user_unsort\n",tmp,user);
		exit(EXIT_FAILURE);
	}
	if (!KeepTempLog && unlink(csort)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),csort,strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}

/*!
Get the internationalized text to display when reporting the sort criterion and order
of a user list.

\param label A pointer to set to the string of the sort criterion name.
\param order A pointer to set to the string of the sort order name
*/
void sort_labels(const char **label,const char **order)
{
	if ((UserSort & USER_SORT_CONNECT) != 0) {
		*label=_("connect");
	} else if ((UserSort & USER_SORT_SITE) != 0) {
		*label=_("site");
	} else if ((UserSort & USER_SORT_TIME) != 0) {
		*label=pgettext("duration","time");
	} else {
		*label=_("bytes");
	}

	if ((UserSort & USER_SORT_REVERSE) == 0)
		*order=_("normal");
	else
		*order=_("reverse");
}
