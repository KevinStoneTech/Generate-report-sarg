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
#include "include/readlog.h"

/*!
A new file is being read. The name of the file is \a FileName.
*/
static void Squid_NewFile(const char *FileName)
{
}

/*!
Read one entry from a standard squid log format.

\param Line One line from the input log file.
\param Entry Where to store the information parsed from the line.

\retval RLRC_NoError One valid entry is parsed.
\retval RLRC_Unknown The line is invalid.
\retval RLRC_InternalError An internal error was encountered.
*/
static enum ReadLogReturnCodeEnum Squid_ReadEntry(char *Line,struct ReadLogStruct *Entry)
{
	const char *Begin;
	time_t log_time;
	int IpLen;
	int HttpCodeLen;
	int HttpMethodLen;
	int UrlLen;
	int UserLen;
	struct tm *tt;
	char *Ip;
	char *User;

	// get log time.
	Begin=Line;
	log_time=0;
	while (isdigit(*Line)) log_time=log_time*10+(*Line++-'0');
	if (*Line!='.' || Line==Begin) return(RLRC_Unknown);

	// ignore decimal part to log time.
	Begin=++Line;
	while (isdigit(*Line)) Line++;
	if (*Line!=' ' || Line==Begin) return(RLRC_Unknown);

	// skip spaces before the elapsed time.
	while (*Line==' ') Line++;

	// get the elapsed time.
	Begin=Line;
	Entry->ElapsedTime=0L;
	if (*Line=='-')
	{
		/*
		 * Negative elapsed time happens in squid (see
		 * http://www.squid-cache.org/mail-archive/squid-users/200711/0192.html)
		 * but no answer were provided as to why it happens. Let's just
		 * assume a zero elapsed time and ignore every following digit.
		 */
		Line++;
		if (!isdigit(*Line)) return(RLRC_Unknown);
		while (isdigit(*Line)) Line++;
	}
	else
	{
		if (!isdigit(*Line)) return(RLRC_Unknown);
		while (isdigit(*Line)) Entry->ElapsedTime=Entry->ElapsedTime*10+(*Line++-'0');
	}
	if (*Line!=' ' || Line==Begin) return(RLRC_Unknown);

	// get IP address. It can be a fqdn if that option is enabled in squid.
	Entry->Ip=Ip=++Line;
	for (IpLen=0 ; *Line && *Line!=' ' ; IpLen++) Line++;
	if (*Line!=' ' || IpLen==0) return(RLRC_Unknown);

	// get the HTTP code.
	Entry->HttpCode=++Line;
	for (HttpCodeLen=0 ; *Line && *Line!=' ' ; HttpCodeLen++) Line++;
	if (*Line!=' ' || HttpCodeLen==0) return(RLRC_Unknown);

	// get the number of transfered bytes.
	Begin=++Line;
	Entry->DataSize=0LL;
	while (isdigit(*Line)) Entry->DataSize=Entry->DataSize*10+(*Line++-'0');
	if (*Line!=' ' || Begin==Line) return(RLRC_Unknown);

	// get the HTTP method
	Entry->HttpMethod=++Line;
	for (HttpMethodLen=0 ; *Line && *Line!=' ' ; HttpMethodLen++) Line++;
	if (*Line!=' '|| HttpMethodLen==0) return(RLRC_Unknown);

	// the url
	Entry->Url=++Line;
	for (UrlLen=0 ; *Line && *Line!=' ' ; UrlLen++) Line++;
	if (*Line!=' ' || UrlLen==0) return(RLRC_Unknown);

	// the ID of the user or - if the user is unidentified
	Entry->User=User=++Line;
	for (UserLen=0 ; *Line && *Line!=' ' ; UserLen++) Line++;
	if (*Line!=' ' || UserLen==0) return(RLRC_Unknown);

	// now, the format is known with a good confidence. If the time doesn't decode, it is an error.
	tt=localtime(&log_time);
	if (tt==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot convert the timestamp from the squid log file\n"));
		return(RLRC_InternalError);
	}
	memcpy(&Entry->EntryTime,tt,sizeof(struct tm));

	// it is safe to alter the line buffer now that we are returning a valid entry
	Ip[IpLen]='\0';
	Entry->HttpCode[HttpCodeLen]='\0';
	Entry->HttpMethod[HttpMethodLen]='\0';
	Entry->Url[UrlLen]='\0';
	User[UserLen]='\0';

	return(RLRC_NoError);
}

//! \brief Object to read a standard squid log format.
const struct ReadLogProcessStruct ReadSquidLog=
{
	/* TRANSLATORS: This is the name of the log format displayed when this format is detected in an input log file. */
	N_("squid log format"),
	Squid_NewFile,
	Squid_ReadEntry
};
