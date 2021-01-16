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
static void Common_NewFile(const char *FileName)
{
}

/*!
Extract a column containing a long long int from \a Line.

The extracted value is stored in \a Value.

The pointer to the next byte just after the number is returned
by the function.
*/
static char *Common_GetLongLongInt(char *Line,long long int *Value)
{
	*Value=0LL;
	if (*Line=='-') {
		++Line;
	} else {
		while (isdigit(*Line)) *Value=*Value*10+(*Line++-'0');
	}
	return(Line);
}

/*!
Read one entry from a standard squid log format.

\param Line One line from the input log file.
\param Entry Where to store the information parsed from the line.

\retval RLRC_NoError One valid entry is parsed.
\retval RLRC_Unknown The line is invalid.
\retval RLRC_InternalError An internal error was encountered.
*/
static enum ReadLogReturnCodeEnum Common_ReadEntry(char *Line,struct ReadLogStruct *Entry)
{
	const char *Begin;
	int IpLen;
	int HttpCodeLen;
	int UrlLen;
	int UserLen;
	int Day;
	char MonthName[4];
	int MonthNameLen;
	int Month;
	int Year;
	int Hour;
	int Minute;
	int Second;
	char *Ip;
	char *User;

	// get IP address
	Entry->Ip=Ip=Line;
	for (IpLen=0 ; *Line && *Line!=' ' ; IpLen++) Line++;
	if (*Line!=' ' || IpLen==0) return(RLRC_Unknown);

	if (!squid24) {
		// squid version <= 2.4 store the user ID in the second column: skip the first column here
		Begin=++Line;
		while (*Line && *Line!=' ') Line++;
		if (*Line!=' '|| Line==Begin) return(RLRC_Unknown);
	}

	// the ID of the user or - if the user is unidentified
	Entry->User=User=++Line;
	for (UserLen=0 ; *Line && *Line!=' ' ; UserLen++) Line++;
	if (*Line!=' ' || UserLen==0) return(RLRC_Unknown);

	if (squid24) {
		// squid version > 2.4 store the user ID in the first column: skip the second column here
		Begin=++Line;
		while (*Line && *Line!=' ') Line++;
		if (*Line!=' '|| Line==Begin) return(RLRC_Unknown);
	}

	// get the date enclosed within square brackets
	++Line;
	if (*Line!='[') return(RLRC_Unknown);
	++Line;
	Day=0;
	while (isdigit(*Line)) Day=Day*10+(*Line++-'0');
	if (*Line!='/' || Day<1 || Day>31) return(RLRC_Unknown);

	++Line;
	for (MonthNameLen=0 ; MonthNameLen<sizeof(MonthName)-1 && isalpha(*Line) ; MonthNameLen++) MonthName[MonthNameLen]=*Line++;
	if (*Line!='/') return(RLRC_Unknown);
	MonthName[MonthNameLen]='\0';
	Month=month2num(MonthName);
	if (Month>=12) return(RLRC_Unknown);

	++Line;
	Year=0;
	while (isdigit(*Line)) Year=Year*10+(*Line++-'0');
	if (*Line!=':' || Year<1900 || Year>2200) return(RLRC_Unknown);

	// get the time
	++Line;
	Hour=0;
	while (isdigit(*Line)) Hour=Hour*10+(*Line++-'0');
	if (*Line!=':' || Hour>=24) return(RLRC_Unknown);
	++Line;
	Minute=0;
	while (isdigit(*Line)) Minute=Minute*10+(*Line++-'0');
	if (*Line!=':' || Minute>=60) return(RLRC_Unknown);
	++Line;
	Second=0;
	while (isdigit(*Line)) Second=Second*10+(*Line++-'0');
	if (*Line!=' ' || Second>60) return(RLRC_Unknown); //second can be 60 due to a leap second

	// skip the timezone up to the closing ]
	while (*Line && *Line!=']') Line++;
	if (*Line!=']') return(RLRC_Unknown);

	Entry->EntryTime.tm_year=Year-1900;
	Entry->EntryTime.tm_mon=Month;
	Entry->EntryTime.tm_mday=Day;
	Entry->EntryTime.tm_hour=Hour;
	Entry->EntryTime.tm_min=Minute;
	Entry->EntryTime.tm_sec=Second;
	Entry->EntryTime.tm_isdst=-1;

	// the URL is enclosed between double qhotes
	++Line;
	if (*Line!=' ') return(RLRC_Unknown);
	++Line;
	if (*Line!='\"') return(RLRC_Unknown);

	// skip the HTTP function
	Begin=++Line;
	while (isalpha(*Line)) Line++;
	if (*Line!=' ' || Line==Begin) return(RLRC_Unknown);

	// get the URL
	Entry->Url=++Line;
	for (UrlLen=0 ; *Line && *Line!=' ' ; UrlLen++) Line++;
	if (*Line!=' ' || UrlLen==0) return(RLRC_Unknown);

	// skip the HTTP/...
	++Line;
	while (*Line && *Line!='\"') Line++;
	if (*Line!='\"') return(RLRC_Unknown);
	++Line;
	if (*Line!=' ') return(RLRC_Unknown);

	// get the HTTP code.
	Entry->HttpCode=++Line;
	for (HttpCodeLen=0 ; *Line && *Line!=' ' ; HttpCodeLen++) Line++;
	if (*Line!=' ' || HttpCodeLen==0) return(RLRC_Unknown);

	// get the number of transfered bytes.
	Begin=++Line;
	Line=Common_GetLongLongInt(Line,&Entry->DataSize);
	// some log contains more columns
	if ((*Line && *Line!=' ') || Begin==Line) return(RLRC_Unknown);

	// check the entry time
	if (mktime(&Entry->EntryTime)==-1) {
		debuga(__FILE__,__LINE__,_("Invalid date or time found in the common log file\n"));
		return(RLRC_InternalError);
	}

	// it is safe to alter the line buffer now that we are returning a valid entry
	Ip[IpLen]='\0';
	Entry->HttpCode[HttpCodeLen]='\0';
	Entry->Url[UrlLen]='\0';
	User[UserLen]='\0';

	return(RLRC_NoError);
}

//! \brief Object to read a standard common log format.
const struct ReadLogProcessStruct ReadCommonLog=
{
	/* TRANSLATORS: This is the name of the log format displayed when this format is detected in an input log file. */
	N_("common log format"),
	Common_NewFile,
	Common_ReadEntry
};
