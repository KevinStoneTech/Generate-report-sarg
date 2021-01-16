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

//! \c True if the current log is known to be a sarg parsed log.
static bool InSargLog=false;
//! \c True if the file name is invalid.
static bool InvalidFileName=true;
//! The last period extracted from the log file name.
static struct periodstruct SargPeriod;

/*!
A new file is being read. The name of the file is \a FileName.
*/
static void Sarg_NewFile(const char *FileName)
{
	InSargLog=false;
	InvalidFileName=(getperiod_fromsarglog(FileName,&SargPeriod)<0);
}

/*!
Read one entry from a sarg generated log.

\param Line One line from the input log file.
\param Entry Where to store the information parsed from the line.

\retval RLRC_NoError One valid entry is parsed.
\retval RLRC_Unknown The line is invalid.
\retval RLRC_InternalError An internal error was encountered.
*/
static enum ReadLogReturnCodeEnum Sarg_ReadEntry(char *Line,struct ReadLogStruct *Entry)
{
	const char *Begin;
	int IpLen;
	int HttpCodeLen;
	int UrlLen;
	int UserLen;
	int Day;
	int Month;
	int Year;
	int Hour;
	int Minute;
	int Second;
	char *Ip;
	char *User;

	if (strncmp(Line,"*** SARG Log ***",16)==0) {
		if (InvalidFileName) {
			debuga(__FILE__,__LINE__,_("The name of the file is invalid for a sarg log\n"));
			exit(EXIT_FAILURE);
		}
		getperiod_merge(&period,&SargPeriod);
		InSargLog=true;
		return(RLRC_Ignore);
	}
	if (!InSargLog) return(RLRC_Unknown);

	// get the date
	Day=0;
	while (isdigit(*Line)) Day=Day*10+(*Line++-'0');
	if (*Line!='/' || Day<1 || Day>31) return(RLRC_Unknown);

	++Line;
	Month=0;
	while (isdigit(*Line)) Month=Month*10+(*Line++-'0');
	if (*Line!='/') return(RLRC_Unknown);
	if (Month<=0 || Month>12) return(RLRC_Unknown);

	++Line;
	Year=0;
	while (isdigit(*Line)) Year=Year*10+(*Line++-'0');
	if (*Line!='\t' || Year<1900 || Year>2200) return(RLRC_Unknown);

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
	if (*Line!='\t' || Second>60) return(RLRC_Unknown); //second can be 60 due to a leap second

	Entry->EntryTime.tm_year=Year-1900;
	Entry->EntryTime.tm_mon=Month-1;
	Entry->EntryTime.tm_mday=Day;
	Entry->EntryTime.tm_hour=Hour;
	Entry->EntryTime.tm_min=Minute;
	Entry->EntryTime.tm_sec=Second;
	Entry->EntryTime.tm_isdst=-1;

	// the ID of the user
	Entry->User=User=++Line;
	for (UserLen=0 ; *Line && *Line!='\t' ; UserLen++) Line++;
	if (*Line!='\t' || UserLen==0) return(RLRC_Unknown);

	// get IP address
	Entry->Ip=Ip=++Line;
	for (IpLen=0 ; *Line && *Line!='\t' ; IpLen++) Line++;
	if (*Line!='\t' || IpLen==0) return(RLRC_Unknown);

	// get the URL
	Entry->Url=++Line;
	for (UrlLen=0 ; *Line && *Line!='\t' ; UrlLen++) Line++;
	if (*Line!='\t' || UrlLen==0) return(RLRC_Unknown);

	// get the number of transfered bytes.
	Begin=++Line;
	Entry->DataSize=0LL;
	while (isdigit(*Line)) Entry->DataSize=Entry->DataSize*10+(*Line++-'0');
	if (*Line!='\t' || Begin==Line) return(RLRC_Unknown);

	// get the HTTP code.
	Entry->HttpCode=++Line;
	for (HttpCodeLen=0 ; *Line && *Line!='\t' ; HttpCodeLen++) Line++;
	if (*Line!='\t' || HttpCodeLen==0) return(RLRC_Unknown);

	// get the elapsed time.
	Begin=++Line;
	Entry->ElapsedTime=0L;
	while (isdigit(*Line)) Entry->ElapsedTime=Entry->ElapsedTime*10+(*Line++-'0');
	if (*Line!='\t' || Line==Begin) return(RLRC_Unknown);

	// get the smart filter
	//! \bug Smart filter ignored from sarg log format.

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

//! \brief Object to read a standard squid log format.
const struct ReadLogProcessStruct ReadSargLog=
{
	/* TRANSLATORS: This is the name of the log format displayed when this format is detected in an input log file. */
	N_("sarg log format"),
	Sarg_NewFile,
	Sarg_ReadEntry
};
