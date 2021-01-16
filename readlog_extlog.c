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
Maximum number of columns accepted in an extended log format.

The current value is an arbitrary number chosen to have an
actual limit.
*/
#define MAX_EXT_COLUMNS 250

enum ext_col_id {
	EXTCOL_Ip,
	EXTCOL_UserName,
	EXTCOL_Date,
	EXTCOL_Time,
	EXTCOL_TimeTaken,
	EXTCOL_Bytes,
	EXTCOL_Uri,
	EXTCOL_Scheme,
	EXTCOL_Host,
	EXTCOL_Port,
	EXTCOL_Path,
	EXTCOL_Query,
	EXTCOL_Status,
	EXTCOL_UserAgent,
	EXTCOL_Last //last entry of the list !
};

//! \c True if the extended common long format is confirmed.
static bool InExtLog=false;
//! The index of relevant columns in the log file.
static int ExtCols[EXTCOL_Last];
//! The character to use as a columns separator.
static char ExtColSep[MAX_EXT_COLUMNS];
//! The number of columns according to the "fields" directive.
static int ExtColNumber;
//! Temporary buffer to concatenate the url.
static char ExtTempUrl[MAX_URL_LEN];

/*!
A new file is being read. The name of the file is \a FileName.
*/
static void ExtLog_NewFile(const char *FileName)
{
	InExtLog=false;
	ExtColNumber=0;
}

/*!
Parse the "Fields" directive listing the columns in the log. The
\a columns is a pointer to the first column of the directive.

\return \c True if the fields is valid or false if it could not
be decoded.
*/
static bool ExtLog_Fields(const char *columns)
{
	int col;
	int len;
	int prefix;
	int header_start;
	int header_end;
	int i;
	enum ext_col_id col_id;
	char col_sep;
	// see http://www.w3.org/TR/WD-logfile.html for the list of prefixes
	const char * const prefixes[]=
	{
		"c",
		"s",
		"r",
		"cs",
		"sc",
		"sr",
		"rs",
		"x",
	};

	for (i=0 ; i<EXTCOL_Last ; i++) ExtCols[i]=-1;

	col=0;
	while (*columns) {
		if (col>=MAX_EXT_COLUMNS) {
			debuga(__FILE__,__LINE__,_("Too many columns found in an extended log format. The maximum allowed is %d but it can be changed if a bigger value is legitimate\n"),MAX_EXT_COLUMNS);
			exit(EXIT_FAILURE);
		}
		prefix=-1;
		header_start=-1;
		header_end=-1;
		for (i=sizeof(prefixes)/sizeof(*prefixes)-1 ; i>=0 ; i--) {
			len=strlen(prefixes[i]);
			if (strncasecmp(columns,prefixes[i],len)==0) {
				if (columns[len]=='-') {
					prefix=len++;
					break;
				} else if (columns[len]=='(') {
					header_start=len++;
					break;
				}
			}
		}
		(void)prefix;//compiler pacifier
		if (i<0) len=0;
		for ( ; (unsigned char)columns[len]>' ' ; len++) {//skip a word and accept any separator (tab or space)
			if (header_start>=0 && columns[len]==')') header_end=len;
		}
		(void)header_end;//compiler pacifier
		col_sep=columns[len];
		ExtColSep[col]=col_sep;

		// see http://www.w3.org/TR/WD-logfile.html for list of possible identifiers
		col_id=EXTCOL_Last;
		if (len==4) {
			if (strncasecmp(columns,"c-ip",len)==0 && ExtCols[EXTCOL_Ip]<0) col_id=EXTCOL_Ip;
			else if (strncasecmp(columns,"date",len)==0) col_id=EXTCOL_Date;
			else if (strncasecmp(columns,"time",len)==0) col_id=EXTCOL_Time;
		} else if (len==5) {
			if (strncasecmp(columns,"c-dns",len)==0) col_id=EXTCOL_Ip;
		} else if (len==6) {
			if (strncasecmp(columns,"cs-uri",len)==0) col_id=EXTCOL_Uri;
		} else if (len==7) {
			if (strncasecmp(columns,"cs-host",len)==0) col_id=EXTCOL_Host;
		} else if (len==8) {
			if (strncasecmp(columns,"sc-bytes",len)==0) col_id=EXTCOL_Bytes;
		} else if (len==9) {
			if (strncasecmp(columns,"sc-status",len)==0) col_id=EXTCOL_Status;
		} else if (len==10) {
			if (strncasecmp(columns,"time-taken",len)==0) col_id=EXTCOL_TimeTaken;
		} else if (len==11) {
			if (strncasecmp(columns,"cs-username",len)==0) col_id=EXTCOL_UserName;
			if (strncasecmp(columns,"cs-uri-port",len)==0) col_id=EXTCOL_Port;
			if (strncasecmp(columns,"cs-uri-path",len)==0) col_id=EXTCOL_Path;
		} else if (len==12) {
			if (strncasecmp(columns,"cs-uri-query",len)==0) col_id=EXTCOL_Query;
		} else if (len==13) {
			if (strncasecmp(columns,"cs-uri-scheme",len)==0) col_id=EXTCOL_Scheme;
		} else if (len==14) {
			if (strncasecmp(columns,"cs(User-Agent)",len)==0) col_id=EXTCOL_UserAgent;
		}
		if (col_id!=EXTCOL_Last) {
			ExtCols[col_id]=col;
		}

		col++;
		columns+=len;
		while (*columns && (unsigned char)*columns<=' ') {
			if (*columns!=col_sep) {
				debuga(__FILE__,__LINE__,_("Multiple column separators found between two columns in the \"fields\" directive of an extended log format\n"));
				exit(EXIT_FAILURE);
			}
			columns++;
		}
	}
	ExtColNumber=col;
	return(true);
}

/*!
Decode a directive field from the \a Line.

\return RLRC_Ignore if the line is a directive or RLRC_Unknown
if the line is not a known directive.
*/
static enum ReadLogReturnCodeEnum ExtLog_Directive(const char *Line)
{
		++Line;
		if (strncasecmp(Line,"Version:",8)==0) return(RLRC_Ignore);
		if (strncasecmp(Line,"Software:",9)==0) return(RLRC_Ignore);
		if (strncasecmp(Line,"Start-Date:",11)==0) return(RLRC_Ignore);
		if (strncasecmp(Line,"End-Date:",9)==0) return(RLRC_Ignore);
		if (strncasecmp(Line,"Date:",5)==0) return(RLRC_Ignore);
		if (strncasecmp(Line,"Remark:",7)==0) return(RLRC_Ignore);
		if (strncasecmp(Line,"Fields:",7)==0) {
			Line+=7;
			while (*Line==' ' || *Line=='\t') Line++;
			if (!ExtLog_Fields(Line)) return(RLRC_Unknown);
			return(RLRC_Ignore);
		}
		return(RLRC_Unknown);
}

/*!
Get the type of the column \a col_num.

\return The type of the column or EXTCOL_Last if
the column must be ignored.
*/
static enum ext_col_id ExtLog_WhichColumn(int col_num)
{
	int i;

	for (i=0 ; i<EXTCOL_Last && ExtCols[i]!=col_num ; i++);
	return(i);
}

/*!
Scan through the string of a column.

\param Line The pointer to the beginning of the string.
\param col The column number.
*/
static char *ExtLog_GetString(char *Line,int col,char **End)
{
	bool quote;

	//skip opening double quote
	quote=(*Line=='\"');
	if (quote) ++Line;

	while (*Line) {
		if (quote) {
			if (*Line=='\"') {
				if (Line[1]=='\"') {
					Line++;//skip the first quote here, the second is skipped by the other Line++
				} else {
					if (End) *End=Line;
					Line++;//skip closing quote
					quote=false;
					break;
				}
			}
		} else {
			if (*Line==ExtColSep[col]) {
				if (End) *End=Line;
				break;
			}
		}
		Line++;
	}
	if (quote) return(NULL);//missing closing quote.
	return(Line);
}

/*!
Scan through the date in a column.

\param Line The pointer to the beginning of the string.
*/
static char *ExtLog_GetDate(char *Line,struct tm *Date)
{
	bool quote;
	int year;
	int month;
	int day;
	int next;

	//skip opening double quote
	quote=(*Line=='\"');
	if (quote) ++Line;
	if (sscanf(Line,"%d-%d-%d%n",&year,&month,&day,&next)!=3) return(NULL);
	Line+=next;
	if (quote) {
		if (*Line!='\"') return(NULL);//missing closing quote.
		++Line;
	}
	Date->tm_year=year-1900;
	Date->tm_mon=month-1;
	Date->tm_mday=day;
	return(Line);
}

/*!
Scan through the time in a column.

\param Line The pointer to the beginning of the string.
*/
static char *ExtLog_GetTime(char *Line,struct tm *Date)
{
	bool quote;
	int hour;
	int minute;
	int second;
	int next;

	//skip opening double quote
	quote=(*Line=='\"');
	if (quote) ++Line;
	if (sscanf(Line,"%d:%d:%d%n",&hour,&minute,&second,&next)!=3) return(NULL);
	Line+=next;
	if (quote) {
		if (*Line!='\"') return(NULL);//missing closing quote.
		++Line;
	}
	Date->tm_hour=hour;
	Date->tm_min=minute;
	Date->tm_sec=second;
	return(Line);
}

/*!
Scan through a number in a column.

\param Line The pointer to the beginning of the string.
\param Value A variable to store the number.
*/
static char *ExtLog_GetLongInt(char *Line,long int *Value)
{
	bool quote;

	//skip opening double quote
	quote=(*Line=='\"');
	if (quote) ++Line;
	*Value=0;
	while (isdigit(*Line)) *Value=*Value*10+(*Line++-'0');
	if (quote) {
		if (*Line!='\"') return(NULL);//missing closing quote.
		++Line;
	}
	return(Line);
}

/*!
Scan through a number in a column.

\param Line The pointer to the beginning of the string.
\param Value A variable to store the number.
*/
static char *ExtLog_GetLongLongInt(char *Line,long long int *Value)
{
	bool quote;

	//skip opening double quote
	quote=(*Line=='\"');
	if (quote) ++Line;
	*Value=0;
	while (isdigit(*Line)) *Value=*Value*10+(*Line++-'0');
	if (quote) {
		if (*Line!='\"') return(NULL);//missing closing quote.
		++Line;
	}
	return(Line);
}

/*!
Remove the quotes inside the \a string. If no quotes are known to
be in the string, the \a end_ptr is the pointer to the last
character of the string.
*/
static void ExtLog_FixString(char *string,char *end_ptr)
{
	char *dest;

	if (!string) return;//string not parsed
	if (*string!='\"' && end_ptr) { //no quotes to remove from the string
		*end_ptr='\0';
		return;
	}

	// remove first quote
	dest=string;
	if (string[1]!='\"') string++;

	// remove the quotes and end at the first unremoveable quote
	while (*string)
	{
		if (*string=='\"') {
			if (string[1]!='\"') break; //closing quote
			string++;//skip the first quote
		}
		*dest++=*string++;
	}
	*dest='\0';
}

/*!
 * Discard a empty string.
 *
 * An empty string may contain a single dash.
 *
 * \param String The string to check.
 *
 * \return The string pointer if it isn't empty or NULL if the string
 * is empty.
 */
static const char *ExtLog_FixEmptyString(const char *String)
{
	if (String && (String[0]=='\0' || (String[0]=='-' && String[1]=='\0'))) String=NULL;
	return(String);
}

/*!
 * Create the URL from the split elements.
 */
static char *ExtLog_ConcatUrl(const char *Scheme,const char *Host,const char *Port,const char *Path,const char *Query)
{
	int tlen=0;
	int len;

	Scheme=ExtLog_FixEmptyString(Scheme);
	Host=ExtLog_FixEmptyString(Host);
	if (!Scheme && !Host)
	{
		/*
		 * Example of such an entry:
		 *
		 * #Fields:
		 * date time time-taken c-ip sc-status s-action sc-bytes cs-bytes cs-method cs-uri-scheme cs-host cs-uri-port cs-uri-path cs-uri-query cs-username cs-auth-group s-hierarchy s-supplier-name rs(Content-Type) cs(Referer) cs(User-Agent) sc-filter-result cs-categories x-virus-id s-ip
		 * 2015-07-29 06:05:50 30 192.168.1.21 400 TCP_NC_MISS 903 8163 unknown - - 0 / - userid - - 10.81.0.26 - - - DENIED "unavailable" - 10.81.0.26 - - ICAP_NOT_SCANNED - - -
		 *
		 * It looks like a failed connection attempt to an unavailable resource. Let's assume it is safe to ignore it.
		 */
		ExtTempUrl[0]='\0';
		return(ExtTempUrl);
	}
	Port=ExtLog_FixEmptyString(Port);
	Path=ExtLog_FixEmptyString(Path);
	Query=ExtLog_FixEmptyString(Query);

	if (Scheme)
	{
		len=strlen(Scheme);
		if (tlen+len+3>=sizeof(ExtTempUrl))
		{
			debuga(__FILE__,__LINE__,_("URI scheme too long in log file\n"));
			exit(EXIT_FAILURE);
		}
		strcpy(ExtTempUrl,Scheme);
		strcpy(ExtTempUrl+len,"://");
		tlen+=len+3;
	}

	if (Host)
	{
		len=strlen(Host);
		if (tlen+len>=sizeof(ExtTempUrl)) len=sizeof(ExtTempUrl)-tlen-1;
		strncpy(ExtTempUrl+tlen,Host,len);
		tlen+=len;
	}

	if (tlen+2<sizeof(ExtTempUrl) && Port)
	{
		len=strlen(Port);
		if (tlen+len+1>=sizeof(ExtTempUrl)) len=sizeof(ExtTempUrl)-tlen-2;
		ExtTempUrl[tlen++]=':';
		strncpy(ExtTempUrl+tlen,Port,len);
		tlen+=len;
	}

	if (tlen<sizeof(ExtTempUrl) && Path)
	{
		len=strlen(Path);
		if (tlen+len>=sizeof(ExtTempUrl)) len=sizeof(ExtTempUrl)-tlen-1;
		strncpy(ExtTempUrl+tlen,Path,len);
		tlen+=len;
	}

	if (tlen<sizeof(ExtTempUrl) && Query)
	{
		len=strlen(Query);
		if (tlen+len>=sizeof(ExtTempUrl)) len=sizeof(ExtTempUrl)-tlen-1;
		strncpy(ExtTempUrl+tlen,Query,len);
		tlen+=len;
	}
	ExtTempUrl[tlen]='\0';
	return(ExtTempUrl);
}

/*!
Read one entry from an extended log.

\param Line One line from the input log file.
\param Entry Where to store the information parsed from the line.

\retval RLRC_NoError One valid entry is parsed.
\retval RLRC_Unknown The line is invalid.
\retval RLRC_InternalError An internal error was encountered.
*/
static enum ReadLogReturnCodeEnum ExtLog_ReadEntry(char *Line,struct ReadLogStruct *Entry)
{
	int col;
	enum ext_col_id col_id;
	char *Ip=NULL;
	char *IpEnd;
	char *User=NULL;
	char *UserEnd;
	char *UrlEnd;
	char *HttpCodeEnd;
	char *UrlScheme=NULL,*UrlSchemeEnd;
	char *UrlHost=NULL,*UrlHostEnd;
	char *UrlPort=NULL,*UrlPortEnd;
	char *UrlPath=NULL,*UrlPathEnd;
	char *UrlQuery=NULL,*UrlQueryEnd;
	char *UserAgent=NULL,*UserAgentEnd;

	// is it a directive
	if (*Line=='#') {
		enum ReadLogReturnCodeEnum status=ExtLog_Directive(Line);
		if (status!=RLRC_Unknown) InExtLog=true;
		return(status);
	}
	if (!InExtLog) return(RLRC_Unknown);

	col=0;
	while (*Line) {
		if (col>=ExtColNumber) {
			debuga(__FILE__,__LINE__,_("Too many columns in an extended log file format: %d columns found when %d have been announced\n"),col,ExtColNumber);
			return(RLRC_Unknown);
		}
		col_id=ExtLog_WhichColumn(col);
		switch (col_id)
		{
			case EXTCOL_Ip:
				Entry->Ip=Ip=Line;
				Line=ExtLog_GetString(Line,col,&IpEnd);
				if (!Line) return(RLRC_Unknown);
				break;
			case EXTCOL_UserName:
				Entry->User=User=Line;
				Line=ExtLog_GetString(Line,col,&UserEnd);
				if (!Line) return(RLRC_Unknown);
				break;
			case EXTCOL_Date:
				Line=ExtLog_GetDate(Line,&Entry->EntryTime);
				if (!Line) return(RLRC_Unknown);
				break;
			case EXTCOL_Time:
				Line=ExtLog_GetTime(Line,&Entry->EntryTime);
				if (!Line) return(RLRC_Unknown);
				break;
			case EXTCOL_TimeTaken:
				Line=ExtLog_GetLongInt(Line,&Entry->ElapsedTime);
				if (!Line) return(RLRC_Unknown);
				break;
			case EXTCOL_Bytes:
				Line=ExtLog_GetLongLongInt(Line,&Entry->DataSize);
				if (!Line) return(RLRC_Unknown);
				break;
			case EXTCOL_Uri:
				Entry->Url=Line;
				Line=ExtLog_GetString(Line,col,&UrlEnd);
				if (!Line) return(RLRC_Unknown);
				break;
			case EXTCOL_Scheme:
				UrlScheme=Line;
				Line=ExtLog_GetString(Line,col,&UrlSchemeEnd);
				if (!Line) return(RLRC_Unknown);
				break;
			case EXTCOL_Host:
				UrlHost=Line;
				Line=ExtLog_GetString(Line,col,&UrlHostEnd);
				if (!Line) return(RLRC_Unknown);
				break;
			case EXTCOL_Port:
				UrlPort=Line;
				Line=ExtLog_GetString(Line,col,&UrlPortEnd);
				if (!Line) return(RLRC_Unknown);
				break;
			case EXTCOL_Path:
				UrlPath=Line;
				Line=ExtLog_GetString(Line,col,&UrlPathEnd);
				if (!Line) return(RLRC_Unknown);
				break;
			case EXTCOL_Query:
				UrlQuery=Line;
				Line=ExtLog_GetString(Line,col,&UrlQueryEnd);
				if (!Line) return(RLRC_Unknown);
				break;
			case EXTCOL_Status:
				Entry->HttpCode=Line;
				Line=ExtLog_GetString(Line,col,&HttpCodeEnd);
				if (!Line) return(RLRC_Unknown);
				break;
			case EXTCOL_UserAgent:
				UserAgent=Line;
				Line=ExtLog_GetString(Line,col,&UserAgentEnd);
				if (!Line) return(RLRC_Unknown);
				break;
			case EXTCOL_Last://ignored column
				Line=ExtLog_GetString(Line,col,NULL);
				if (!Line) return(RLRC_Unknown);
				break;
		}
		if (*Line && *Line!=ExtColSep[col]) return(RLRC_Unknown);
		while (*Line && *Line==ExtColSep[col]) Line++;
		col++;
	}
	if (col!=ExtColNumber) {
		debuga(__FILE__,__LINE__,_("Only %d columns in an extended log file format when %d have been announced\n"),col,ExtColNumber);
		return(RLRC_Unknown);
	}

	// check the entry time
	if (mktime(&Entry->EntryTime)==-1) {
		debuga(__FILE__,__LINE__,_("Invalid date or time found in the extended log file\n"));
		return(RLRC_InternalError);
	}

	ExtLog_FixString(Ip,IpEnd);
	ExtLog_FixString(User,UserEnd);
	ExtLog_FixString(Entry->Url,UrlEnd);
	ExtLog_FixString(Entry->HttpCode,HttpCodeEnd);
	if (!Entry->Url)
	{
		ExtLog_FixString(UrlScheme,UrlSchemeEnd);
		ExtLog_FixString(UrlHost,UrlHostEnd);
		ExtLog_FixString(UrlPort,UrlPortEnd);
		ExtLog_FixString(UrlPath,UrlPathEnd);
		ExtLog_FixString(UrlQuery,UrlQueryEnd);
		Entry->Url=ExtLog_ConcatUrl(UrlScheme,UrlHost,UrlPort,UrlPath,UrlQuery);
	}
	ExtLog_FixString(UserAgent,UserAgentEnd);
	Entry->UserAgent=ExtLog_FixEmptyString(UserAgent);

	return(RLRC_NoError);
}

//! \brief Object to read an extended log.
const struct ReadLogProcessStruct ReadExtLog=
{
	/* TRANSLATORS: This is the name of the log format displayed when this format is detected in an input log file. */
	N_("extended log format"),
	ExtLog_NewFile,
	ExtLog_ReadEntry
};
