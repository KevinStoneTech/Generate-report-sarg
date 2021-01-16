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
#include "include/filelist.h"

#define REPORT_EVERY_X_LINES 5000
#define MAX_OPEN_USER_FILES 10

struct userfilestruct
{
	struct userfilestruct *next;
	struct userinfostruct *user;
	FILE *file;
};

enum ExcludeReasonEnum
{
	//! User name too long.
	ER_UserNameTooLong,
	//! Squid logged an incomplete query received from the client.
	ER_IncompleteQuery,
	//! Log file turned over.
	ER_LogfileTurnedOver,
	//! Excluded by exclude_string from sarg.conf.
	ER_ExcludeString,
	//! Unknown input log file format.
	ER_UnknownFormat,
	//! Line to be ignored from the input log file.
	ER_FormatData,
	//! Entry not withing the requested date range. 
	ER_OutOfDateRange,
	//! Ignored week day.
	ER_OutOfWDayRange,
	//! Ignored hour.
	ER_OutOfHourRange,
	//! User is not in the include_users list.
	ER_User,
	//! HTTP code excluded by exclude_code file.
	ER_HttpCode,
	//! Invalid character found in user name.
	ER_InvalidUserChar,
	//! No URL in entry.
	ER_NoUrl,
	//! Not the IP address requested with -a.
	ER_UntrackedIpAddr,
	//! URL excluded by -c or exclude_hosts.
	ER_Url,
	//! Entry time outside of requested hour range.
	ER_OutOfTimeRange,
	//! Not the URL requested by -s.
	ER_UntrackedUrl,
	//! No user in entry.
	ER_NoUser,
	//! Not the user requested by -u.
	ER_UntrackedUser,
	//! System user.
	ER_SysUser,
	//! User ignored by exclude_users 
	ER_IgnoredUser,

	ER_Last //!< last entry of the list
};

int weekdays[7] = { 1, 2, 3, 4, 5, 6, 7};
int hours[24] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24};
//! Domain suffix to strip from the user name.
char StripUserSuffix[MAX_USER_LEN]="";
//! Length of the suffix to strip from the user name.
int StripSuffixLen=0;

extern FileListObject AccessLog;

extern const struct ReadLogProcessStruct ReadSquidLog;
extern const struct ReadLogProcessStruct ReadCommonLog;
extern const struct ReadLogProcessStruct ReadSargLog;
extern const struct ReadLogProcessStruct ReadExtLog;

//! The list of the supported log formats.
static const struct ReadLogProcessStruct * const LogFormats[]=
{
	&ReadSquidLog,
	&ReadCommonLog,
	&ReadSargLog,
	&ReadExtLog
};

//! The path to the sarg log file.
static char SargLogFile[4096]="";
//! Handle to the sarg log file. NULL if not created.
static FILE *fp_log=NULL;
//! The number of records read from the input logs.
static long int totregsl=0;
//! The number of records kept.
static long int totregsg=0;
//! The number of records excluded.
static long int totregsx=0;
//! The beginning of a linked list of user's file.
static struct userfilestruct *first_user_file=NULL;
//! Count the number of occurence of each input log format.
static unsigned long int format_count[sizeof(LogFormats)/sizeof(*LogFormats)];
//! The minimum date found in the input logs.
static int mindate=0;
static int maxdate=0;
//! Count the number of excluded records.
static unsigned long int excluded_count[ER_Last];
//! Earliest date found in the log.
static int EarliestDate=-1;
//! The earliest date in time format.
static struct tm EarliestDateTime;
//! Latest date found in the log.
static int LatestDate=-1;
//! The latest date in time format.
static struct tm LatestDateTime;

/*!
 * Read from standard input.
 *
 * \param Data The file object.
 * \param Buffer The boffer to store the data read.
 * \param Size How many bytes to read.
 *
 * \return The number of bytes read.
 */
static int Stdin_Read(void *Data,void *Buffer,int Size)
{
	return(fread(Buffer,1,Size,(FILE *)Data));
}

/*!
 * Check if end of file is reached.
 *
 * \param Data The file object.
 *
 * \return \c True if end of file is reached.
 */
static int Stdin_Eof(void *Data)
{
	return(feof((FILE *)Data));
}

/*!
 * Mimic a close of standard input but do nothing
 *
 * \param Data File to close.
 *
 * \return EOF on error.
 */
static int Stdin_Close(void *Data)
{
	return(0);
}

/*!
 * Open a file object to read from standard input.
 *
 * \return The object to pass to other function in this module.
 */
static FileObject *Stdin_Open(void)
{
	FileObject *File;

	FileObject_SetLastOpenError(NULL);
	File=calloc(1,sizeof(*File));
	if (!File)
	{
		FileObject_SetLastOpenError(_("Not enough memory"));
		return(NULL);
	}
	File->Data=stdin;
	File->Read=Stdin_Read;
	File->Eof=Stdin_Eof;
	File->Rewind=NULL;
	File->Close=Stdin_Close;
	return(File);
}

/*!
 * Initialize the memory structure needed by LogLine_Parse() to parse
 * a log line.
 *
 * \param log_line The structure to initialize.
 */
void LogLine_Init(struct LogLineStruct *log_line)
{
	log_line->current_format=NULL;
	log_line->current_format_idx=-1;
	log_line->file_name="";
	log_line->successive_errors=0;
	log_line->total_errors=0;
}

/*!
 * Set the name of the log file being parsed.
 *
 * \param log_line Data structure to parse the log line.
 * \param file_name The name of the log file being read.
 */
void LogLine_File(struct LogLineStruct *log_line,const char *file_name)
{
	log_line->file_name=file_name;
}

/*!
 * Parse the next line from a log file.
 *
 * \param log_line A buffer to store the data about the current parsing.
 * \param log_entry The variable to store the parsed data.
 * \param linebuf The text line read from the log file.
 *
 * \return
 */
enum ReadLogReturnCodeEnum LogLine_Parse(struct LogLineStruct *log_line,struct ReadLogStruct *log_entry,char *linebuf)
{
	enum ReadLogReturnCodeEnum log_entry_status=RLRC_Unknown;
	int x;

	if (log_line->current_format)
	{
		memset(log_entry,0,sizeof(*log_entry));
		log_entry_status=log_line->current_format->ReadEntry(linebuf,log_entry);
	}

	// find out what line format to use
	if (log_entry_status==RLRC_Unknown)
	{
		for (x=0 ; x<(int)(sizeof(LogFormats)/sizeof(*LogFormats)) ; x++)
		{
			if (LogFormats[x]==log_line->current_format) continue;
			memset(log_entry,0,sizeof(*log_entry));
			log_entry_status=LogFormats[x]->ReadEntry(linebuf,log_entry);
			if (log_entry_status!=RLRC_Unknown)
			{
				log_line->current_format=LogFormats[x];
				log_line->current_format_idx=x;
				if (debugz>=LogLevel_Process)
				{
					/* TRANSLATORS: The argument is the log format name as translated by you. */
					debuga(__FILE__,__LINE__,_("Log format identified as \"%s\" for %s\n"),_(log_line->current_format->Name),log_line->file_name);
				}
				break;
			}
		}
		if (x>=(int)(sizeof(LogFormats)/sizeof(*LogFormats)))
		{
			if (++log_line->successive_errors>NumLogSuccessiveErrors) {
				debuga(__FILE__,__LINE__,ngettext("%d consecutive error found in the input log file %s\n",
												"%d consecutive errors found in the input log file %s\n",log_line->successive_errors),log_line->successive_errors,log_line->file_name);
				exit(EXIT_FAILURE);
			}
			if (NumLogTotalErrors>=0 && ++log_line->total_errors>NumLogTotalErrors) {
				debuga(__FILE__,__LINE__,ngettext("%d error found in the input log file (last in %s)\n",
												"%d errors found in the input log file (last in %s)\n",log_line->total_errors),log_line->total_errors,log_line->file_name);
				exit(EXIT_FAILURE);
			}
			debuga(__FILE__,__LINE__,_("The following line read from %s could not be parsed and is ignored\n%s\n"),log_line->file_name,linebuf);
		}
		else
			log_line->successive_errors=0;
	}

	if (log_line->current_format_idx<0 || log_line->current_format==NULL) {
		debuga(__FILE__,__LINE__,_("Sarg failed to determine the format of the input log file %s\n"),log_line->file_name);
		exit(EXIT_FAILURE);
	}
	if (log_entry_status==RLRC_InternalError) {
		debuga(__FILE__,__LINE__,_("Internal error encountered while processing %s\nSee previous message to know the reason for that error.\n"),log_line->file_name);
		exit(EXIT_FAILURE);
	}
	return(log_entry_status);
}

/*!
Read a single log file.

\param arq The log file name to read.
*/
static void ReadOneLogFile(struct ReadLogDataStruct *Filter,const char *arq)
{
	longline line;
	char *linebuf;
	char *str;
	char hora[30];
	char dia[128]="";
	char tmp3[MAXLEN]="";
	char download_url[MAXLEN];
	char smartfilter[MAXLEN];
	const char *url;
	int OutputNonZero = REPORT_EVERY_X_LINES ;
	int idata=0;
	int x;
	int hmr;
	int nopen;
	int maxopenfiles=MAX_OPEN_USER_FILES;
	unsigned long int recs1=0UL;
	unsigned long int recs2=0UL;
	FileObject *fp_in=NULL;
	bool download_flag=false;
	bool id_is_ip;
	enum ReadLogReturnCodeEnum log_entry_status;
	enum UserProcessError PUser;
	struct stat logstat;
	struct getwordstruct gwarea;
	struct userfilestruct *prev_ufile;
	struct userinfostruct *uinfo;
	struct userfilestruct *ufile;
	struct userfilestruct *ufile1;
	struct ReadLogStruct log_entry;
	struct LogLineStruct log_line;
	FILE *UseragentLog=NULL;

	LogLine_Init(&log_line);
	LogLine_File(&log_line,arq);
	for (x=0 ; x<sizeof(LogFormats)/sizeof(*LogFormats) ; x++)
		if (LogFormats[x]->NewFile)
			LogFormats[x]->NewFile(arq);

	if (arq[0]=='-' && arq[1]=='\0') {
		fp_in=Stdin_Open();
		if (debug)
			debuga(__FILE__,__LINE__,_("Reading access log file: from stdin\n"));
	} else {
		if (Filter->DateRange[0]!='\0') {
			if (stat(arq,&logstat)!=0) {
				debuga(__FILE__,__LINE__,_("Cannot get the modification time of input log file %s (%s). Processing it anyway\n"),arq,strerror(errno));
			} else {
				struct tm *logtime=localtime(&logstat.st_mtime);
				if ((logtime->tm_year+1900)*10000+(logtime->tm_mon+1)*100+logtime->tm_mday<Filter->StartDate) {
					debuga(__FILE__,__LINE__,_("Ignoring old log file %s\n"),arq);
					return;
				}
			}
		}
		fp_in=decomp(arq);
		if (fp_in==NULL) {
			debuga(__FILE__,__LINE__,_("Cannot open input log file \"%s\": %s\n"),arq,FileObject_GetLastOpenError());
			exit(EXIT_FAILURE);
		}
		if (debug) debuga(__FILE__,__LINE__,_("Reading access log file: %s\n"),arq);
	}

	download_flag=false;

	recs1=0UL;
	recs2=0UL;

	// pre-read the file only if we have to show stats
	if (ShowReadStatistics && ShowReadPercent && fp_in->Rewind) {
		int nread,i;
		bool skipcr=false;
		char tmp4[MAXLEN];

		while ((nread=FileObject_Read(fp_in,tmp4,sizeof(tmp4)))>0) {
			for (i=0 ; i<nread ; i++)
				if (skipcr) {
					if (tmp4[i]!='\n' && tmp4[i]!='\r') {
						skipcr=false;
					}
				} else {
					if (tmp4[i]=='\n' || tmp4[i]=='\r') {
						skipcr=true;
						recs1++;
					}
				}
		}
		FileObject_Rewind(fp_in);
		printf(_("SARG: Records in file: %lu, reading: %3.2f%%"),recs1,(float) 0);
		putchar('\r');
		fflush( stdout ) ;
	}

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),arq);
		exit(EXIT_FAILURE);
	}

	while ((linebuf=longline_read(fp_in,line))!=NULL) {
		lines_read++;

		recs2++;
		if (ShowReadStatistics && --OutputNonZero<=0) {
			if (recs1>0) {
				double perc = recs2 * 100. / recs1 ;
				printf(_("SARG: Records in file: %lu, reading: %3.2lf%%"),recs2,perc);
			} else {
				printf(_("SARG: Records in file: %lu"),recs2);
			}
			putchar('\r');
			fflush (stdout);
			OutputNonZero = REPORT_EVERY_X_LINES ;
		}

		/*
		The following checks are retained here as I don't know to
		what format they apply. They date back to pre 2.4 versions.
		*/
		//if (blen < 58) continue; //this test conflict with the reading of the sarg log header line
		if (strstr(linebuf,"HTTP/0.0") != 0) {//recorded by squid when encountering an incomplete query
			excluded_count[ER_IncompleteQuery]++;
			continue;
		}
		if (strstr(linebuf,"logfile turned over") != 0) {//reported by newsyslog
			excluded_count[ER_LogfileTurnedOver]++;
			continue;
		}

		// exclude_string
		if (ExcludeString[0] != '\0') {
			bool exstring=false;
			getword_start(&gwarea,ExcludeString);
			while(strchr(gwarea.current,':') != 0) {
				if (getword_multisep(val1,sizeof(val1),&gwarea,':')<0) {
					debuga(__FILE__,__LINE__,_("Invalid record in exclusion string\n"));
					exit(EXIT_FAILURE);
				}
				if ((str=(char *) strstr(linebuf,val1)) != (char *) NULL ) {
					exstring=true;
					break;
				}
			}
			if (!exstring && (str=(char *) strstr(linebuf,gwarea.current)) != (char *) NULL )
				exstring=true;
			if (exstring) {
				excluded_count[ER_ExcludeString]++;
				continue;
			}
		}

		totregsl++;
		if (debugz>=LogLevel_Data)
			printf("BUF=%s\n",linebuf);

		// process the line
		log_entry_status=LogLine_Parse(&log_line,&log_entry,linebuf);
		if (log_entry_status==RLRC_Unknown)
		{
			excluded_count[ER_UnknownFormat]++;
			continue;
		}
		if (log_entry_status==RLRC_Ignore) {
			excluded_count[ER_FormatData]++;
			continue;
		}
		format_count[log_line.current_format_idx]++;

		if (!fp_log && ParsedOutputLog[0] && log_line.current_format!=&ReadSargLog) {
			if (access(ParsedOutputLog,R_OK) != 0) {
				my_mkdir(ParsedOutputLog);
			}
			if (snprintf(SargLogFile,sizeof(SargLogFile),"%s/sarg_temp.log",ParsedOutputLog)>=sizeof(SargLogFile)) {
				debuga(__FILE__,__LINE__,_("Path too long: "));
				debuga_more("%s/sarg_temp.log\n",ParsedOutputLog);
				exit(EXIT_FAILURE);
			}
			if ((fp_log=MY_FOPEN(SargLogFile,"w"))==NULL) {
				debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),SargLogFile,strerror(errno));
				exit(EXIT_FAILURE);
			}
			fputs("*** SARG Log ***\n",fp_log);
		}

		if (log_entry.Ip==NULL) {
			debuga(__FILE__,__LINE__,_("Unknown input log file format: no IP addresses\n"));
			break;
		}
		if (log_entry.User==NULL) {
			debuga(__FILE__,__LINE__,_("Unknown input log file format: no user\n"));
			break;
		}
		if (log_entry.Url==NULL) {
			debuga(__FILE__,__LINE__,_("Unknown input log file format: no URL\n"));
			break;
		}

		idata=builddia(log_entry.EntryTime.tm_mday,log_entry.EntryTime.tm_mon+1,log_entry.EntryTime.tm_year+1900);
		if (debugz>=LogLevel_Data)
			printf("DATE=%s IDATA=%d DFROM=%d DUNTIL=%d\n",Filter->DateRange,idata,Filter->StartDate,Filter->EndDate);

		if (EarliestDate<0 || idata<EarliestDate) {
			EarliestDate=idata;
			memcpy(&EarliestDateTime,&log_entry.EntryTime,sizeof(struct tm));
		}
		if (LatestDate<0 || idata>LatestDate) {
			LatestDate=idata;
			memcpy(&LatestDateTime,&log_entry.EntryTime,sizeof(struct tm));
		}
		if (Filter->DateRange[0] != '\0'){
			if (idata<Filter->StartDate || idata>Filter->EndDate) {
				excluded_count[ER_OutOfDateRange]++;
				continue;
			}
		}

		// Record only hours usage which is required
		if (!numlistcontains(weekdays, 7, log_entry.EntryTime.tm_wday))
		{
			excluded_count[ER_OutOfWDayRange]++;
			continue;
		}

		if (!numlistcontains(hours, 24, log_entry.EntryTime.tm_hour))
		{
			excluded_count[ER_OutOfHourRange]++;
			continue;
		}

		PUser=process_user(&log_entry.User,log_entry.Ip,&id_is_ip);
		switch (PUser)
		{
			case USERERR_NoError:
				break;
			case USERERR_NameTooLong:
				if (debugz>=LogLevel_Process) debuga(__FILE__,__LINE__,_("User ID too long: %s\n"),log_entry.User);
				excluded_count[ER_UserNameTooLong]++;
				totregsx++;
				continue;
			case USERERR_Excluded:
				excluded_count[ER_User]++;
				continue;
			case USERERR_InvalidChar:
				excluded_count[ER_InvalidUserChar]++;
				continue;
			case USERERR_EmptyUser:
				excluded_count[ER_NoUser]++;
				continue;
			case USERERR_SysUser:
				excluded_count[ER_SysUser]++;
				continue;
			case USERERR_Ignored:
				excluded_count[ER_IgnoredUser]++;
				totregsx++;
				continue;
			case USERERR_Untracked:
				excluded_count[ER_UntrackedUser]++;
				continue;
		}

		if (vercode(log_entry.HttpCode)) {
			if (debugz>=LogLevel_Process) debuga(__FILE__,__LINE__,_("Excluded code: %s\n"),log_entry.HttpCode);
			excluded_count[ER_HttpCode]++;
			totregsx++;
			continue;
		}

		// replace any tab by a single space
		for (str=log_entry.Url ; *str ; str++)
			if (*str=='\t') *str=' ';
		for (str=log_entry.HttpCode ; *str ; str++)
			if (*str=='\t') *str=' ';

		if (log_line.current_format!=&ReadSargLog) {
			/*
			The full URL is not saved in sarg log. There is no point in testing the URL to detect
			a downloaded file.
			*/
			download_flag=is_download_suffix(log_entry.Url);
			if (download_flag) {
				safe_strcpy(download_url,log_entry.Url,sizeof(download_url));
			}
		} else
			download_flag=false;

		url=process_url(log_entry.Url,LongUrl);
		if (!url || url[0] == '\0') {
			excluded_count[ER_NoUrl]++;
			continue;
		}

		if (addr[0] != '\0'){
			if (strcmp(addr,log_entry.Ip)!=0) {
				excluded_count[ER_UntrackedIpAddr]++;
				continue;
			}
		}
		if (Filter->HostFilter) {
			if (!vhexclude(url)) {
				if (debugz>=LogLevel_Data) debuga(__FILE__,__LINE__,_("Excluded site: %s\n"),url);
				excluded_count[ER_Url]++;
				totregsx++;
				continue;
			}
		}

		if (Filter->StartTime >= 0 && Filter->EndTime >= 0) {
			hmr=log_entry.EntryTime.tm_hour*100+log_entry.EntryTime.tm_min;
			if (hmr < Filter->StartTime || hmr >= Filter->EndTime) {
				excluded_count[ER_OutOfTimeRange]++;
				continue;
			}
		}

		if (site[0] != '\0'){
			if (strstr(url,site)==0) {
				excluded_count[ER_UntrackedUrl]++;
				continue;
			}
		}

		if (log_entry.DataSize<0) log_entry.DataSize=0;

		if (log_entry.ElapsedTime<0) log_entry.ElapsedTime=0;
		if (Filter->max_elapsed>0 && log_entry.ElapsedTime>Filter->max_elapsed) {
			log_entry.ElapsedTime=0;
		}

		if ((str=(char *) strstr(linebuf, "[SmartFilter:")) != (char *) NULL ) {
			fixendofline(str);
			snprintf(smartfilter,sizeof(smartfilter),"\"%s\"",str+1);
		} else strcpy(smartfilter,"\"\"");

		nopen=0;
		prev_ufile=NULL;
		for (ufile=first_user_file ; ufile && strcmp(log_entry.User,ufile->user->id)!=0 ; ufile=ufile->next) {
			prev_ufile=ufile;
			if (ufile->file) nopen++;
		}
		if (!ufile) {
			ufile=malloc(sizeof(*ufile));
			if (!ufile) {
				debuga(__FILE__,__LINE__,_("Not enough memory to store the user %s\n"),log_entry.User);
				exit(EXIT_FAILURE);
			}
			memset(ufile,0,sizeof(*ufile));
			ufile->next=first_user_file;
			first_user_file=ufile;
			/*
			 * This id_is_ip stuff is just to store the string only once if the user is
			 * identified by its IP address instead of a distinct ID and IP address.
			 */
			uinfo=userinfo_create(log_entry.User,(id_is_ip) ? NULL : log_entry.Ip);
			ufile->user=uinfo;
			nusers++;
		} else {
			if (prev_ufile) {
				prev_ufile->next=ufile->next;
				ufile->next=first_user_file;
				first_user_file=ufile;
			}
		}
#ifdef ENABLE_DOUBLE_CHECK_DATA
		if (strcmp(log_entry.HttpCode,"TCP_DENIED/407")!=0) {
			ufile->user->nbytes+=log_entry.DataSize;
			ufile->user->elap+=log_entry.ElapsedTime;
		}
#endif

		if (ufile->file==NULL) {
			if (nopen>=maxopenfiles) {
				x=0;
				for (ufile1=first_user_file ; ufile1 ; ufile1=ufile1->next) {
					if (ufile1->file!=NULL) {
						if (x>=maxopenfiles) {
							if (fclose(ufile1->file)==EOF) {
								debuga(__FILE__,__LINE__,_("Write error in log file of user %s: %s\n"),ufile1->user->id,strerror(errno));
								exit(EXIT_FAILURE);
							}
							ufile1->file=NULL;
						}
						x++;
					}
				}
			}
			if (snprintf (tmp3, sizeof(tmp3), "%s/%s.user_unsort", tmp, ufile->user->filename)>=sizeof(tmp3)) {
				debuga(__FILE__,__LINE__,_("Temporary user file name too long: %s/%s.user_unsort\n"), tmp, ufile->user->filename);
				exit(EXIT_FAILURE);
			}
			if ((ufile->file = MY_FOPEN (tmp3, "a")) == NULL) {
				debuga(__FILE__,__LINE__,_("(log) Cannot open temporary file %s: %s\n"), tmp3, strerror(errno));
				exit(EXIT_FAILURE);
			}
		}

		strftime(dia, sizeof(dia), "%d/%m/%Y",&log_entry.EntryTime);
		strftime(hora,sizeof(hora),"%H:%M:%S",&log_entry.EntryTime);

		if (fprintf(ufile->file, "%s\t%s\t%s\t%s\t%"PRIu64"\t%s\t%ld\t%s\n",dia,hora,
								log_entry.Ip,url,(uint64_t)log_entry.DataSize,
								log_entry.HttpCode,log_entry.ElapsedTime,smartfilter)<=0) {
			debuga(__FILE__,__LINE__,_("Write error in the log file of user %s\n"),log_entry.User);
			exit(EXIT_FAILURE);
		}
		records_kept++;

		if (fp_log && log_line.current_format!=&ReadSargLog) {
			fprintf(fp_log, "%s\t%s\t%s\t%s\t%s\t%"PRIu64"\t%s\t%ld\t%s\n",dia,hora,
							log_entry.User,log_entry.Ip,url,(uint64_t)log_entry.DataSize,
							log_entry.HttpCode,log_entry.ElapsedTime,smartfilter);
		}

		totregsg++;

		denied_write(&log_entry);
		authfail_write(&log_entry);
		if (download_flag) download_write(&log_entry,download_url);
		if (log_entry.UserAgent)
		{
			if (!UseragentLog)
				UseragentLog=UserAgent_Open();
			UserAgent_Write(UseragentLog,&log_entry.EntryTime,log_entry.Ip,log_entry.User,log_entry.UserAgent);
		}

		if (log_line.current_format!=&ReadSargLog) {
			if (period.start.tm_year==0 || idata<mindate || compare_date(&period.start,&log_entry.EntryTime)>0){
				mindate=idata;
				memcpy(&period.start,&log_entry.EntryTime,sizeof(log_entry.EntryTime));
			}
			if (period.end.tm_year==0 || idata>maxdate || compare_date(&period.end,&log_entry.EntryTime)<0) {
				maxdate=idata;
				memcpy(&period.end,&log_entry.EntryTime,sizeof(log_entry.EntryTime));
			}
		}

		if (debugz>=LogLevel_Data){
			printf("IP=\t%s\n",log_entry.Ip);
			printf("USER=\t%s\n",log_entry.User);
			printf("ELAP=\t%ld\n",log_entry.ElapsedTime);
			printf("DATE=\t%s\n",dia);
			printf("TIME=\t%s\n",hora);
			//printf("FUNC=\t%s\n",fun);
			printf("URL=\t%s\n",url);
			printf("CODE=\t%s\n",log_entry.HttpCode);
			printf("LEN=\t%"PRIu64"\n",(uint64_t)log_entry.DataSize);
		}
	}
	longline_destroy(&line);

	if (FileObject_Close(fp_in)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),arq,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}
	if (UseragentLog) fclose(UseragentLog);
	if (ShowReadStatistics) {
		if (ShowReadPercent)
			printf(_("SARG: Records in file: %lu, reading: %3.2f%%\n"),recs2, (float) 100 );
		else
			printf(_("SARG: Records in file: %lu\n"),recs2);
	}
}

/*!
 * Display a line with the excluded entries count.
 *
 * \param Explain A translated string explaining the exluded count.
 * \param Reason The reason number.
 */
static void DisplayExcludeCount(const char *Explain,enum ExcludeReasonEnum Reason)
{
	if (excluded_count[Reason]>0) {
		debuga(__FILE__,__LINE__,"   %s: %lu\n",Explain,excluded_count[Reason]);
	}
}

/*!
Read the log files.

\param Filter The filtering parameters for the file to load.

\retval 1 Records found.
\retval 0 No record found.
*/
int ReadLogFile(struct ReadLogDataStruct *Filter)
{
	int x;
	int cstatus;
	struct userfilestruct *ufile;
	struct userfilestruct *ufile1;
	FileListIterator FIter;
	const char *file;

	for (x=0 ; x<sizeof(format_count)/sizeof(*format_count) ; x++) format_count[x]=0;
	for (x=0 ; x<sizeof(excluded_count)/sizeof(*excluded_count) ; x++) excluded_count[x]=0;
	first_user_file=NULL;

	if (!dataonly) {
		denied_open();
		authfail_open();
		download_open();
	}

	FIter=FileListIter_Open(AccessLog);
	while ((file=FileListIter_Next(FIter))!=NULL)
		ReadOneLogFile(Filter,file);
	FileListIter_Close(FIter);

	if (fp_log != NULL) {
		char val2[40];
		char val4[4096];//val4 must not be bigger than SargLogFile without fixing the strcpy below

		if (fclose(fp_log)==EOF) {
			debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),SargLogFile,strerror(errno));
			exit(EXIT_FAILURE);
		}
		strftime(val2,sizeof(val2),"%d%m%Y_%H%M",&period.start);
		strftime(val1,sizeof(val1),"%d%m%Y_%H%M",&period.end);
		if (snprintf(val4,sizeof(val4),"%s/sarg-%s-%s.log",ParsedOutputLog,val2,val1)>=sizeof(val4)) {
			debuga(__FILE__,__LINE__,_("Path too long: "));
			debuga_more("%s/sarg-%s-%s.log\n",ParsedOutputLog,val2,val1);
			exit(EXIT_FAILURE);
		}
		if (rename(SargLogFile,val4)) {
			debuga(__FILE__,__LINE__,_("failed to rename %s to %s - %s\n"),SargLogFile,val4,strerror(errno));
		} else {
			strcpy(SargLogFile,val4);

			if (strcmp(ParsedOutputLogCompress,"nocompress") != 0 && ParsedOutputLogCompress[0] != '\0') {
				/*
				No double quotes around ParsedOutputLogCompress because it may contain command line options. If double quotes are
				necessary around the command name, put them in the configuration file.
				*/
				if (snprintf(val1,sizeof(val1),"%s \"%s\"",ParsedOutputLogCompress,SargLogFile)>=sizeof(val1)) {
					debuga(__FILE__,__LINE__,_("Command too long: %s \"%s\"\n"),ParsedOutputLogCompress,SargLogFile);
					exit(EXIT_FAILURE);
				}
				cstatus=system(val1);
				if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
					debuga(__FILE__,__LINE__,_("command return status %d\n"),WEXITSTATUS(cstatus));
					debuga(__FILE__,__LINE__,_("command: %s\n"),val1);
					exit(EXIT_FAILURE);
				}
			}
		}
		if (debug)
			debuga(__FILE__,__LINE__,_("Sarg parsed log saved as %s\n"),SargLogFile);
	}

	denied_close();
	authfail_close();
	download_close();

	for (ufile=first_user_file ; ufile ; ufile=ufile1) {
		ufile1=ufile->next;
		if (ufile->file!=NULL && fclose(ufile->file)==EOF) {
			debuga(__FILE__,__LINE__,_("Write error in log file of user %s: %s\n"),ufile->user->id,strerror(errno));
			exit(EXIT_FAILURE);
		}
		free(ufile);
	}

	if (debug) {
		unsigned long int totalcount=0;

		debuga(__FILE__,__LINE__,_("   Records read: %ld, written: %ld, excluded: %ld\n"),totregsl,totregsg,totregsx);

		for (x=sizeof(excluded_count)/sizeof(*excluded_count)-1 ; x>=0 && excluded_count[x]>0 ; x--);
		if (x>=0) {
			debuga(__FILE__,__LINE__,_("Reasons for excluded entries:\n"));
			DisplayExcludeCount(_("User name too long"),ER_UserNameTooLong);
			DisplayExcludeCount(_("Squid logged an incomplete query received from the client"),ER_IncompleteQuery);
			DisplayExcludeCount(_("Log file turned over"),ER_LogfileTurnedOver);
			DisplayExcludeCount(_("Excluded by \"exclude_string\" in sarg.conf"),ER_ExcludeString);
			DisplayExcludeCount(_("Unknown input log file format"),ER_UnknownFormat);
			DisplayExcludeCount(_("Line ignored by the input log format"),ER_FormatData);
			DisplayExcludeCount(_("Time outside the requested date range (-d)"),ER_OutOfDateRange);
			DisplayExcludeCount(_("Ignored week day (\"weekdays\" parameter in sarg.conf)"),ER_OutOfWDayRange);
			DisplayExcludeCount(_("Ignored hour (\"hours\" parameter in sarg.conf)"),ER_OutOfHourRange);
			DisplayExcludeCount(_("User is not in the \"include_users\" list"),ER_User);
			DisplayExcludeCount(_("HTTP code excluded by \"exclude_code\" file"),ER_HttpCode);
			DisplayExcludeCount(_("Invalid character found in user name"),ER_InvalidUserChar);
			DisplayExcludeCount(_("No URL in entry"),ER_NoUrl);
			DisplayExcludeCount(_("Not the IP address requested with -a"),ER_UntrackedIpAddr);
			DisplayExcludeCount(_("URL excluded by -c or \"exclude_hosts\""),ER_Url);
			DisplayExcludeCount(_("Entry time outside of requested hour range (-t)"),ER_OutOfTimeRange);
			DisplayExcludeCount(_("Not the URL requested by -s"),ER_UntrackedUrl);
			DisplayExcludeCount(_("No user in entry"),ER_NoUser);
			DisplayExcludeCount(_("Not the user requested by -u"),ER_UntrackedUser);
			DisplayExcludeCount(_("System user as defined by \"password\" in sarg.conf"),ER_SysUser);
			DisplayExcludeCount(_("User ignored by \"exclude_users\""),ER_IgnoredUser);
		}

		for (x=0 ; x<sizeof(LogFormats)/sizeof(*LogFormats) ; x++) {
			if (format_count[x]>0) {
				/* TRANSLATORS: It displays the number of lines found in the input log files
				* for each supported log format. The log format name is the %s and is a string
				* you translate somewhere else. */
				debuga(__FILE__,__LINE__,_("%s: %lu entries\n"),_(LogFormats[x]->Name),format_count[x]);
				totalcount+=format_count[x];
			}
		}

		if (totalcount==0 && totregsg)
			debuga(__FILE__,__LINE__,_("Log with invalid format\n"));
	}

	return((totregsg!=0) ? 1 : 0);
}

/*!
 * Get the start and end date of the period covered by the log files.
 */
bool GetLogPeriod(struct tm *Start,struct tm *End)
{
	bool Valid=false;

	if (EarliestDate>=0) {
		memcpy(Start,&EarliestDateTime,sizeof(struct tm));
		Valid=true;
	} else {
		memset(Start,0,sizeof(struct tm));
	}
	if (LatestDate>=0) {
		memcpy(End,&LatestDateTime,sizeof(struct tm));
		Valid=true;
	} else {
		memset(End,0,sizeof(struct tm));
	}
	return(Valid);
}
