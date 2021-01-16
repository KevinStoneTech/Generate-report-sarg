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
#include "include/filelist.h"
#include "include/readlog.h"

//! Maximum length of the scheme plus host name from the url.
#define MAX_URL_HOST_LEN 260

/*!
\brief Data read from an input log file.
*/
struct RealtimeReadLogStruct
{
	//! The time corresponding to the entry.
	struct tm EntryTime;
	//! The IP address connecting to internet.
	char Ip[48];
	//! The user's name.
	char User[MAX_USER_LEN];
	/*!
	The URL of the visited site.

	The pointer may be NULL if the URL doesn't exists in the log file.
	*/
	char Url[MAX_URL_HOST_LEN];
	//! HTTP method or NULL if the information is not stored in the log.
	char HttpMethod[32];
};

extern FileListObject AccessLog;

static bool GetLatestModified(char *file_name,int file_name_size)
{
	FileListIterator FIter;
	const char *file;
	bool found=false;
	struct stat st;
	time_t latest;

	FIter=FileListIter_Open(AccessLog);
	while ((file=FileListIter_Next(FIter))!=NULL)
	{
		if (stat(file,&st)==-1) {
			debuga(__FILE__,__LINE__,_("Cannot stat \"%s\": %s\n"),file,strerror(errno));
		}
		if (!found)
		{
			found=true;
			latest=st.st_mtime;
			safe_strcpy(file_name,file,file_name_size);
		}
		else if (st.st_mtime>latest)
		{
			latest=st.st_mtime;
			safe_strcpy(file_name,file,file_name_size);
		}
	}
	FileListIter_Close(FIter);
	return(found);
}

/*!
 * \brief Store a log entry.
 *
 * \param Dest A pointer to the list entry where to store the entry.
 * \param Entry The entry to store.
 */
static void StoreLogEntry(struct RealtimeReadLogStruct *Dest,struct ReadLogStruct *Entry)
{
	memcpy(&Dest->EntryTime,&Entry->EntryTime,sizeof(Dest->EntryTime));
	safe_strcpy(Dest->Ip,Entry->Ip,sizeof(Dest->Ip));
	if (Entry->Url)
	{
		int i;
		const char *url=Entry->Url;

		// skip the scheme
		for (i=0 ; i<8 && url[i] && (isalnum(url[i]) || url[i]=='+' || url[i]=='-' || url[i]=='.') ; i++);
		if (url[i]==':' && url[i+1]=='/' && url[i+2]=='/')
		{
			url+=i+3;
			for (i=0 ; url[i] && url[i]!='/' ; i++);
		}
		if (i>=sizeof(Dest->Url)) i=sizeof(Dest->Url)-1;
		strncpy(Dest->Url,url,i);
		Dest->Url[i]='\0';
	}
	safe_strcpy(Dest->User,Entry->User,sizeof(Dest->User));
	safe_strcpy(Dest->HttpMethod,Entry->HttpMethod,sizeof(Dest->HttpMethod));
}

static void header(void)
{
	puts("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"");
	puts(" \"http://www.w3.org/TR/html4/loose.dtd\">\n");
	puts("<html>\n");
	puts("<head>\n");
	if (realtime_refresh)
		printf("  <meta http-equiv=refresh content=\"%d\" url=\"sarg-php/sarg-realtime.php\"; charset=\"%s\">\n",realtime_refresh,CharSet);
	else
		printf("  <meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\">\n",CharSet);
	css(stdout);
	puts("</head>\n");
	printf("<body style=\"font-family:%s;font-size:%s;background-color:%s;background-image:url(%s)\">\n",FontFace,TitleFontSize,BgColor,BgImage);
	puts("<div align=\"center\"><table cellpadding=\"1\" cellspacing=\"1\">\n");
	printf("<tr><th class=\"title_l\" colspan=\"10\">SARG %s</th></tr>\n",_("Realtime"));
	printf("<tr><th class=\"text\" colspan=\"10\">%s: %d s</th></tr>\n",_("Auto refresh"),realtime_refresh);
	printf("<tr><th class=\"header_c\">%s</th><th class=\"header_c\">%s</th><th class=\"header_c\">%s</th><th class=\"header_c\">%s</th><th class=\"header_l\">%s</th></tr>\n",_("DATE/TIME"),_("IP/NAME"),_("USERID"),_("TYPE"),_("ACCESSED SITE"));
}

static void datashow(struct RealtimeReadLogStruct *List,int Index,int Size)
{
	char tbuf[128];
	char user[MAX_USER_LEN];
	char name[MAX_USER_LEN];
	int i;
	struct RealtimeReadLogStruct *entry;

	header();
	for (i=0 ; i<realtime_access_log_lines ; i++)
	{
		entry=List+Index;
		Index--;
		if (Index<0) Index=Size-1;

		if (UserIp)
			strcpy(user,entry->Ip);
		else
			strcpy(user,entry->User);
		if (Ip2Name)
			ip2name(user,sizeof(user));
		user_find(name, sizeof(name), user);

		if (df=='u')
			strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M", &entry->EntryTime);
		else if (df=='e')
			strftime(tbuf, sizeof(tbuf), "%d-%m-%Y %H:%M", &entry->EntryTime);

		printf("<tr><td class=\"data\">%s</td><td class=\"data3\">%s</td><td class=\"data3\">%s</td><td class=\"data3\">%s</td><td class=\"data2\"><a href=\"http://%s\">%s</td></tr>\n",
			   tbuf,entry->Ip,name,entry->HttpMethod,entry->Url,entry->Url);
	}

	puts("</table>\n</div>\n</body>\n</html>\n");
	fflush(NULL);
}

void realtime(void)
{
	FileObject *fp;
	char file_name[2048];
	char *buf;
	longline line;
	struct ReadLogStruct log_entry;
	enum ReadLogReturnCodeEnum log_entry_status;
	struct LogLineStruct log_line;
	struct RealtimeReadLogStruct *StoredLogEntries;
	int StoreIndex=0;
	int StoreSize=0;
	int NextIndex=1;

	init_usertab(UserTabFile);
	LogLine_Init(&log_line);

	/*
	 * Store one more entry to prepare the memory structure in place and reject it if
	 * it is about the same user and url as the last stored one.
	 */
	StoredLogEntries=calloc(realtime_access_log_lines+1,sizeof(struct RealtimeReadLogStruct));
	if (!StoredLogEntries)
	{
		debuga(__FILE__,__LINE__,_("Not enough memory to store %d records"),realtime_access_log_lines);
		exit(EXIT_FAILURE);
	}
	/*
	 * Clear the url and user strings so that strcmp on the user and url are not
	 * satisfied and the first entry can be stored.
	 */
	memset(StoredLogEntries,0,sizeof(struct RealtimeReadLogStruct));

	if (!GetLatestModified(file_name,sizeof(file_name)))
	{
		debuga(__FILE__,__LINE__,_("No log file to read the last %d lines from\n"),realtime_access_log_lines);
		exit(EXIT_FAILURE);
	}
	fp = FileObject_Open(file_name);
	if (!fp) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),file_name,FileObject_GetLastOpenError());
		exit(EXIT_FAILURE);
	}

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),file_name);
		exit(EXIT_FAILURE);
	}

	while((buf=longline_read(fp,line)) != NULL )
	{
		log_entry_status=LogLine_Parse(&log_line,&log_entry,buf);
		if (log_entry_status==RLRC_Unknown)
		{
			continue;
		}
		if (log_entry_status==RLRC_Ignore)
		{
			continue;
		}
		if (log_entry.HttpMethod && strstr(RealtimeTypes,log_entry.HttpMethod)==0)
			continue;
		if (RealtimeUnauthRec==REALTIME_UNAUTH_REC_IGNORE && log_entry.User[0]=='-' && log_entry.User[1]=='\0')
			continue;
		StoreLogEntry(StoredLogEntries+NextIndex,&log_entry);
		if (strcmp(StoredLogEntries[StoreIndex].User,StoredLogEntries[NextIndex].User)==0 && strcmp(StoredLogEntries[StoreIndex].Url,StoredLogEntries[NextIndex].Url)==0)
			continue;

		StoreIndex=NextIndex;
		NextIndex++;
		if (NextIndex>StoreSize) StoreSize=NextIndex;
		if (NextIndex>realtime_access_log_lines) NextIndex=0;
	}
	if (FileObject_Close(fp)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),file_name,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}
	longline_destroy(&line);

	datashow(StoredLogEntries,StoreIndex,StoreSize);
	free(StoredLogEntries);
}
