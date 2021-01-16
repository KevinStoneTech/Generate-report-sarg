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
The buffer to store the list of the suffixes to take into account when generating
the report of the downloaded files. The suffixes in the list are separated by the ASCII
null.
*/
/*@null@*/static char *DownloadSuffix=NULL;

/*!
The index of all the suffixes stored in ::DownloadSuffix. The list is sorted alphabetically.
to speed up the search.
*/
/*@null@*/static char **DownloadSuffixIndex=NULL;

/*!
The number of suffixes in ::DownloadSuffixIndex.
*/
static int NDownloadSuffix=0;

//! Name of the file containing the unsorted downloaded entries.
static char download_unsort[MAXLEN]="";
//! The file handle to write the entries.
static FILE *fp_download=NULL;
//! \c True if at least one downloaded entry exists.
static bool download_exists=false;

/*!
Open a file to store the denied accesses.

\return The file handle or NULL if no file is necessary.
*/
void download_open(void)
{
	if ((ReportType & REPORT_TYPE_DOWNLOADS) == 0) {
		if (debugz>=LogLevel_Process) debugaz(__FILE__,__LINE__,_("Download report not produced as it is not requested\n"));
		return;
	}
	if (Privacy) {
		if (debugz>=LogLevel_Process) debugaz(__FILE__,__LINE__,_("Download report not produced because privacy option is active\n"));
		return;
	}

	format_path(__FILE__, __LINE__, download_unsort, sizeof(download_unsort), "%s/download.int_unsort", tmp);
	if ((fp_download=MY_FOPEN(download_unsort,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),download_unsort,strerror(errno));
		exit(EXIT_FAILURE);
	}
	return;
}

/*!
Write one entry in the unsorted downloaded file provided that it is required.

\param log_entry The entry to write into the log file.
\param url The URL of the downloaded file.
*/
void download_write(const struct ReadLogStruct *log_entry,const char *url)
{
	char date[80];

	if (fp_download && strstr(log_entry->HttpCode,"DENIED") == 0) {
		strftime(date,sizeof(date),"%d/%m/%Y\t%H:%M:%S",&log_entry->EntryTime);
		fprintf(fp_download,"%s\t%s\t%s\t%s\n",date,log_entry->User,log_entry->Ip,url);
		download_exists=true;
	}
}

/*!
Close the file opened by denied_open().
*/
void download_close(void)
{
	if (fp_download)
	{
		if (fclose(fp_download)==EOF) {
			debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),download_unsort,strerror(errno));
			exit(EXIT_FAILURE);
		}
		fp_download=NULL;
	}
}

/*!
Tell the caller if a download report exists.

\return \c True if the report is available or \c false if no report
was generated.
*/
bool is_download(void)
{
	return(download_exists);
}

/*!
Sort the raw log file with the downloaded files.

\param report_in The name of the file where to store the sorted entries.

The file is sorted by columns 3, 1, 2 and 5 that are the columns of the user's ID, the
date, the time and the URL.
*/
static void download_sort(const char *report_in)
{
	int clen;
	char csort[MAXLEN];
	int cstatus;

	clen=snprintf(csort,sizeof(csort),"sort -T \"%s\" -t \"\t\" -k 3,3 -k 1,1 -k 2,2 -k 5,5 -o \"%s\" \"%s\"",
			tmp, report_in, download_unsort);
	if (clen>=sizeof(csort)) {
		debuga(__FILE__,__LINE__,_("Path too long to sort file \"%s\"\n"),download_unsort);
		exit(EXIT_FAILURE);
	}
	cstatus=system(csort);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(__FILE__,__LINE__,_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}
	if (!KeepTempLog) {
		if (unlink(download_unsort)) {
			debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),download_unsort,strerror(errno));
			exit(EXIT_FAILURE);
		}
		download_unsort[0]='\0';
	}
}

/*!
Generate the report of the downloaded files. The list of the suffixes to take into account
is set with set_download_suffix().
*/
void download_report(void)
{
	FileObject *fp_in = NULL;
	FILE *fp_ou = NULL;

	char *buf;
	char *url;
	char report_in[MAXLEN];
	char report[MAXLEN];
	char ip[MAXLEN];
	char oip[MAXLEN];
	char user[MAXLEN];
	char ouser[MAXLEN];
	char ouser2[MAXLEN];
	char data[15];
	char hora[15];
	int  z=0;
	int  count=0;
	int i;
	int day,month,year;
	bool new_user;
	struct getwordstruct gwarea;
	longline line;
	struct userinfostruct *uinfo;
	struct tm t;

	if (!download_exists) {
		if (!KeepTempLog && download_unsort[0]!='\0' && unlink(download_unsort))
			debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),download_unsort,strerror(errno));
		download_unsort[0]='\0';
		if (debugz>=LogLevel_Process) debugaz(__FILE__,__LINE__,_("No downloaded files to report\n"));
		return;
	}

	if (debugz>=LogLevel_Process)
		debuga(__FILE__,__LINE__,_("Creating download report...\n"));
	ouser[0]='\0';
	ouser2[0]='\0';

	// sort the raw file
	format_path(__FILE__, __LINE__, report_in, sizeof(report_in), "%s/download.int_log", tmp);
	download_sort(report_in);

	// produce the report.
	format_path(__FILE__, __LINE__, report, sizeof(report), "%s/download.html", outdirname);

	if ((fp_in=FileObject_Open(report_in))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),report_in,FileObject_GetLastOpenError());
		exit(EXIT_FAILURE);
	}

	if ((fp_ou=MY_FOPEN(report,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),report,strerror(errno));
		exit(EXIT_FAILURE);
	}

	write_html_header(fp_ou,(IndexTree == INDEX_TREE_DATE) ? 3 : 1,_("Downloads"),HTML_JS_NONE);
	fputs("<tr><td class=\"header_c\">",fp_ou);
	fprintf(fp_ou,_("Period: %s"),period.html);
	fputs("</td></tr>\n",fp_ou);
	fprintf(fp_ou,"<tr><th class=\"header_c\">%s</th></tr>\n",_("Downloads"));
	close_html_header(fp_ou);

	fputs("<div class=\"report\"><table cellpadding=\"0\" cellspacing=\"2\">\n",fp_ou);
	fprintf(fp_ou,"<tr><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th></tr>\n",_("USERID"),_("IP/NAME"),_("DATE/TIME"),_("ACCESSED SITE"));

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),report_in);
		exit(EXIT_FAILURE);
	}

	while((buf=longline_read(fp_in,line))!=NULL) {
		getword_start(&gwarea,buf);
		if (getword(data,sizeof(data),&gwarea,'\t')<0 || getword(hora,sizeof(hora),&gwarea,'\t')<0 ||
		    getword(user,sizeof(user),&gwarea,'\t')<0 || getword(ip,sizeof(ip),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid record in file \"%s\"\n"),report_in);
			exit(EXIT_FAILURE);
		}
		if (getword_ptr(buf,&url,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid url in file \"%s\"\n"),report_in);
			exit(EXIT_FAILURE);
		}
		if (sscanf(data,"%d/%d/%d",&day,&month,&year)!=3) continue;
		computedate(year,month,day,&t);
		strftime(data,sizeof(data),"%x",&t);

		uinfo=userinfo_find_from_id(user);
		if (!uinfo) {
			debuga(__FILE__,__LINE__,_("Unknown user ID %s in file \"%s\"\n"),user,report_in);
			exit(EXIT_FAILURE);
		}
		new_user=false;
		if (!z) {
			strcpy(ouser,user);
			strcpy(oip,ip);
			z++;
			new_user=true;
		} else {
			if (strcmp(ouser,user) != 0) {
				strcpy(ouser,user);
				new_user=true;
			}
			if (strcmp(oip,ip) != 0) {
				strcpy(oip,ip);
				new_user=true;
			}
		}

		if (DownloadReportLimit) {
			if (strcmp(ouser2,uinfo->label) == 0) {
				count++;
			} else {
				count=1;
				strcpy(ouser2,uinfo->label);
			}
			if (count >= DownloadReportLimit)
				continue;
		}

		for (i=strlen(url)-1 ; i>=0 && (unsigned char)url[i]<' ' ; i--) url[i]=0;

		fputs("<tr>",fp_ou);
		if (new_user) {
			if (uinfo->topuser)
				fprintf(fp_ou,"<td class=\"data\"><a href=\"%s/%s.html\">%s</a></td><td class=\"data\">%s</td>",uinfo->filename,uinfo->filename,uinfo->label,ip);
			else
				fprintf(fp_ou,"<td class=\"data\">%s</td><td class=\"data\">%s</td>",uinfo->label,ip);
		} else
			fputs("<td class=\"data\"></td><td class=\"data\"></td>",fp_ou);
		fprintf(fp_ou,"<td class=\"data\">%s-%s</td><td class=\"data2\">",data,hora);
		if (BlockIt[0]!='\0' && url[0]!=ALIAS_PREFIX) {
			fprintf(fp_ou,"<a href=\"%s%s?url=\"",wwwDocumentRoot,BlockIt);
			output_html_url(fp_ou,url);
			fprintf(fp_ou,"\"><img src=\"%s/sarg-squidguard-block.png\"></a>&nbsp;",ImageFile);
		}
		output_html_link(fp_ou,url,100);
		fputs("</td></tr>\n",fp_ou);
	}
	if (FileObject_Close(fp_in)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),report_in,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}
	longline_destroy(&line);

	fputs("</table></div>\n",fp_ou);
	write_html_trailer(fp_ou);
	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),report,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!KeepTempLog && unlink(report_in)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),report_in,strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}

/*!
Free the memory allocated by set_download_suffix().
*/
void free_download(void)
{
	if (DownloadSuffix) {
		free(DownloadSuffix);
		DownloadSuffix=NULL;
	}
	if (DownloadSuffixIndex) {
		free(DownloadSuffixIndex);
		DownloadSuffixIndex=NULL;
	}
	NDownloadSuffix=0;
}

/*!
Set the list of the suffixes corresponding to the download of files you want to detect with
is_download_suffix(). The list is sorted to make the search faster.

\param list A comma separated list of the suffixes to set in ::DownloadSuffix.

\note The memory allocated by this function must be freed by free_download().
*/
void set_download_suffix(const char *list)
{
	char *str;
	int i, j, k;
	int cmp;

	free_download();

	DownloadSuffix=strdup(list);
	if (!DownloadSuffix) {
		debuga(__FILE__,__LINE__,_("Download suffix list too long\n"));
		exit(EXIT_FAILURE);
	}
	j = 1;
	for (i=0 ; list[i] ; i++)
		if (list[i] == ',') j++;
	DownloadSuffixIndex=malloc(j*sizeof(char *));
	if (!DownloadSuffixIndex) {
		debuga(__FILE__,__LINE__,_("Too many download suffixes\n"));
		exit(EXIT_FAILURE);
	}

	str = DownloadSuffix;
	for (i=0 ; DownloadSuffix[i] ; i++) {
		if (DownloadSuffix[i] == ',') {
			DownloadSuffix[i] = '\0';
			if (*str) {
				cmp = -1;
				for (j=0 ; j<NDownloadSuffix && (cmp=strcasecmp(str,DownloadSuffixIndex[j]))>0 ; j++);
				if (cmp != 0) {
					for (k=NDownloadSuffix ; k>j ; k--)
						DownloadSuffixIndex[k]=DownloadSuffixIndex[k-1];
					NDownloadSuffix++;
					DownloadSuffixIndex[j]=str;
				}
			}
			str=DownloadSuffix+i+1;
		}
	}

	if (*str) {
		cmp = -1;
		for (j=0 ; j<NDownloadSuffix && (cmp=strcasecmp(str,DownloadSuffixIndex[j]))>0 ; j++);
		if (cmp != 0) {
			for (k=NDownloadSuffix ; k>j ; k--)
				DownloadSuffixIndex[k]=DownloadSuffixIndex[k-1];
			NDownloadSuffix++;
			DownloadSuffixIndex[j]=str;
		}
	}
}

/*!
Tell if the URL correspond to a downloaded file. The function takes the extension at the end of the
URL with a maximum of 9 characters and compare it to the list of the download suffix in
::DownloadSuffix. If the suffix is found in the list, the function reports the URL as the download
of a file.

\param url The URL to test.

\retval 1 The URL matches a suffix of a download.
\retval 0 The URL is not a known download.

\note A downloaded file cannot be detected if the file name is embedded in a GET or POST request. Only requests
that ends with the file name can be detected.

\note A URL embedding another web site's address ending by .com at the end of the URL will match the download
extension com if it is defined in the ::DownloadSuffix.
*/
bool is_download_suffix(const char *url)
{
	int urllen;
	int i;
	int down, up, center;
	const char *suffix;
	int cmp;
	const int max_suffix=10;

	if (DownloadSuffix == NULL || NDownloadSuffix == 0) return(false);

	urllen=strlen(url)-1;
	if (urllen<=0) return(false);
	if (url[urllen] == '.') return(false); //reject a single trailing dot
	for (i=0 ; i<urllen && (url[i]!='/' || url[i+1]=='/') && url[i]!='?' ; i++);
	if (i>=urllen) return(false); // url is a hostname without any path or file to download

	for (i=0 ; i<=max_suffix && i<urllen && url[urllen-i]!='.' ; i++)
		if (url[urllen-i] == '/' || url[urllen-i] == '?') return(false);
	if (i>max_suffix || i>=urllen) return(false);

	suffix=url+urllen-i+1;
	down=0;
	up=NDownloadSuffix-1;
	while (down<=up) {
		center=(down+up)/2;
		cmp=strcasecmp(suffix,DownloadSuffixIndex[center]);
		if (cmp == 0) return(true);
		if (cmp < 0)
			up = center-1;
		else
			down = center+1;
	}
	return(false);
}

/*!
Remove any temporary file left by the download module.
*/
void download_cleanup(void)
{
	if (fp_download) {
		if (fclose(fp_download)==EOF) {
			debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),download_unsort,strerror(errno));
			exit(EXIT_FAILURE);
		}
		fp_download=NULL;
	}
	if (download_unsort[0]) {
		if (unlink(download_unsort)==-1)
			debuga(__FILE__,__LINE__,_("Failed to delete \"%s\": %s\n"),download_unsort,strerror(errno));
	}
}
