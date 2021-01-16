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

//! Name of the file containing the unsorted authentication failure entries.
static char authfail_unsort[MAXLEN]="";
//! The file handle to write the entries.
static FILE *fp_authfail=NULL;
//! \c True if at least one anthentication failure entry exists.
static bool authfail_exists=false;

/*!
Open a file to store the authentication failure.

\return The file handle or NULL if no file is necessary.
*/
void authfail_open(void)
{
	if ((ReportType & REPORT_TYPE_AUTH_FAILURES) == 0) {
		if (debugz>=LogLevel_Process) debugaz(__FILE__,__LINE__,_("Authentication failures report not produced as it is not requested\n"));
		return;
	}
	if (Privacy) {
		if (debugz>=LogLevel_Process) debugaz(__FILE__,__LINE__,_("Authentication failures report not produced because privacy option is active\n"));
		return;
	}

	format_path(__FILE__, __LINE__, authfail_unsort, sizeof(authfail_unsort), "%s/authfail.int_unsort", tmp);
	if ((fp_authfail=MY_FOPEN(authfail_unsort,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),authfail_unsort,strerror(errno));
		exit(EXIT_FAILURE);
	}
	return;
}

/*!
Write one entry in the unsorted authentication file file provided that it is required.

\param log_entry The entry to write into the log file.
*/
void authfail_write(const struct ReadLogStruct *log_entry)
{
	char date[80];

	if (fp_authfail && (strstr(log_entry->HttpCode,"DENIED/401") != 0 || strstr(log_entry->HttpCode,"DENIED/407") != 0)) {
		strftime(date,sizeof(date),"%d/%m/%Y\t%H:%M:%S",&log_entry->EntryTime);
		fprintf(fp_authfail, "%s\t%s\t%s\t%s\n",date,log_entry->User,log_entry->Ip,log_entry->Url);
		authfail_exists=true;
	}
}

/*!
Close the file opened by authfail_open().
*/
void authfail_close(void)
{
	if (fp_authfail)
	{
		if (fclose(fp_authfail)==EOF) {
			debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),authfail_unsort,strerror(errno));
			exit(EXIT_FAILURE);
		}
		fp_authfail=NULL;
	}
}

/*!
Tell the caller if a authentication failure report exists.

\return \c True if the report is available or \c false if no report
was generated.
*/
bool is_authfail(void)
{
	return(authfail_exists);
}


static void show_ignored_auth(FILE *fp_ou,int count)
{
	char ignored[80];

	snprintf(ignored,sizeof(ignored),ngettext("%d more authentication failure not shown here&hellip;","%d more authentication failures not shown here&hellip;",count),count);
	fprintf(fp_ou,"<tr><td class=\"data\"></td><td class=\"data\"></td><td class=\"data\"></td><td class=\"data2 more\">%s</td></tr>\n",ignored);
}

void authfail_report(void)
{
	FileObject *fp_in = NULL;
	FILE *fp_ou = NULL;

	char *buf;
	char *url;
	char authfail_sort[MAXLEN];
	char report[MAXLEN];
	char ip[MAXLEN];
	char oip[MAXLEN]="";
	char user[MAXLEN];
	char ouser[MAXLEN]="";
	char ouser2[MAXLEN]="";
	char data[15];
	char hora[15];
	char csort[MAXLEN];
	int z=0;
	int count=0;
	int cstatus;
	int day,month,year;
	bool new_user;
	struct getwordstruct gwarea;
	longline line;
	struct userinfostruct *uinfo;
	struct tm t;

	if (!authfail_exists) {
		if (!KeepTempLog && authfail_unsort[0]!='\0' && unlink(authfail_unsort))
			debuga(__FILE__,__LINE__,_("Failed to delete \"%s\": %s\n"),authfail_unsort,strerror(errno));

		authfail_unsort[0]='\0';
		if (debugz>=LogLevel_Process) debugaz(__FILE__,__LINE__,_("Authentication failures report not produced because it is empty\n"));
		return;
	}
	if (debugz>=LogLevel_Process)
		debuga(__FILE__,__LINE__,_("Creating authentication failures report...\n"));

	format_path(__FILE__, __LINE__, authfail_sort, sizeof(authfail_sort), "%s/authfail.int_log", tmp);
	format_path(__FILE__, __LINE__, report, sizeof(report), "%s/authfail.html", outdirname);

	if (snprintf(csort, sizeof(csort), "sort -b -t \"\t\" -T \"%s\" -k 3,3 -k 5,5 -o \"%s\" \"%s\"", tmp, authfail_sort, authfail_unsort) >= sizeof(csort)) {
		debuga(__FILE__,__LINE__,_("Sort command too long when sorting file \"%s\" to \"%s\"\n"), authfail_unsort, authfail_sort);
		debuga_more("sort -b -t \"\t\" -T \"%s\" -k 3,3 -k 5,5 -o \"%s\" \"%s\"", tmp, authfail_sort, authfail_unsort);
		exit(EXIT_FAILURE);
	}
	cstatus=system(csort);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(__FILE__,__LINE__,_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}
	if ((fp_in=FileObject_Open(authfail_sort))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),authfail_sort,FileObject_GetLastOpenError());
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}
	if (!KeepTempLog && unlink(authfail_unsort)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),authfail_unsort,strerror(errno));
		exit(EXIT_FAILURE);
	}
	authfail_unsort[0]='\0';

	if ((fp_ou=MY_FOPEN(report,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),report,strerror(errno));
		exit(EXIT_FAILURE);
	}

	write_html_header(fp_ou,(IndexTree == INDEX_TREE_DATE) ? 3 : 1,_("Authentication Failures"),HTML_JS_NONE);
	fputs("<tr><td class=\"header_c\">",fp_ou);
	fprintf(fp_ou,_("Period: %s"),period.html);
	fputs("</td></tr>\n",fp_ou);
	fprintf(fp_ou,"<tr><th class=\"header_c\">%s</th></tr>\n",_("Authentication Failures"));
	close_html_header(fp_ou);

	fputs("<div class=\"report\"><table cellpadding=\"0\" cellspacing=\"2\">\n",fp_ou);
	fprintf(fp_ou,"<tr><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th></tr>\n",_("USERID"),_("IP/NAME"),_("DATE/TIME"),_("ACCESSED SITE"));

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),authfail_sort);
		exit(EXIT_FAILURE);
	}

	while((buf=longline_read(fp_in,line))!=NULL) {
		getword_start(&gwarea,buf);
		if (getword(data,sizeof(data),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid date in file \"%s\"\n"),authfail_sort);
			exit(EXIT_FAILURE);
		}
		if (getword(hora,sizeof(hora),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid time in file \"%s\"\n"),authfail_sort);
			exit(EXIT_FAILURE);
		}
		if (getword(user,sizeof(user),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid user ID in file \"%s\"\n"),authfail_sort);
			exit(EXIT_FAILURE);
		}
		if (getword(ip,sizeof(ip),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid IP address in file \"%s\"\n"),authfail_sort);
			exit(EXIT_FAILURE);
		}
		if (getword_ptr(buf,&url,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid url in file \"%s\"\n"),authfail_sort);
			exit(EXIT_FAILURE);
		}
		if (sscanf(data,"%d/%d/%d",&day,&month,&year)!=3) continue;
		computedate(year,month,day,&t);
		strftime(data,sizeof(data),"%x",&t);

		uinfo=userinfo_find_from_id(user);
		if (!uinfo) {
			debuga(__FILE__,__LINE__,_("Unknown user ID %s in file \"%s\"\n"),user,authfail_sort);
			exit(EXIT_FAILURE);
		}

		new_user=false;
		if (z == 0) {
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

		if (AuthfailReportLimit>0) {
			if (strcmp(ouser2,uinfo->label) == 0) {
				count++;
			} else {
				if (count>AuthfailReportLimit && AuthfailReportLimit>0)
					show_ignored_auth(fp_ou,count-AuthfailReportLimit);
				count=1;
				strcpy(ouser2,uinfo->label);
			}
			if (count > AuthfailReportLimit)
				continue;
		}

		fputs("<tr>",fp_ou);
		if (new_user)
			fprintf(fp_ou,"<td class=\"data2\">%s</td><td class=\"data2\">%s</td>",uinfo->label,ip);
		else
			fputs("<td class=\"data2\"></td><td class=\"data2\"></td>",fp_ou);
		fprintf(fp_ou,"<td class=\"data2\">%s-%s</td><td class=\"data2\">",data,hora);
		if (BlockIt[0]!='\0' && url[0]!=ALIAS_PREFIX) {
			fprintf(fp_ou,"<a href=\"%s%s?url=",wwwDocumentRoot,BlockIt);
			output_html_url(fp_ou,url);
			fputs("\"><img src=\"../images/sarg-squidguard-block.png\"></a>&nbsp;",fp_ou);
		}
		output_html_link(fp_ou,url,100);
		fputs("</td></th>\n",fp_ou);
	}
	if (FileObject_Close(fp_in)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),authfail_sort,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}
	longline_destroy(&line);

	if (count>AuthfailReportLimit && AuthfailReportLimit>0)
		show_ignored_auth(fp_ou,count-AuthfailReportLimit);

	fputs("</table></div>\n",fp_ou);
	write_html_trailer(fp_ou);
	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),report,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!KeepTempLog && unlink(authfail_sort)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),authfail_sort,strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}

/*!
Remove any temporary file left by the authfail module.
*/
void authfail_cleanup(void)
{
	if (fp_authfail) {
		if (fclose(fp_authfail)==EOF) {
			debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),authfail_unsort,strerror(errno));
			exit(EXIT_FAILURE);
		}
		fp_authfail=NULL;
	}
	if (authfail_unsort[0]) {
		if (!KeepTempLog && unlink(authfail_unsort)==-1)
			debuga(__FILE__,__LINE__,_("Failed to delete \"%s\": %s\n"),authfail_unsort,strerror(errno));
	}
}
