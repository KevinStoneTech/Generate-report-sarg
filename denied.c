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

//! Name of the file containing the unsorted denied entries.
static char denied_unsort[MAXLEN]="";
//! The file handle to write the entries.
static FILE *fp_denied=NULL;
//! \c True if at least one denied entry exists.
static bool denied_exists=false;

/*!
Open a file to store the denied accesses.

\return The file handle or NULL if no file is necessary.
*/
void denied_open(void)
{
	if ((ReportType & REPORT_TYPE_DENIED) == 0) {
		if (debugz>=LogLevel_Process) debugaz(__FILE__,__LINE__,_("Denied report not produced as it is not requested\n"));
		return;
	}
	if (Privacy) {
		if (debugz>=LogLevel_Process) debugaz(__FILE__,__LINE__,_("Denied report not produced because privacy option is active\n"));
		return;
	}

	format_path(__FILE__, __LINE__, denied_unsort, sizeof(denied_unsort), "%s/denied.int_unsort", tmp);
	if ((fp_denied=MY_FOPEN(denied_unsort,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),denied_unsort,strerror(errno));
		exit(EXIT_FAILURE);
	}
	return;
}

/*!
Write one entry in the unsorted denied file provided that it is required.

\param log_entry The entry to write into the log file.
*/
void denied_write(const struct ReadLogStruct *log_entry)
{
	char date[80];

	if (fp_denied && strstr(log_entry->HttpCode,"DENIED/403") != 0) {
		strftime(date,sizeof(date),"%d/%m/%Y\t%H:%M:%S",&log_entry->EntryTime);
		fprintf(fp_denied, "%s\t%s\t%s\t%s\n",date,log_entry->User,log_entry->Ip,log_entry->Url);
		denied_exists=true;
	}
}

/*!
Close the file opened by denied_open().
*/
void denied_close(void)
{
	if (fp_denied) {
		if (fclose(fp_denied)==EOF) {
			debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),denied_unsort,strerror(errno));
			exit(EXIT_FAILURE);
		}
		fp_denied=NULL;
	}
}

/*!
Tell the caller if a denied report exists.

\return \c True if the report is available or \c false if no report
was generated.
*/
bool is_denied(void)
{
	return(denied_exists);
}

static void show_ignored_denied(FILE *fp_ou,int count)
{
	char ignored[80];

	snprintf(ignored,sizeof(ignored),ngettext("%d more denied access not shown here&hellip;","%d more denied accesses not shown here&hellip;",count),count);
	fprintf(fp_ou,"<tr><td class=\"data\"></td><td class=\"data\"></td><td class=\"data\"></td><td class=\"data2 more\">%s</td></tr>\n",ignored);
}

/*!
Generate a report containing the denied accesses.
*/
void gen_denied_report(void)
{
	FileObject *fp_in = NULL;
	FILE *fp_ou = NULL;

	char *buf;
	char *url;
	char denied_sort[MAXLEN];
	char report[MAXLEN];
	char ip[MAXLEN];
	char oip[MAXLEN];
	char user[MAXLEN];
	char ouser[MAXLEN]="";
	char ouser2[MAXLEN]="";
	char data[15];
	char hora[15];
	char csort[4098];
	bool z=false;
	int  count=0;
	int day,month,year;
	int cstatus;
	bool new_user;
	struct getwordstruct gwarea;
	longline line;
	struct userinfostruct *uinfo;
	struct tm t;

	if (!denied_exists) {
		if (!KeepTempLog && denied_unsort[0]!='\0' && unlink(denied_unsort))
			debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),denied_unsort,strerror(errno));
		denied_unsort[0]='\0';
		if (debugz>=LogLevel_Process) debugaz(__FILE__,__LINE__,_("Denied report not produced because it is empty\n"));
		return;
	}
	if (debugz>=LogLevel_Process)
		debuga(__FILE__,__LINE__,_("Creating denied accesses report...\n"));

	if (snprintf(denied_sort,sizeof(denied_sort),"%s/denied.int_log",tmp)>=sizeof(denied_sort)) {
		debuga(__FILE__,__LINE__,_("Temporary directory path too long to sort the denied accesses\n"));
		exit(EXIT_FAILURE);
	}
	if (snprintf(csort,sizeof(csort),"sort -T \"%s\" -t \"\t\" -k 3,3 -k 5,5 -o \"%s\" \"%s\"",tmp,denied_sort,denied_unsort)>=sizeof(csort)) {
		debuga(__FILE__,__LINE__,_("Sort command too long when sorting file \"%s\" to \"%s\"\n"),denied_unsort,denied_sort);
		exit(EXIT_FAILURE);
	}
	cstatus=system(csort);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(__FILE__,__LINE__,_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}
	if (unlink(denied_unsort)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),denied_unsort,strerror(errno));
		exit(EXIT_FAILURE);
	}
	denied_unsort[0]='\0';

	format_path(__FILE__, __LINE__, report, sizeof(report), "%s/denied.html", outdirname);

	if ((fp_in=FileObject_Open(denied_sort))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),denied_sort,FileObject_GetLastOpenError());
		exit(EXIT_FAILURE);
	}

	if ((fp_ou=MY_FOPEN(report,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),report,strerror(errno));
		exit(EXIT_FAILURE);
	}

	write_html_header(fp_ou,(IndexTree == INDEX_TREE_DATE) ? 3 : 1,_("Denied"),HTML_JS_NONE);
	fputs("<tr><td class=\"header_c\">",fp_ou);
	fprintf(fp_ou,_("Period: %s"),period.html);
	fputs("</td></tr>\n",fp_ou);
	fprintf(fp_ou,"<tr><th class=\"header_c\">%s</th></tr>\n",_("Denied"));
	close_html_header(fp_ou);

	fputs("<div class=\"report\"><table cellpadding=\"0\" cellspacing=\"2\">\n",fp_ou);
	fprintf(fp_ou,"<tr><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th></tr>\n",_("USERID"),_("IP/NAME"),_("DATE/TIME"),_("ACCESSED SITE"));

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),denied_sort);
		exit(EXIT_FAILURE);
	}

	while((buf=longline_read(fp_in,line))!=NULL) {
		getword_start(&gwarea,buf);
		if (getword(data,sizeof(data),&gwarea,'\t')<0 || getword(hora,sizeof(hora),&gwarea,'\t')<0 ||
		    getword(user,sizeof(user),&gwarea,'\t')<0 || getword(ip,sizeof(ip),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid record in file \"%s\"\n"),denied_sort);
			exit(EXIT_FAILURE);
		}
		if (getword_ptr(buf,&url,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid url in file \"%s\"\n"),denied_sort);
			exit(EXIT_FAILURE);
		}
		if (sscanf(data,"%d/%d/%d",&day,&month,&year)!=3) continue;
		computedate(year,month,day,&t);
		strftime(data,sizeof(data),"%x",&t);

		uinfo=userinfo_find_from_id(user);
		if (!uinfo) {
			debuga(__FILE__,__LINE__,_("Unknown user ID %s in file \"%s\"\n"),user,denied_sort);
			exit(EXIT_FAILURE);
		}

		new_user=false;
		if (!z) {
			strcpy(ouser,user);
			strcpy(oip,ip);
			z=true;
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

		if (DeniedReportLimit) {
			if (strcmp(ouser2,uinfo->label) == 0) {
				count++;
			} else {
				if (count>DeniedReportLimit && DeniedReportLimit>0)
					show_ignored_denied(fp_ou,count-DeniedReportLimit);
				count=1;
				strcpy(ouser2,uinfo->label);
			}
			if (count > DeniedReportLimit)
				continue;
		}

		fputs("<tr>",fp_ou);
		if (new_user) {
			if (uinfo->topuser)
				fprintf(fp_ou,"<td class=\"data\"><a href=\"%s/%s.html\">%s</a></td><td class=\"data\">%s</td>",uinfo->filename,uinfo->filename,uinfo->label,ip);
			else
				fprintf(fp_ou,"<td class=\"data\">%s</td><td class=\"data\">%s</td>",uinfo->label,ip);
		} else
			fputs("<td class=\"data\"></td><td class=\"data\"></td>",fp_ou);
		fprintf(fp_ou,"<td class=\"data\">%s-%s</td><td class=\"data2\">",data,hora);
		if (BlockIt[0] != '\0' && url[0]!=ALIAS_PREFIX) {
			fprintf(fp_ou,"<a href=\"%s%s?url=",wwwDocumentRoot,BlockIt);
			output_html_url(fp_ou,url);
			fprintf(fp_ou,"\"><img src=\"%s/sarg-squidguard-block.png\"></a>&nbsp;",ImageFile);
		}
		output_html_link(fp_ou,url,100);
		fputs("</td></tr>\n",fp_ou);
	}
	if (FileObject_Close(fp_in)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),denied_sort,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}
	longline_destroy(&line);

	if (count>DeniedReportLimit && DeniedReportLimit>0)
		show_ignored_denied(fp_ou,count-DeniedReportLimit);

	fputs("</table></div>\n",fp_ou);
	write_html_trailer(fp_ou);
	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),report,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!KeepTempLog && unlink(denied_sort)==-1)
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),denied_sort,strerror(errno));

	return;
}

/*!
Remove any temporary file left by the denied module.
*/
void denied_cleanup(void)
{
	if (fp_denied){
		if (fclose(fp_denied)==EOF) {
			debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),denied_unsort,strerror(errno));
			exit(EXIT_FAILURE);
		}
		fp_denied=NULL;
	}
	if (!KeepTempLog && denied_unsort[0]) {
		if (unlink(denied_unsort)==-1)
			debuga(__FILE__,__LINE__,_("Failed to delete \"%s\": %s\n"),denied_unsort,strerror(errno));
	}
}
