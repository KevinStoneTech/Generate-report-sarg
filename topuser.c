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

struct TopUserStatistics
{
	long long int ttnbytes;
	long long int ttnacc;
	long long int ttnelap;
	long long int ttnincache;
	long long int ttnoucache;
	int totuser;
};

struct SortInfoStruct
{
	const char *sort_field;
	const char *sort_order;
};

extern struct globalstatstruct globstat;
extern bool smartfilter;

/*!
Save the total number of users. The number is written in sarg-users and set
in a global variable for further reference.

\param totuser The total number of users.
*/
static void set_total_users(int totuser)
{
	char tusr[1024];
	FILE *fp_ou;

	format_path(__FILE__, __LINE__, tusr, sizeof(tusr), "%s/sarg-users", outdirname);
	if ((fp_ou=fopen(tusr,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),tusr,strerror(errno));
		exit(EXIT_FAILURE);
	}
	fprintf(fp_ou,"%d\n",totuser);
	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),tusr,strerror(errno));
		exit(EXIT_FAILURE);
	}
	globstat.totuser=totuser;
}

/*!
 * Generate a HTML report with the users downloading the most.
 *
 * \param ListFile Name of the file with the sorted list of users.
 * \param Statis Statistics about the data collected from the log file.
 * \param SortInfo Strings explaining how the list was sorted.
 */
static void TopUser_HtmlReport(const char *ListFile,struct TopUserStatistics *Statis,struct SortInfoStruct *SortInfo)
{
	FileObject *fp_top1 = NULL;
	FILE *fp_top3 = NULL;
	long long int nbytes;
	long long int nacc;
	long long int elap, incac, oucac;
	double perc=0.00;
	double perc2=0.00;
	double inperc=0.00, ouperc=0.00;
	int posicao=0;
	char top3[MAXLEN];
	char user[MAX_USER_LEN];
	char title[80];
	char *warea;
	bool ntopuser=false;
	int topcount=0;
	struct getwordstruct gwarea;
	longline line;
	struct userinfostruct *uinfo;

	if ((fp_top1=FileObject_Open(ListFile))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),ListFile,FileObject_GetLastOpenError());
		exit(EXIT_FAILURE);
	}

	format_path(__FILE__, __LINE__, top3, sizeof(top3), "%s/"INDEX_HTML_FILE, outdirname);
	if ((fp_top3=fopen(top3,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),top3,strerror(errno));
		exit(EXIT_FAILURE);
	}

	snprintf(title,sizeof(title),_("SARG report for %s"),period.text);
	write_html_header(fp_top3,(IndexTree == INDEX_TREE_DATE) ? 3 : 1,title,HTML_JS_SORTTABLE);
	fputs("<tr><td class=\"header_c\">",fp_top3);
	fprintf(fp_top3,_("Period: %s"),period.html);
	fputs("</td></tr>\n",fp_top3);
	if ((ReportType & REPORT_TYPE_TOPUSERS) != 0) {
		fputs("<tr><td class=\"header_c\">",fp_top3);
		fprintf(fp_top3,_("Sort: %s, %s"),SortInfo->sort_field,SortInfo->sort_order);
		fputs("</td></tr>\n",fp_top3);
		fprintf(fp_top3,"<tr><th class=\"header_c\">%s</th></tr>\n",_("Top users"));
	} else {
		/* TRANSLATORS: This is the title of the main report page when no
		 * top users list are requested.
		 */
		fprintf(fp_top3,"<tr><th class=\"header_c\">%s</th></tr>\n",_("Table of content"));
	}
	close_html_header(fp_top3);

	if (!indexonly) {
		fputs("<div class=\"report\"><table cellpadding=\"1\" cellspacing=\"2\">\n",fp_top3);
		if ((ReportType & REPORT_TYPE_TOPSITES) != 0 && !Privacy) fprintf(fp_top3,"<tr><td class=\"link\" colspan=\"0\"><a href=\"topsites.html\">%s</a></td></tr>\n",_("Top sites"));
		if ((ReportType & REPORT_TYPE_SITES_USERS) != 0 && !Privacy) fprintf(fp_top3,"<tr><td class=\"link\" colspan=\"0\"><a href=\"siteuser.html\">%s</a></td></tr>\n",_("Sites & Users"));
		if (dansguardian_count) fprintf(fp_top3,"<tr><td class=\"link\" colspan=\"0\"><a href=\"dansguardian.html\">%s</a></td></tr>\n",_("DansGuardian"));
		if (redirector_count) fprintf(fp_top3,"<tr><td class=\"link\" colspan=\"0\"><a href=\"redirector.html\">%s</a></td></tr>\n",_("Redirector"));
		if (is_download()) fprintf(fp_top3,"<tr><td class=\"link\" colspan=\"0\"><a href=\"download.html\">%s</a></td></tr>\n",_("Downloads"));
		if (is_denied()) fprintf(fp_top3,"<tr><td class=\"link\" colspan=\"0\"><a href=\"denied.html\">%s</a></td></tr>\n",_("Denied accesses"));
		if (is_authfail()) fprintf(fp_top3,"<tr><td class=\"link\" colspan=\"0\"><a href=\"authfail.html\">%s</a></td></tr>\n",_("Authentication Failures"));
		if (smartfilter) fprintf(fp_top3,"<tr><td class=\"link\" colspan=\"0\"><a href=\"smartfilter.html\">%s</a></td></tr>\n",_("SmartFilter"));
		if (useragent_count) fprintf(fp_top3,"<tr><td class=\"link\" colspan=\"0\"><a href=\"useragent.html\">%s</a></td></tr>\n",_("Useragent"));
		fputs("<tr><td></td></tr>\n</table></div>\n",fp_top3);
	}

	if ((ReportType & REPORT_TYPE_TOPUSERS) == 0) {
		fputs("</body>\n</html>\n",fp_top3);
		if (fclose (fp_top3)==EOF) {
			debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),top3,strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (debugz>=LogLevel_Process) debugaz(__FILE__,__LINE__,_("No top users report because it is not configured in report_type\n"));
		return;
	}

	fputs("<div class=\"report\"><table cellpadding=\"1\" cellspacing=\"2\"",fp_top3);
	if (SortTableJs[0])
		fputs(" class=\"sortable\"",fp_top3);
	fputs(">\n<thead><tr>",fp_top3);

	if ((TopUserFields & TOPUSERFIELDS_NUM) != 0)
		fprintf(fp_top3,"<th class=\"header_l\">%s</th>",_("NUM"));
	if ((TopUserFields & TOPUSERFIELDS_DATE_TIME) !=0 && (ReportType & REPORT_TYPE_DATE_TIME) != 0 && !indexonly) {
		fputs("<th class=\"header_l",fp_top3);
		if (SortTableJs[0]) fputs(" sorttable_nosort",fp_top3);
		fputs("\"></th>",fp_top3);
	}
	if ((TopUserFields & TOPUSERFIELDS_USERID) != 0) {
		fputs("<th class=\"header_l",fp_top3);
		if (SortTableJs[0]) fputs(" sorttable_alpha",fp_top3);
		fprintf(fp_top3,"\">%s</th>",_("USERID"));
	}
	if ((TopUserFields & TOPUSERFIELDS_USERIP) != 0) {
		fputs("<th class=\"header_l",fp_top3);
		if (SortTableJs[0]) fputs(" sorttable_alpha",fp_top3);
		fprintf(fp_top3,"\">%s</th>",_("USERIP"));
	}
	if ((TopUserFields & TOPUSERFIELDS_CONNECT) != 0)
		fprintf(fp_top3,"<th class=\"header_l\">%s</th>",_("CONNECT"));
	if ((TopUserFields & TOPUSERFIELDS_BYTES) != 0)
		fprintf(fp_top3,"<th class=\"header_l\">%s</th>",_("BYTES"));
	if ((TopUserFields & TOPUSERFIELDS_SETYB) != 0)
		fprintf(fp_top3,"<th class=\"header_l\">%%%s</th>",_("BYTES"));
	if ((TopUserFields & TOPUSERFIELDS_IN_CACHE_OUT) != 0)
		fprintf(fp_top3,"<th class=\"header_c\" colspan=\"2\">%s</th><th style=\"display:none;\"></th>",_("IN-CACHE-OUT"));
	if ((TopUserFields & TOPUSERFIELDS_USED_TIME) != 0)
		fprintf(fp_top3,"<th class=\"header_l\">%s</th>",_("ELAPSED TIME"));
	if ((TopUserFields & TOPUSERFIELDS_MILISEC) != 0)
		fprintf(fp_top3,"<th class=\"header_l\">%s</th>",_("MILLISEC"));
	if ((TopUserFields & TOPUSERFIELDS_PTIME) != 0)
		fprintf(fp_top3,"<th class=\"header_l\">%%%s</th>",pgettext("duration","TIME"));

	fputs("</tr></thead>\n",fp_top3);

	greport_prepare();

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),ListFile);
		exit(EXIT_FAILURE);
	}

	while ((warea=longline_read(fp_top1,line))!=NULL) {
		getword_start(&gwarea,warea);
		if (getword(user,sizeof(user),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid user in file \"%s\"\n"),ListFile);
			exit(EXIT_FAILURE);
		}
		if (getword_atoll(&nbytes,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid number of bytes in file \"%s\"\n"),ListFile);
			exit(EXIT_FAILURE);
		}
		if (getword_atoll(&nacc,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid number of accesses in file \"%s\"\n"),ListFile);
			exit(EXIT_FAILURE);
		}
		if (getword_atoll(&elap,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid elapsed time in file \"%s\"\n"),ListFile);
			exit(EXIT_FAILURE);
		}
		if (getword_atoll(&incac,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid in-cache size in file \"%s\"\n"),ListFile);
			exit(EXIT_FAILURE);
		}
		if (getword_atoll(&oucac,&gwarea,'\n')<0) {
			debuga(__FILE__,__LINE__,_("Invalid out-of-cache size in file \"%s\"\n"),ListFile);
			exit(EXIT_FAILURE);
		}
		if (nacc < 1)
			continue;
		ntopuser=true;
		if (TopUsersNum>0 && topcount>=TopUsersNum) break;

		uinfo=userinfo_find_from_id(user);
		if (!uinfo) {
			debuga(__FILE__,__LINE__,_("Unknown user ID %s in file \"%s\"\n"),user,ListFile);
			exit(EXIT_FAILURE);
		}
		uinfo->topuser=1;

		fputs("<tr>",fp_top3);

		posicao++;
		if ((TopUserFields & TOPUSERFIELDS_NUM) != 0)
			fprintf(fp_top3,"<td class=\"data\">%d</td>",posicao);

		if (!indexonly) {
			if ((TopUserFields & TOPUSERFIELDS_DATE_TIME) !=0 && (ReportType & REPORT_TYPE_DATE_TIME) != 0) {
				fputs("<td class=\"data2\">",fp_top3);
#ifdef HAVE_GD
				if (Graphs && GraphFont[0]!='\0') {
					greport_day(uinfo);
					//fprintf(fp_top3,"<a href=\"%s/graph_day.png\"><img src=\"%s/graph.png\" title=\"%s\" alt=\"G\"></a>&nbsp;",uinfo->filename,ImageFile,_("Graphic"));
					fprintf(fp_top3,"<a href=\"%s/graph.html\"><img src=\"%s/graph.png\" title=\"%s\" alt=\"G\"></a>&nbsp;",uinfo->filename,ImageFile,_("Graphic"));
				}
#endif
				report_day(uinfo);
				fprintf(fp_top3,"<a href=\"%s/d%s.html\"><img src=\"%s/datetime.png\" title=\"%s\" alt=\"T\"></a></td>",uinfo->filename,uinfo->filename,ImageFile,_("date/time report"));
				day_deletefile(uinfo);
			}
		}
		if ((TopUserFields & TOPUSERFIELDS_USERID) != 0) {
			if ((ReportType & REPORT_TYPE_USERS_SITES) == 0 || indexonly)
				fprintf(fp_top3,"<td class=\"data2\">%s</td>",uinfo->label);
			else
				fprintf(fp_top3,"<td class=\"data2\"><a href=\"%s/%s.html\">%s</a></td>",uinfo->filename,uinfo->filename,uinfo->label);
		}
		if ((TopUserFields & TOPUSERFIELDS_USERIP) != 0) {
			fprintf(fp_top3,"<td class=\"data2\">%s</td>",uinfo->ip);
		}
		if ((TopUserFields & TOPUSERFIELDS_CONNECT) != 0) {
			fputs("<td class=\"data\"",fp_top3);
			if (SortTableJs[0]) fprintf(fp_top3," sorttable_customkey=\"%"PRId64"\"",(int64_t)nacc);
			fprintf(fp_top3,">%s</td>",fixnum(nacc,1));
		}
		if ((TopUserFields & TOPUSERFIELDS_BYTES) != 0) {
			fputs("<td class=\"data\"",fp_top3);
			if (SortTableJs[0]) fprintf(fp_top3," sorttable_customkey=\"%"PRId64"\"",(int64_t)nbytes);
			fprintf(fp_top3,">%s</td>",fixnum(nbytes,1));
		}
		if ((TopUserFields & TOPUSERFIELDS_SETYB) != 0) {
			perc=(Statis->ttnbytes) ? nbytes * 100. / Statis->ttnbytes : 0.;
			fprintf(fp_top3,"<td class=\"data\">%3.2lf%%</td>",perc);
		}
		if ((TopUserFields & TOPUSERFIELDS_IN_CACHE_OUT) != 0) {
			inperc=(nbytes) ? incac * 100. / nbytes : 0.;
			ouperc=(nbytes) ? oucac * 100. / nbytes : 0.;
			fprintf(fp_top3,"<td class=\"data\">%3.2lf%%</td><td class=\"data\">%3.2lf%%</td>",inperc,ouperc);
#ifdef ENABLE_DOUBLE_CHECK_DATA
			if ((inperc!=0. || ouperc!=0.) && fabs(inperc+ouperc-100.)>=0.01) {
				debuga(__FILE__,__LINE__,_("The total of the in-cache and cache-miss is not 100%% at position %d (user %s)\n"),posicao,uinfo->label);
			}
#endif
		}
		if ((TopUserFields & TOPUSERFIELDS_USED_TIME) != 0) {
			fputs("<td class=\"data\"",fp_top3);
			if (SortTableJs[0]) fprintf(fp_top3," sorttable_customkey=\"%"PRId64"\"",(int64_t)elap);
			fprintf(fp_top3,">%s</td>",buildtime(elap));
		}
		if ((TopUserFields & TOPUSERFIELDS_MILISEC) != 0) {
			fputs("<td class=\"data\"",fp_top3);
			if (SortTableJs[0]) fprintf(fp_top3," sorttable_customkey=\"%"PRId64"\"",(int64_t)elap);
			fprintf(fp_top3,">%s</td>",fixnum2(elap,1));
		}
		if ((TopUserFields & TOPUSERFIELDS_PTIME) != 0) {
			perc2=(Statis->ttnelap) ? elap * 100. / Statis->ttnelap : 0.;
			fprintf(fp_top3,"<td class=\"data\">%3.2lf%%</td>",perc2);
		}

		fputs("</tr>\n",fp_top3);

		topcount++;
	}
	if (FileObject_Close(fp_top1)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),ListFile,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}
	if (!KeepTempLog && unlink(ListFile)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),ListFile,strerror(errno));
		exit(EXIT_FAILURE);
	}
	longline_destroy(&line);

	if ((TopUserFields & TOPUSERFIELDS_TOTAL) != 0) {
		fputs("<tfoot><tr>",fp_top3);
		if ((TopUserFields & TOPUSERFIELDS_NUM) != 0)
			fputs("<td></td>",fp_top3);
		if ((TopUserFields & TOPUSERFIELDS_DATE_TIME) !=0 && (ReportType & REPORT_TYPE_DATE_TIME) != 0 && !indexonly)
			fputs("<td></td>",fp_top3);
		if ((TopUserFields & TOPUSERFIELDS_USERIP) != 0)
			fprintf(fp_top3,"<th class=\"header_l\" colspan=\"2\">%s</th>",_("TOTAL"));
		else
			fprintf(fp_top3,"<th class=\"header_l\">%s</th>",_("TOTAL"));

		if ((TopUserFields & TOPUSERFIELDS_CONNECT) != 0)
			fprintf(fp_top3,"<th class=\"header_r\">%s</th>",fixnum(Statis->ttnacc,1));
		if ((TopUserFields & TOPUSERFIELDS_BYTES) != 0)
			fprintf(fp_top3,"<th class=\"header_r\">%15s</th>",fixnum(Statis->ttnbytes,1));
		if ((TopUserFields & TOPUSERFIELDS_SETYB) != 0)
			fputs("<td></td>",fp_top3);
		if ((TopUserFields & TOPUSERFIELDS_IN_CACHE_OUT) != 0)
		{
			inperc=(Statis->ttnbytes) ? Statis->ttnincache * 100. / Statis->ttnbytes : 0.;
			ouperc=(Statis->ttnbytes) ? Statis->ttnoucache *100. / Statis->ttnbytes : 0.;
			fprintf(fp_top3,"<th class=\"header_r\">%3.2lf%%</th><th class=\"header_r\">%3.2lf%%</th>",inperc,ouperc);
#ifdef ENABLE_DOUBLE_CHECK_DATA
			if (fabs(inperc+ouperc-100.)>=0.01) {
				debuga(__FILE__,__LINE__,_("The total of the in-cache and cache-miss is not 100%%\n"));
			}
#endif
		}
		if ((TopUserFields & TOPUSERFIELDS_USED_TIME) != 0)
			fprintf(fp_top3,"<th class=\"header_r\">%s</th>",buildtime(Statis->ttnelap));
		if ((TopUserFields & TOPUSERFIELDS_MILISEC) != 0)
			fprintf(fp_top3,"<th class=\"header_r\">%s</th>",fixnum2(Statis->ttnelap,1));

		fputs("</tr>\n",fp_top3);
	}
	greport_cleanup();

	if (ntopuser && (TopUserFields & TOPUSERFIELDS_AVERAGE) != 0) {
		fputs("<tr>",fp_top3);
		if ((TopUserFields & TOPUSERFIELDS_NUM) != 0)
			fputs("<td></td>",fp_top3);
		if ((TopUserFields & TOPUSERFIELDS_DATE_TIME) !=0 && (ReportType & REPORT_TYPE_DATE_TIME) != 0 && !indexonly)
			fputs("<td></td>",fp_top3);
		if ((TopUserFields & TOPUSERFIELDS_USERIP) != 0)
			fprintf(fp_top3,"<th class=\"header_l\" colspan=\"2\">%s</th>",_("AVERAGE"));
		else
			fprintf(fp_top3,"<th class=\"header_l\">%s</th>",_("AVERAGE"));

		if ((TopUserFields & TOPUSERFIELDS_CONNECT) != 0)
			fprintf(fp_top3,"<th class=\"header_r\">%s</th>",fixnum(Statis->ttnacc/Statis->totuser,1));
		if ((TopUserFields & TOPUSERFIELDS_BYTES) != 0) {
			nbytes=(Statis->totuser) ? Statis->ttnbytes / Statis->totuser : 0;
			fprintf(fp_top3,"<th class=\"header_r\">%15s</th>",fixnum(nbytes,1));
		}
		if ((TopUserFields & TOPUSERFIELDS_SETYB) != 0)
			fputs("<td></td>",fp_top3);
		if ((TopUserFields & TOPUSERFIELDS_IN_CACHE_OUT) != 0)
			fputs("<td></td><td></td>",fp_top3);
		if ((TopUserFields & TOPUSERFIELDS_USED_TIME) != 0)
			fprintf(fp_top3,"<th class=\"header_r\">%s</th>",buildtime(Statis->ttnelap/Statis->totuser));
		if ((TopUserFields & TOPUSERFIELDS_MILISEC) != 0)
			fprintf(fp_top3,"<th class=\"header_r\">%s</th>",fixnum2(Statis->ttnelap/Statis->totuser,1));
		fputs("</tr></tfoot>\n",fp_top3);
	}

	fputs("</table></div>\n",fp_top3);
	write_html_trailer(fp_top3);
	if (fclose(fp_top3)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),top3,strerror(errno));
		exit(EXIT_FAILURE);
	}
}

/*!
  Generate the top user email report.
 */
static void TopUser_TextEmail(const char *ListFile,struct TopUserStatistics *Statis,struct SortInfoStruct *SortInfo)
{
	FileObject *fp_top1;
	FILE *fp_mail;
	longline line;
	struct getwordstruct gwarea;
	char *warea;
	char user[MAX_USER_LEN];
	char strip1[MAXLEN], strip2[MAXLEN], strip3[MAXLEN], strip4[MAXLEN], strip5[MAXLEN], strip6[MAXLEN], strip7[MAXLEN];
	long long int nbytes;
	long long int nacc;
	long long int elap, incac, oucac;
	double perc=0.00;
	double perc2=0.00;
	long long int tnbytes=0;
	long long int avgacc, avgelap;
	int topcount=0;
	struct userinfostruct *uinfo;
	time_t t;
	struct tm *local;
	const char *Subject;

	if ((fp_top1=FileObject_Open(ListFile))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),ListFile,FileObject_GetLastOpenError());
		exit(EXIT_FAILURE);
	}

	fp_mail=Email_OutputFile("topuser");

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),ListFile);
		exit(EXIT_FAILURE);
	}

	safe_strcpy(strip1,_("Squid User Access Report"),sizeof(strip1));
	strip_latin(strip1);
	fprintf(fp_mail,"%s\n",strip1);

	snprintf(strip1,sizeof(strip1),_("Sort: %s, %s"),SortInfo->sort_field,SortInfo->sort_order);
	strip_latin(strip1);
	fprintf(fp_mail,"%s\n",strip1);

	snprintf(strip1,sizeof(strip1),_("Period: %s"),period.text);
	strip_latin(strip1);
	fprintf(fp_mail,"%s\n\n",strip1);

	safe_strcpy(strip1,_("NUM"),sizeof(strip1));
	strip_latin(strip1);
	safe_strcpy(strip2,_("USERID"),sizeof(strip2));
	strip_latin(strip2);
	safe_strcpy(strip3,_("CONNECT"),sizeof(strip3));
	strip_latin(strip3);
	safe_strcpy(strip4,_("BYTES"),sizeof(strip4));
	strip_latin(strip4);
	safe_strcpy(strip5,_("ELAPSED TIME"),sizeof(strip5));
	strip_latin(strip5);
	safe_strcpy(strip6,_("MILLISEC"),sizeof(strip6));
	strip_latin(strip6);
	safe_strcpy(strip7,pgettext("duration","TIME"),sizeof(strip7));
	strip_latin(strip7);

	fprintf(fp_mail,"%-7s %-20s %-9s %-15s %%%-6s %-11s %-10s %%%-7s\n------- -------------------- -------- --------------- ------- ---------- ---------- -------\n",strip1,strip2,strip3,strip4,strip4,strip5,strip6,strip7);


	while ((warea=longline_read(fp_top1,line))!=NULL) {
		getword_start(&gwarea,warea);
		if (getword(user,sizeof(user),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid user in file \"%s\"\n"),ListFile);
			exit(EXIT_FAILURE);
		}
		if (getword_atoll(&nbytes,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid number of bytes in file \"%s\"\n"),ListFile);
			exit(EXIT_FAILURE);
		}
		if (getword_atoll(&nacc,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid number of accesses in file \"%s\"\n"),ListFile);
			exit(EXIT_FAILURE);
		}
		if (getword_atoll(&elap,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid elapsed time in file \"%s\"\n"),ListFile);
			exit(EXIT_FAILURE);
		}
		if (getword_atoll(&incac,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid in-cache size in file \"%s\"\n"),ListFile);
			exit(EXIT_FAILURE);
		}
		if (getword_atoll(&oucac,&gwarea,'\n')<0) {
			debuga(__FILE__,__LINE__,_("Invalid out-of-cache size in file \"%s\"\n"),ListFile);
			exit(EXIT_FAILURE);
		}
		if (nacc < 1)
			continue;
		if (TopUsersNum>0 && topcount>=TopUsersNum) break;

		uinfo=userinfo_find_from_id(user);
		if (!uinfo) {
			debuga(__FILE__,__LINE__,_("Unknown user ID %s in file \"%s\"\n"),user,ListFile);
			exit(EXIT_FAILURE);
		}
		uinfo->topuser=1;

		perc=(Statis->ttnbytes) ? nbytes * 100. / Statis->ttnbytes : 0;
		perc2=(Statis->ttnelap) ? elap * 100. / Statis->ttnelap : 0;

		topcount++;

#if defined(__FreeBSD__)
		fprintf(fp_mail,"%7d %20s %8lld %15s %5.2lf%% %10s %10qu %3.2lf%%\n",topcount,uinfo->label,nacc,fixnum(nbytes,1),perc,buildtime(elap),elap,perc2);
#else
		fprintf(fp_mail,"%7d %20s %8"PRIu64" %15s %6.2lf%% %10s %10"PRIu64" %3.2lf%%\n",topcount,uinfo->label,(uint64_t)nacc,fixnum(nbytes,1),perc,buildtime(elap),(uint64_t)elap,perc2);
#endif
	}
	if (FileObject_Close(fp_top1)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),ListFile,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}
	if (!KeepTempLog && unlink(ListFile)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),ListFile,strerror(errno));
		exit(EXIT_FAILURE);
	}
	longline_destroy(&line);

	// output total
	fputs("------- -------------------- -------- --------------- ------- ---------- ---------- -------\n",fp_mail);
#if defined(__FreeBSD__)
	fprintf(fp_mail,"%-7s %20s %8qu %15s %8s %9s %10qu\n",_("TOTAL")," ",Statis->ttnacc,fixnum(Statis->ttnbytes,1)," ",buildtime(Statis->ttnelap),Statis->ttnelap);
#else
	fprintf(fp_mail,"%-7s %20s %8"PRIu64" %15s %8s %9s %10"PRIu64"\n",_("TOTAL")," ",(uint64_t)Statis->ttnacc,fixnum(Statis->ttnbytes,1)," ",buildtime(Statis->ttnelap),(uint64_t)Statis->ttnelap);
#endif

	// compute and write average
	if (Statis->totuser>0) {
		tnbytes=Statis->ttnbytes / Statis->totuser;
		avgacc=Statis->ttnacc/Statis->totuser;
		avgelap=Statis->ttnelap/Statis->totuser;
	} else {
		tnbytes=0;
		avgacc=0;
		avgelap=0;
	}

	safe_strcpy(strip1,_("AVERAGE"),sizeof(strip1));
	strip_latin(strip1);
#if defined(__FreeBSD__)
	fprintf(fp_mail,"%-7s %20s %8qu %15s %8s %9s %10qu\n",strip1," ",avgacc,fixnum(tnbytes,1)," ",buildtime(avgelap),avgelap);
#else
	fprintf(fp_mail,"%-7s %20s %8"PRIu64" %15s %8s %9s %10"PRIu64"\n",strip1," ",(uint64_t)avgacc,fixnum(tnbytes,1)," ",buildtime(avgelap),(uint64_t)avgelap);
#endif

	t = time(NULL);
	local = localtime(&t);
	fprintf(fp_mail, "\n%s\n", asctime(local));

	/* TRANSLATORS: This is the e-mail subject. */
	Subject=_("Sarg: top user report");
	Email_Send(fp_mail,Subject);
}

/*!
 * Produce a report with the user downloading the most data.
 */
void topuser(void)
{
	FileObject *fp_in = NULL;
	FILE *fp_top2;
	char wger[MAXLEN];
	char top1[MAXLEN];
	char top2[MAXLEN];
	longline line;
	long long int tnacc=0;
	long long int tnbytes=0, tnelap=0;
	long long int tnincache=0, tnoucache=0;
	char *warea;
	struct generalitemstruct item;
	char olduser[MAX_USER_LEN], csort[MAXLEN];
	const char *sfield="-n -k 2,2";
	const char *order;
	int cstatus;
	struct TopUserStatistics Statis;
	struct SortInfoStruct SortInfo;

	if (debugz>=LogLevel_Process)
		debuga(__FILE__,__LINE__,_("Creating top users report...\n"));

	memset(&Statis,0,sizeof(Statis));

	format_path(__FILE__, __LINE__, wger, sizeof(wger), "%s/sarg-general", outdirname);
	if ((fp_in=FileObject_Open(wger))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),wger,FileObject_GetLastOpenError());
		exit(EXIT_FAILURE);
	}

	format_path(__FILE__, __LINE__, top2, sizeof(top2), "%s/top.tmp", outdirname);
	if ((fp_top2=fopen(top2,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),top2,strerror(errno));
		exit(EXIT_FAILURE);
	}

	olduser[0]='\0';

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),wger);
		exit(EXIT_FAILURE);
	}

	while ((warea=longline_read(fp_in,line))!=NULL) {
		ger_read(warea,&item,wger);
		if (item.total) continue;
		if (strcmp(olduser,item.user) != 0) {
			Statis.totuser++;

			if (olduser[0] != '\0') {
				/*
				This complicated printf is due to Microsoft's inability to comply with any standard. Msvcrt is unable
				to print a long long int unless it is exactly 64-bits long.
				*/
				fprintf(fp_top2,"%s\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\n",olduser,(uint64_t)tnbytes,(uint64_t)tnacc,(uint64_t)tnelap,(uint64_t)tnincache,(uint64_t)tnoucache);

				Statis.ttnbytes+=tnbytes;
				Statis.ttnacc+=tnacc;
				Statis.ttnelap+=tnelap;
				Statis.ttnincache+=tnincache;
				Statis.ttnoucache+=tnoucache;
			}
			safe_strcpy(olduser,item.user,sizeof(olduser));
			tnbytes=0;
			tnacc=0;
			tnelap=0;
			tnincache=0;
			tnoucache=0;
		}

		tnbytes+=item.nbytes;
		tnacc+=item.nacc;
		tnelap+=item.nelap;
		tnincache+=item.incache;
		tnoucache+=item.oucache;
	}
	if (FileObject_Close(fp_in)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),wger,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}
	longline_destroy(&line);

	if (olduser[0] != '\0') {
		/*
		This complicated printf is due to Microsoft's inability to comply with any standard. Msvcrt is unable
		to print a long long int unless it is exactly 64-bits long.
		*/
		fprintf(fp_top2,"%s\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\n",olduser,(uint64_t)tnbytes,(uint64_t)tnacc,(uint64_t)tnelap,(uint64_t)tnincache,(uint64_t)tnoucache);

		Statis.ttnbytes+=tnbytes;
		Statis.ttnacc+=tnacc;
		Statis.ttnelap+=tnelap;
		Statis.ttnincache+=tnincache;
		Statis.ttnoucache+=tnoucache;
	}
	if (fclose(fp_top2)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),top2,strerror(errno));
		exit(EXIT_FAILURE);
	}

#ifdef ENABLE_DOUBLE_CHECK_DATA
	if (Statis.ttnacc!=globstat.nacc || Statis.ttnbytes!=globstat.nbytes || Statis.ttnelap!=globstat.elap ||
		Statis.ttnincache!=globstat.incache || Statis.ttnoucache!=globstat.oucache) {
		debuga(__FILE__,__LINE__,_("Total statistics mismatch when reading \"%s\" to produce the top users\n"),wger);
		exit(EXIT_FAILURE);
	}
#endif

	set_total_users(Statis.totuser);

	if ((TopuserSort & TOPUSER_SORT_USER) != 0) {
		sfield="-k 1,1";
		SortInfo.sort_field=_("user");
	} else if ((TopuserSort & TOPUSER_SORT_CONNECT) != 0) {
		sfield="-n -k 3,3";
		SortInfo.sort_field=_("connect");
	} else if ((TopuserSort & TOPUSER_SORT_TIME) != 0) {
		sfield="-n -k 4,4";
		SortInfo.sort_field=pgettext("duration","time");
	} else {
		SortInfo.sort_field=_("bytes");
	}

	if ((TopuserSort & TOPUSER_SORT_REVERSE) == 0) {
		order="";
		SortInfo.sort_order=_("normal");
	} else {
		order="-r";
		SortInfo.sort_order=_("reverse");
	}

	format_path(__FILE__, __LINE__, top1, sizeof(top1), "%s/top", outdirname);
	if (snprintf(csort,sizeof(csort),"sort -T \"%s\" -t \"\t\" %s %s -o \"%s\" \"%s\"", tmp, order, sfield, top1, top2)>=sizeof(csort)) {
		debuga(__FILE__,__LINE__,_("Sort command too long when sorting file \"%s\" to \"%s\"\n"),top2,top1);
		exit(EXIT_FAILURE);
	}
	cstatus=system(csort);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(__FILE__,__LINE__,_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}

	if (!KeepTempLog && unlink(top2)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),top2,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (email[0])
		TopUser_TextEmail(top1,&Statis,&SortInfo);
	else
		TopUser_HtmlReport(top1,&Statis,&SortInfo);
}
