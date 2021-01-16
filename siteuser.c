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

void siteuser(void)
{
	FileObject *fp_in;
	FILE *fp_ou;

	char *buf;
	char *ourl;
	char csort[4096];
	char general[MAXLEN];
	char general2[MAXLEN];
	char sites[MAXLEN];
	char report[MAXLEN];
	int regs=0;
	int ourl_size;
	int url_len;
	int topuser_link;
	int nsitesusers;
	int cstatus;
	longline line;
	struct generalitemstruct item;
	struct userinfostruct *uinfo;

	if (Privacy) {
		if (debugz>=LogLevel_Process) debugaz(__FILE__,__LINE__,_("Sites & users report not generated because privacy option is on\n"));
		return;
	}

	if (debugz>=LogLevel_Process)
		debuga(__FILE__,__LINE__,_("Creating report to list who visisted what site...\n"));
	nsitesusers = 0;
	format_path(__FILE__, __LINE__, general, sizeof(general), "%s/sarg-general", outdirname);
	format_path(__FILE__, __LINE__, sites, sizeof(sites), "%s/sarg-sites", outdirname);
	format_path(__FILE__, __LINE__, general2, sizeof(general2), "%s/sarg-general2", outdirname);
	format_path(__FILE__, __LINE__, report, sizeof(report), "%s/siteuser.html", outdirname);

	if (snprintf(csort,sizeof(csort),"sort -t \"\t\" -k 4,4 -k 1,1 -o \"%s\" \"%s\"",general2,general)>=sizeof(csort)) {
		debuga(__FILE__,__LINE__,_("Sort command too long when sorting file \"%s\" to \"%s\"\n"),general,general2);
		exit(EXIT_FAILURE);
	}
	cstatus=system(csort);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(__FILE__,__LINE__,_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}

	if ((fp_in=FileObject_Open(general2))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),general2,FileObject_GetLastOpenError());
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}

	if ((fp_ou=fopen(report,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),report,strerror(errno));
		exit(EXIT_FAILURE);
	}

	write_html_header(fp_ou,(IndexTree == INDEX_TREE_DATE) ? 3 : 1,_("Sites & Users"),HTML_JS_SORTTABLE);
	fputs("<tr><td class=\"header_c\">",fp_ou);
	fprintf(fp_ou,_("Period: %s"),period.html);
	fputs("</td></tr>\n",fp_ou);
	fprintf(fp_ou,"<tr><th class=\"header_c\">%s</th></tr>\n",_("Sites & Users"));
	close_html_header(fp_ou);

	fputs("<div class=\"report\"><table cellpadding=\"0\" cellspacing=\"2\"",fp_ou);
	if (SortTableJs[0]) fputs(" class=\"sortable\"",fp_ou);
	fprintf(fp_ou,">\n<thead><tr><th class=\"header_l\">%s</th><th class=\"header_l",_("NUM"));
	if (SortTableJs[0]) fputs(" sorttable_alpha",fp_ou);
	fprintf(fp_ou,"\">%s</th>",_("ACCESSED SITE"));
	if (BytesInSitesUsersReport)
		fprintf(fp_ou,"<th class=\"header_l\">%s</th>",_("BYTES"));
	fputs("<th class=\"header_l",fp_ou);
	if (SortTableJs[0]) fputs(" sorttable_alpha",fp_ou);
	/* TRANSLATORS: This is a column header showing the users who visited each site. */
	fprintf(fp_ou,"\">%s</th></tr></thead>\n",_("USERS"));

	ourl=NULL;
	ourl_size=0;

	userinfo_clearflag();
	topuser_link=((ReportType & REPORT_TYPE_USERS_SITES) != 0 && !indexonly);

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),general2);
		exit(EXIT_FAILURE);
	}

	while((buf=longline_read(fp_in,line))!=NULL) {
		ger_read(buf,&item,general2);
		if (item.total) continue;
		uinfo=userinfo_find_from_id(item.user);
		if (!uinfo) {
			debuga(__FILE__,__LINE__,_("Unknown user ID %s in file \"%s\"\n"),item.user,general2);
			exit(EXIT_FAILURE);
		}

		if (item.nacc > 0) nsitesusers = 1;
		if (!nsitesusers) continue;

		if (ourl==NULL || strcmp(item.url,ourl) != 0) {
			if (regs>0) fputs("</td></tr>\n",fp_ou);

			regs++;
			if (SiteUsersReportLimit && regs >= SiteUsersReportLimit)
				break;
			fprintf(fp_ou,"<tr><td class=\"data\">%d</td><td class=\"data2\">",regs);

			url_len=strlen(item.url);
			if (url_len>=ourl_size) {
				ourl_size=url_len+1;
				ourl=realloc(ourl,ourl_size);
				if (!ourl) {
					debuga(__FILE__,__LINE__,_("Not enough memory to store the url\n"));
					exit(EXIT_FAILURE);
				}
			}
			strcpy(ourl,item.url);

			if (BlockIt[0]!='\0' && ourl[0]!=ALIAS_PREFIX) {
				fprintf(fp_ou,"<a href=\"%s%s?url=",wwwDocumentRoot,BlockIt);
				output_html_url(fp_ou,ourl);
				fputs("\"><img src=\"../images/sarg-squidguard-block.png\"></a>&nbsp;",fp_ou);
			}
			output_html_link(fp_ou,ourl,100);
			fputs("</td>",fp_ou);

			if (BytesInSitesUsersReport) {
				fputs("<td class=\"data\"",fp_ou);
				if (SortTableJs[0]) fprintf(fp_ou," sorttable_customkey=\"%"PRId64"\"",(int64_t)item.nbytes);
				fprintf(fp_ou,">%s</td>",fixnum(item.nbytes,1));
			}
			fputs("<td class=\"data2\">",fp_ou);

			userinfo_clearflag();
			if (topuser_link && uinfo->topuser)
				fprintf(fp_ou,"<a href=\"%s/%s.html\">%s</a>",uinfo->filename,uinfo->filename,uinfo->label);
			else
				fprintf(fp_ou,"%s",uinfo->label);
			uinfo->flag=1;
		}
		else if (uinfo->flag==0) {
			if (topuser_link && uinfo->topuser)
				fprintf(fp_ou," <a href=\"%s/%s.html\">%s</a>",uinfo->filename,uinfo->filename,uinfo->label);
			else
				fprintf(fp_ou," %s",uinfo->label);
			uinfo->flag=1;
		}

	}
	if (FileObject_Close(fp_in)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),general2,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}
	longline_destroy(&line);

	if (regs>0) {
		fputs("</td></tr>\n",fp_ou);
	}
	if (ourl) free(ourl);

	if (!KeepTempLog && unlink(general2)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),general2,strerror(errno));
		exit(EXIT_FAILURE);
	}

	fputs("</table></div>\n",fp_ou);
	write_html_trailer(fp_ou);
	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),report,strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}
