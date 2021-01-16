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

static void show_ignored_dansguardian(FILE *fp_ou,int count)
{
	char ignored[80];

	snprintf(ignored,sizeof(ignored),ngettext("%d more dansguardian entry not shown here&hellip;","%d more dansguardian entries not shown here&hellip;",count),count);
	fprintf(fp_ou,"<tr><td class=\"data\"></td><td class=\"data\"></td><td class=\"data\"></td><td class=\"data2 more\">%s</td><td class=\"data\"></td></tr>\n",ignored);
}

void dansguardian_report(void)
{
	FILE *fp_in = NULL, *fp_ou = NULL;

	char buf[MAXLEN];
	char *url;
	char dansguardian_in[MAXLEN];
	char report[MAXLEN];
	char ip[MAXLEN];
	char rule[255];
	char oip[MAXLEN];
	char user[MAXLEN];
	char ouser[MAXLEN];
	char date[15];
	char date2[15];
	char hour[15];
	char ouser2[255];
	int  z=0;
	int  count=0;
	struct getwordstruct gwarea;

	ouser[0]='\0';

	format_path(__FILE__, __LINE__, dansguardian_in, sizeof(dansguardian_in), "%s/dansguardian.int_log", tmp);
	if (!dansguardian_count) {
		if (!KeepTempLog && unlink(dansguardian_in))
			debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),dansguardian_in,strerror(errno));
		if (debugz>=LogLevel_Process) debugaz(__FILE__,__LINE__,_("Dansguardian report not generated because it is empty\n"));
		return;
	}

	format_path(__FILE__, __LINE__, report, sizeof(report), "%s/dansguardian.html", outdirname);

	if ((fp_in=MY_FOPEN(dansguardian_in,"r"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),dansguardian_in,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((fp_ou=MY_FOPEN(report,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),report,strerror(errno));
		exit(EXIT_FAILURE);
	}

	write_html_header(fp_ou,(IndexTree == INDEX_TREE_DATE) ? 3 : 1,_("DansGuardian"),HTML_JS_NONE);
	fputs("<tr><td class=\"header_c\">",fp_ou);
	fprintf(fp_ou,_("Period: %s"),period.html);
	fputs("</td></tr>\n",fp_ou);
	fprintf(fp_ou,"<tr><th class=\"header_c\">%s</th></tr>\n",_("DansGuardian"));
	close_html_header(fp_ou);

	fputs("<div class=\"report\"><table cellpadding=\"1\" cellspacing=\"2\">\n",fp_ou);
	fprintf(fp_ou,"<tr><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th></tr>\n",_("USERID"),_("IP/NAME"),_("DATE/TIME"),_("ACCESSED SITE"),_("CAUSE"));

	while(fgets(buf,sizeof(buf),fp_in)!=NULL) {
		getword_start(&gwarea,buf);
		if (getword(user,sizeof(user),&gwarea,'\t')<0 || getword(date2,sizeof(date2),&gwarea,'\t')<0 ||
		    getword(hour,sizeof(hour),&gwarea,'\t')<0 || getword(ip,sizeof(ip),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid record in file \"%s\"\n"),dansguardian_in);
			exit(EXIT_FAILURE);
		}
		if (getword_ptr(buf,&url,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid url in file \"%s\"\n"),dansguardian_in);
			exit(EXIT_FAILURE);
		}
		if (getword(rule,sizeof(rule),&gwarea,'\n')<0) {
			debuga(__FILE__,__LINE__,_("Invalid rule in file \"%s\"\n"),dansguardian_in);
			exit(EXIT_FAILURE);
		}

		if (UserIp)
			strcpy(user,ip);

		memset(date,0,sizeof(date));
		if (df!='u') {
			strncpy(date,date2+6,2);
			strcat(date,"/");
			strncat(date,date2+4,2);
			strcat(date,"/");
			strncat(date,date2,4);
		} else {
			strncpy(date,date2+4,2);
			strcat(date,"/");
			strncat(date,date2+6,2);
			strcat(date,"/");
			strncat(date,date2,4);
		}

		if (Ip2Name)
			ip2name(ip,sizeof(ip));

		if (!z) {
			strcpy(ouser,user);
			strcpy(oip,ip);
			z++;
		} else {
			if (strcmp(ouser,user) == 0)
				user[0]='\0';
			if (user[0] != '\0')
				strcpy(ouser,user);
			if (strcmp(oip,ip) == 0)
				ip[0]='\0';
			if (ip[0] != '\0')
				strcpy(oip,ip);
		}

		user_find(name, sizeof(name), user);

		if (DansGuardianReportLimit) {
			if (strcmp(ouser2,name) == 0) {
				count++;
			} else {
				if (count>DansGuardianReportLimit && DansGuardianReportLimit>0)
					show_ignored_dansguardian(fp_ou,count-DansGuardianReportLimit);
				count=1;
				strcpy(ouser2,name);
			}
			if (count > DansGuardianReportLimit)
				continue;
		}

		fprintf(fp_ou,"<tr><td class=\"data2\">%s</td><td class=\"data2\">%s</td><td class=\"data2\">%s-%s</td><td class=\"data2\">",name,ip,date,hour);
		output_html_link(fp_ou,url,100);
		fprintf(fp_ou,"</td><td class=\"data2\">%s</td></tr>\n",rule);
	}
	if (fclose(fp_in)==EOF) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),dansguardian_in,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (count>DansGuardianReportLimit && DansGuardianReportLimit>0)
		show_ignored_dansguardian(fp_ou,count-DansGuardianReportLimit);

	fputs("</table></div>\n",fp_ou);
	write_html_trailer(fp_ou);
	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),report,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!KeepTempLog && unlink(dansguardian_in)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),dansguardian_in,strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}
