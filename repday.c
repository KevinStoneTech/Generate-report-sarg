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

extern int hours[24];

void report_day(const struct userinfostruct *uinfo)
{
	FILE *fp_in, *fp_ou;

	char buf[200];
	char data[20];
	long long int hour;
	const char *label;
	char arqout[MAXLEN];
	char wdirname[2048];
	char colsep;
	int  ihour=0;
	int day,month,year;
	int daylist[MAX_DATETIME_DAYS];
	int daysort[MAX_DATETIME_DAYS];
	int ndaylist;
	int daynum;
	int dayidx;
	long long int bytes;
	long long int elap;
	long long int tbytes[MAX_DATETIME_DAYS*24];
	long long int telap[MAX_DATETIME_DAYS*24];
	long long int tt;
	long long int tttime[24];
	int i, j;
	struct getwordstruct gwarea;
	struct tm t;

	if (datetimeby==0) return;
	format_path(__FILE__, __LINE__, wdirname, sizeof(wdirname), "%s/%s.day", tmp, uinfo->filename);
	if (access(wdirname, R_OK) != 0) return;

	if (snprintf(arqout,sizeof(arqout),"%s/%s/d%s.html",outdirname,uinfo->filename,uinfo->filename)>=sizeof(arqout)) {
		debuga(__FILE__,__LINE__,_("Path too long: "));
		debuga_more("%s/%s/d%s.html\n",outdirname,uinfo->filename,uinfo->filename);
		exit(EXIT_FAILURE);
	}

	if ((fp_in=fopen(wdirname,"r"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),wdirname,strerror(errno));
		exit(EXIT_FAILURE);
	}

	memset(tbytes,0,sizeof(tbytes));
	memset(telap,0,sizeof(telap));
	ndaylist=0;

	while(fgets(buf,sizeof(buf),fp_in)!=NULL) {
		fixendofline(buf);
		getword_start(&gwarea,buf);
		if (getword(data,sizeof(data),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid date in file \"%s\"\n"),wdirname);
			exit(EXIT_FAILURE);
		}
		if (sscanf(data,"%d/%d/%d",&day,&month,&year)!=3) continue;
		if (day<1 || day>31 || month<1 || month>12 || year>9999) continue;
		daynum=(year*10000)+(month*100)+day;
		for (dayidx=0 ; dayidx<ndaylist && daynum!=daylist[dayidx] ; dayidx++);
		if (dayidx>=ndaylist) {
			if (dayidx>=sizeof(daylist)/sizeof(*daylist)) {
				debuga(__FILE__,__LINE__,_("Too many different dates in file \"%s\"\n"),wdirname);
				exit(EXIT_FAILURE);
			}
			daylist[ndaylist++]=daynum;
		}

		if (getword_atoll(&hour,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid time in file \"%s\"\n"),wdirname);
			exit(EXIT_FAILURE);
		}
		ihour=(int)hour;
		i=dayidx*24+ihour;

		if ((datetimeby & DATETIME_BYTE)!=0) {
			colsep=((datetimeby & DATETIME_ELAP)!=0) ? '\t' : '\0';
			if (getword_atoll(&bytes,&gwarea,colsep)<0) {
				debuga(__FILE__,__LINE__,_("Invalid number of bytes in file \"%s\"\n"),wdirname);
				exit(EXIT_FAILURE);
			}
			tbytes[i]+=bytes;
		}
		if ((datetimeby & DATETIME_ELAP)!=0) {
			if (getword_atoll(&elap,&gwarea,'\0')<0) {
				debuga(__FILE__,__LINE__,_("Invalid elapsed time in file \"%s\"\n"),wdirname);
				exit(EXIT_FAILURE);
			}
			telap[i]+=elap;
		}
	}
	if (fclose(fp_in)==EOF) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),wdirname,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((fp_ou=fopen(arqout,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),arqout,strerror(errno));
		exit(EXIT_FAILURE);
	}

	write_html_header(fp_ou,(IndexTree == INDEX_TREE_DATE) ? 4 : 2,_("Day report"),HTML_JS_NONE);
	fprintf(fp_ou,"<tr><td class=\"header_c\" colspan=\"2\">%s:&nbsp;%s</td></tr>\n",_("Period"),period.html);
	fprintf(fp_ou,"<tr><th class=\"header_c\" colspan=\"2\">%s:&nbsp;%s</th></tr>\n",_("User"),uinfo->label);
	close_html_header(fp_ou);

	dayidx=0;
	for (i=0 ; i<ndaylist ; i++) {
		daynum=daylist[i];
		for (j=dayidx ; j>0 && daynum<daylist[daysort[j-1]] ; j--) daysort[j]=daysort[j-1];
		daysort[j]=i;
		dayidx++;
	}

	if ((datetimeby & DATETIME_BYTE)!=0) {
		label=_("BYTES");
		fputs("<table class=\"report\" cellpadding=\"0\" cellspacing=\"2\">\n", fp_ou);
		fputs("<tr><th class=\"header_c\"></th>",fp_ou);
		for (i=0 ; i<24 ; i++)
		{
			if (hours[i])
			{
				/* TRANSLATORS: It is an hour in the hourly report */
				sprintf(data,_("%02dH"),i);
				fprintf(fp_ou, "<td class=\"header_c\">%s<br>%s</td>\n", data, label );
			}
		}
		fprintf(fp_ou, "<td class=\"header_c\">%s<br>%s</td></tr>\n", _("TOTAL"), label );

		memset(tttime,0,sizeof(tttime));
		for (dayidx=0 ; dayidx<ndaylist ; dayidx++) {
			daynum=daysort[dayidx];
			day=daylist[daynum]%100;
			month=(daylist[daynum]/100)%100;
			year=daylist[daynum]/10000;
			computedate(year,month,day,&t);
			strftime(data,sizeof(data),"%x",&t);
			fprintf(fp_ou, "<tr><td class=\"data\">%s</td>\n", data );
			tt=0;
			for (i=0 ; i<24 ; i++)
			{
				if (!hours[i]) continue;
				ihour=i;
				if (tbytes[daynum*24+ihour]>0)
				{
					fprintf(fp_ou, "<td class=\"data\">%s</td>\n",fixnum(tbytes[daynum*24+ihour],1));
					tt+=tbytes[daynum*24+ihour];
					tttime[ihour]+=tbytes[daynum*24+ihour];
				}
				else
					fputs("<td class=\"data\"></td>\n",fp_ou);
			}
			fprintf(fp_ou, "<td class=\"data\">%s</td></tr>\n",fixnum(tt,1));
		}

		fprintf(fp_ou, "<tr><td class=\"header_l\">%s</td>\n", _("TOTAL") );
		tt=0;
		for (i=0 ; i<24 ; i++)
		{
			if (!hours[i]) continue;
			if (tttime[i]>0)
			{
				fprintf(fp_ou, "<td class=\"header_r\">%s</td>\n",fixnum(tttime[i],1));
				tt+=tttime[i];
			}
			else
				fputs("<td class=\"header_r\"></td>\n",fp_ou);
		}
		fprintf(fp_ou, "<td class=\"header_r\">%s</td></tr>\n",fixnum(tt,1));
		fputs("</table>\n",fp_ou);
#ifdef ENABLE_DOUBLE_CHECK_DATA
		if (tt!=uinfo->nbytes) {
			debuga(__FILE__,__LINE__,_("Total downloaded bytes is %"PRIi64" instead of %"PRIi64" in the hourly report of user %s\n"),
						 (int64_t)tt,(int64_t)uinfo->nbytes,uinfo->label);
			exit(EXIT_FAILURE);
		}
#endif
	}

	if ((datetimeby & DATETIME_ELAP)!=0) {
		label=_("H:M:S");
		fputs("<table class=\"report\" cellpadding=\"0\" cellspacing=\"2\">\n", fp_ou);
		fputs("<tr><th class=\"header_c\"></th>",fp_ou);
		for (i=0 ; i<24 ; i++)
		{
			if (hours[i])
			{
				sprintf(data,_("%02dH"),i);
				fprintf(fp_ou, "<td class=\"header_c\">%s<br>%s</td>\n", data, label );
			}
		}
		fprintf(fp_ou, "<td class=\"header_c\">%s<br>%s</td></tr>\n", _("TOTAL"), label );

		memset(tttime,0,sizeof(tttime));
		for (dayidx=0 ; dayidx<ndaylist ; dayidx++) {
			daynum=daysort[dayidx];
			day=daylist[daynum]%100;
			month=(daylist[daynum]/100)%100;
			year=daylist[daynum]/10000;
			computedate(year,month,day,&t);
			strftime(data,sizeof(data),"%x",&t);
			fprintf(fp_ou, "<tr><td class=\"data\">%s</td>\n", data );
			tt=0;
			for (i=0 ; i<24 ; i++)
			{
				if (!hours[i]) continue;
				ihour=i;
				if (telap[daynum*24+ihour]>0) {
					fprintf(fp_ou, "<td class=\"data\">%s</td>\n",fixtime(telap[daynum*24+ihour]));
					tt+=telap[daynum*24+ihour];
					tttime[ihour]+=telap[daynum*24+ihour];
				} else
					fputs("<td class=\"data\"></td>\n",fp_ou);
			}
			fprintf(fp_ou, "<td class=\"data\">%s</td></tr>\n",fixtime(tt));
		}

		fprintf(fp_ou, "<tr><td class=\"header_l\">%s</td>\n", _("TOTAL") );
		tt=0;
		for (i=0 ; i<24 ; i++)
		{
			if (!hours[i]) continue;
			if (tttime[i]>0)
			{
				fprintf(fp_ou, "<td class=\"header_r\">%s</td>\n",fixtime(tttime[i]));
				tt+=tttime[i];
			}
			else
				fputs("<td class=\"header_r\"></td>\n",fp_ou);
		}
		fprintf(fp_ou, "<td class=\"header_r\">%s</td></tr>\n",fixtime(tt));
		fputs("</table>\n",fp_ou);
#ifdef ENABLE_DOUBLE_CHECK_DATA
		if (tt!=uinfo->elap) {
			debuga(__FILE__,__LINE__,_("Total elapsed time is %"PRIi64" instead of %"PRIi64" in the hourly report of user %s\n"),
						 (int64_t)tt,(int64_t)uinfo->elap,uinfo->label);
			exit(EXIT_FAILURE);
		}
#endif
	}

	write_html_trailer(fp_ou);
	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),arqout,strerror(errno));
		exit(EXIT_FAILURE);
	}
	return;
}
