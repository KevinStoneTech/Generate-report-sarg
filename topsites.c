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

#ifdef ENABLE_DOUBLE_CHECK_DATA
extern struct globalstatstruct globstat;
#endif

void topsites(void)
{
	FileObject *fp_in;
	FILE *fp_ou;

	char *buf;
	char *url;
	char *ourl=NULL;
	char csort[4096];
	char general[MAXLEN];
	char general2[MAXLEN];
	char general3[MAXLEN];
	char sites[MAXLEN];
	char report[MAXLEN];
	char ouser[MAX_USER_LEN]="";
	const char *sortf;
	const char *sortt;
	long long int nacc;
	long long int nbytes;
	long long int ntime;
	long long int tnacc=0;
	long long int tnbytes=0;
	long long int tntime=0;
	long long int twork1=0, twork2=0, twork3=0;
#ifdef ENABLE_DOUBLE_CHECK_DATA
	long long int ttnacc=0;
	long long int ttnbytes=0;
	long long int ttntime=0;
#endif
	int nusers=0;
	int regs=0;
	int cstatus;
	int url_len;
	int ourl_size=0;
	struct getwordstruct gwarea;
	longline line;
	struct generalitemstruct item;

	if (Privacy) {
		if (debugz>=LogLevel_Process) debugaz(__FILE__,__LINE__,_("Top sites report not produced because privacy option is on\n"));
		return;
	}
	if (debugz>=LogLevel_Process)
		debuga(__FILE__,__LINE__,_("Creating top sites report...\n"));

	format_path(__FILE__, __LINE__, general, sizeof(general), "%s/sarg-general", outdirname);
	format_path(__FILE__, __LINE__, sites, sizeof(sites) ,"%s/sarg-sites",outdirname);
	format_path(__FILE__, __LINE__, general2, sizeof(general2), "%s/sarg-general2", outdirname);
	format_path(__FILE__, __LINE__, general3, sizeof(general3), "%s/sarg-general3", outdirname);

	format_path(__FILE__, __LINE__, report, sizeof(report), "%s/topsites.html", outdirname);

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

	if ((fp_ou=fopen(general3,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),general3,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),general2);
		exit(EXIT_FAILURE);
	}

	while((buf=longline_read(fp_in,line))!=NULL) {
		ger_read(buf,&item,general2);
		if (item.total) continue;

		if (!regs) {
			url_len=strlen(item.url);
			if (!ourl || url_len>=ourl_size) {
				ourl_size=url_len+1;
				ourl=realloc(ourl,ourl_size);
				if (!ourl) {
					debuga(__FILE__,__LINE__,_("Not enough memory to store the url\n"));
					exit(EXIT_FAILURE);
				}
			}
			strcpy(ourl,item.url);
			regs++;
		}

		if (strcmp(item.url,ourl) != 0) {
			/*
			This complicated printf is due to Microsoft's inability to comply with any standard. Msvcrt is unable
			to print a long long int unless it is exactly 64-bits long.
			*/
			fprintf(fp_ou,"%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%d\t%s\n",(uint64_t)tnacc,(uint64_t)tnbytes,(uint64_t)tntime,nusers,ourl);
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
			strcpy(ouser,item.user);
			tnacc=0;
			tnbytes=0;
			tntime=0;
			nusers=1;
		} else if (strcmp(item.user,ouser)!=0) {
			strcpy(ouser,item.user);
			nusers++;
		}

		tnacc+=item.nacc;
		tnbytes+=item.nbytes;
		tntime+=item.nelap;
#ifdef ENABLE_DOUBLE_CHECK_DATA
		ttnacc+=item.nacc;
		ttnbytes+=item.nbytes;
		ttntime+=item.nelap;
#endif
	}
	if (FileObject_Close(fp_in)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),general2,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}
	longline_destroy(&line);

	if (ourl) {
		/*
		This complicated printf is due to Microsoft's inability to comply with any standard. Msvcrt is unable
		to print a long long int unless it is exactly 64-bits long.
		*/
		fprintf(fp_ou,"%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%d\t%s\n",(uint64_t)tnacc,(uint64_t)tnbytes,(uint64_t)tntime,nusers,ourl);
		free(ourl);
	}

	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),general3,strerror(errno));
		exit(EXIT_FAILURE);
	}

#ifdef ENABLE_DOUBLE_CHECK_DATA
	if (ttnacc!=globstat.nacc || ttnbytes!=globstat.nbytes || ttntime!=globstat.elap) {
		debuga(__FILE__,__LINE__,_("Total statistics mismatch when reading \"%s\" to produce the top sites\n"),general2);
		exit(EXIT_FAILURE);
	}
#endif

	if (!KeepTempLog && unlink(general2)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),general2,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((TopsitesSort & TOPSITE_SORT_CONNECT) != 0) {
		sortf="-k 1,1 -k 2,2";
	} else if ((TopsitesSort & TOPSITE_SORT_BYTES) != 0) {
		sortf="-k 2,2 -k 1,1";
	} else if ((TopsitesSort & TOPSITE_SORT_TIME) != 0) {
		sortf="-k 3,3";
	} else if ((TopsitesSort & TOPSITE_SORT_USER) != 0) {
		sortf="-k 4,4 -k 1,1 -k 2,2";
	} else {
		sortf="-k 2,2 -k 1,1"; //default is BYTES
	}
	if ((TopsitesSort & TOPSITE_SORT_REVERSE) != 0) {
		sortt="-r";
	} else {
		sortt="";
	}

	if (snprintf(csort,sizeof(csort),"sort -t \"\t\" %s -n %s -o \"%s\" \"%s\"",sortt,sortf,sites,general3)>=sizeof(csort)) {
		debuga(__FILE__,__LINE__,_("Sort command too long when sorting file \"%s\" to \"%s\"\n"),general3,sites);
		exit(EXIT_FAILURE);
	}
	cstatus=system(csort);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(__FILE__,__LINE__,_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}
	if ((fp_in=FileObject_Open(sites))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),sites,FileObject_GetLastOpenError());
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}

	if (!KeepTempLog && unlink(general3)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),general3,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((fp_ou=fopen(report,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),report,strerror(errno));
		exit(EXIT_FAILURE);
	}

	write_html_header(fp_ou,(IndexTree == INDEX_TREE_DATE) ? 3 : 1,_("Top sites"),HTML_JS_SORTTABLE);
	fputs("<tr><td class=\"header_c\">",fp_ou);
	fprintf(fp_ou,_("Period: %s"),period.html);
	fputs("</td></tr>\n",fp_ou);
	fputs("<tr><th class=\"header_c\">",fp_ou);
	fprintf(fp_ou,_("Top %d sites"),TopSitesNum);
	fputs("</th></tr>\n",fp_ou);
	close_html_header(fp_ou);

	fputs("<div class=\"report\"><table cellpadding=\"1\" cellspacing=\"2\"",fp_ou);
	if (SortTableJs[0]) fputs(" class=\"sortable\"",fp_ou);
	fputs(">\n",fp_ou);
	fprintf(fp_ou,"<thead><tr><th class=\"header_l\">%s</th><th class=\"header_l",
	/* TRANSLATORS: This is a column header showing the position of the entry in the sorted list. */
	_("NUM"));
	if (SortTableJs[0]) fputs(" sorttable_alpha",fp_ou);
	fprintf(fp_ou,"\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th></tr></thead>\n",
	/* TRANSLATORS: This is a column header showing the URL of the visited sites. */
	_("ACCESSED SITE"),
	/* TRANSLATORS: This is a column header showing the number of connections to a visited site. */
	_("CONNECT"),
	/* TRANSLATORS: This is a column header showing the number of transfered bytes. */
	_("BYTES"),
	/* TRANSLATORS: This is a column header showing the time spent by the proxy processing the requests. */
	pgettext("duration","TIME"),
	/* TRANSLATORS: This is a column header showing the number of users who visited a sites. */
	_("USERS"));

	regs=0;
	ntopsites = 0;

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),sites);
		exit(EXIT_FAILURE);
	}

	while(regs<TopSitesNum && (buf=longline_read(fp_in,line))!=NULL) {
		getword_start(&gwarea,buf);
		if (getword_atoll(&nacc,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid record in file \"%s\"\n"),sites);
			exit(EXIT_FAILURE);
		}
		if (nacc == 0) continue;
		if (getword_atoll(&nbytes,&gwarea,'\t')<0 || getword_atoll(&ntime,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid record in file \"%s\"\n"),sites);
			exit(EXIT_FAILURE);
		}
		if (getword_atoi(&nusers,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid number of users in file \"%s\"\n"),sites);
			exit(EXIT_FAILURE);
		}
		if (getword_ptr(buf,&url,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid url in file \"%s\"\n"),sites);
			exit(EXIT_FAILURE);
		}

		twork1=nacc;
		twork2=nbytes;
		twork3=ntime;

		fprintf(fp_ou,"<tr><td class=\"data\">%d</td><td class=\"data2\">",++regs);

		if (BlockIt[0] != '\0' && url[0]!=ALIAS_PREFIX) {
			fprintf(fp_ou,"<a href=\"%s%s?url=\"",wwwDocumentRoot,BlockIt);
			output_html_url(fp_ou,url);
			fputs("\"><img src=\"../images/sarg-squidguard-block.png\"></a>&nbsp;",fp_ou);
		}

		output_html_link(fp_ou,url,100);
		fputs("</td><td class=\"data\"",fp_ou);
		if (SortTableJs[0]) fprintf(fp_ou," sorttable_customkey=\"%"PRId64"\"",(uint64_t)twork1);
		fprintf(fp_ou,">%s</td>",fixnum(twork1,1));
		fputs("<td class=\"data\"",fp_ou);
		if (SortTableJs[0]) fprintf(fp_ou," sorttable_customkey=\"%"PRId64"\"",(uint64_t)twork2);
		fprintf(fp_ou,">%s</td>",fixnum(twork2,1));
		fputs("<td class=\"data\"",fp_ou);
		if (SortTableJs[0]) fprintf(fp_ou," sorttable_customkey=\"%"PRId64"\"",(uint64_t)twork3);
		fprintf(fp_ou,">%s</td>",fixtime(twork3));
		fputs("<td class=\"data\"",fp_ou);
		if (SortTableJs[0]) fprintf(fp_ou," sorttable_customkey=\"%d\"",nusers);
		fprintf(fp_ou,">%s</td></tr>\n",fixnum(nusers,1));
	}
	if (FileObject_Close(fp_in)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),sites,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}
	longline_destroy(&line);

	fputs("</table></div>\n",fp_ou);
	write_html_trailer(fp_ou);
	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),report,strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}
