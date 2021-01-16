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

/*
Extract a date range from a squid log file and write it into a separate file.

It can optionally convert the date in human readable format.

The output can be split by day into separate files.

\param arq The squid log file to split.
\param df The date format if the date is to be converted in human readable form. Only the first
character is taken into account. It can be 'e' for European date format or anything else for
US date format.
\param ReadFilter How to filter out log data.
\param convert \c True if the date must be converted into human readable form.
\param splitprefix If not empty, the output file is written in separate files (one for each day) and
the files are named after the day they contain prefixed with the string contained in this variable.
*/
void splitlog(const char *arq, char df, const struct ReadLogDataStruct *ReadFilter, int convert, const char *splitprefix)
{
	FileObject *fp_in;
	FILE *fp_ou=NULL;
	char *buf;
	char data[30];
	char dia[11];
	char output_file[MAXLEN];
	time_t tt;
	time_t min_tt;
	time_t max_tt=0;
	int idata=0;
	int autosplit=0;
	int output_prefix_len=0;
	int prev_year=0, prev_month=0, prev_day=0;
	struct tm *t;
	struct getwordstruct gwarea;
	longline line;

	if (splitprefix[0]!='\0') {
		// '/' + '-YYYY-mm-dd' + '\0' == 13
		output_prefix_len=snprintf(output_file,sizeof(output_file)-12,"%s%s",outdir,splitprefix);
		if (output_prefix_len>=sizeof(output_file)-12) {
			debuga(__FILE__,__LINE__,_("Path too long: "));
			debuga_more("%s%s-YYYY-mm-dd\n",outdir,splitprefix);
			exit(EXIT_FAILURE);
		}
		autosplit=1;
	} else {
		fp_ou=stdout;
	}

	if (arq[0] == '\0')
		arq="/var/log/squid/access.log";

	if ((fp_in=decomp(arq))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),arq,FileObject_GetLastOpenError());
		exit(EXIT_FAILURE);
	}

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),arq);
		exit(EXIT_FAILURE);
	}
	time(&min_tt);

	while((buf=longline_read(fp_in,line))!=NULL) {
		getword_start(&gwarea,buf);
		if (getword(data,sizeof(data),&gwarea,' ')<0) {
			debuga(__FILE__,__LINE__,_("Invalid date in file \"%s\"\n"),arq);
			exit(EXIT_FAILURE);
		}
		tt=atoi(data);
		t=localtime(&tt);

		if (ReadFilter->DateRange[0])
		{
			idata=(t->tm_year+1900)*10000+(t->tm_mon+1)*100+t->tm_mday;
			if (idata<ReadFilter->StartDate || idata>ReadFilter->EndDate)
				continue;
		}
		if (ReadFilter->StartTime>=0 || ReadFilter->EndTime>=0)
		{
			int hmr=t->tm_hour*100+t->tm_min;
			if (hmr<ReadFilter->StartTime || hmr>=ReadFilter->EndTime)
				continue;
		}

		if (autosplit && (prev_year!=t->tm_year || prev_month!=t->tm_mon || prev_day!=t->tm_mday)) {
			prev_year=t->tm_year;
			prev_month=t->tm_mon;
			prev_day=t->tm_mday;
			if (fp_ou && fclose(fp_ou)==EOF) {
				debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),output_file,strerror(errno));
				exit(EXIT_FAILURE);
			}
			strftime(output_file+output_prefix_len, sizeof(output_file)-output_prefix_len, "-%Y-%m-%d", t);
			/*
			The line must be added to a file we have already created. The file must be created if the date
			is seen for the first time. The idea is to create the files from scratch if the split is started
			a second time.
			*/
			if ((fp_ou=MY_FOPEN(output_file,(tt>=min_tt && tt<=max_tt) ? "a" : "w"))==NULL) {
				debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),output_file,strerror(errno));
				exit(EXIT_FAILURE);
			}
			if (tt<min_tt) min_tt=tt;
			if (tt>max_tt) max_tt=tt;
		}

		if (!convert) {
			fprintf(fp_ou,"%s %s\n",data,gwarea.current);
		} else {
			if (df=='e')
				strftime(dia, sizeof(dia), "%d/%m/%Y", t);
			else
				strftime(dia, sizeof(dia), "%m/%d/%Y", t);

			fprintf(fp_ou,"%s %02d:%02d:%02d %s\n",dia,t->tm_hour,t->tm_min,t->tm_sec,gwarea.current);
		}
	}

	longline_destroy(&line);
	if (FileObject_Close(fp_in)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),arq,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}
	if (autosplit && fp_ou) {
		if (fclose(fp_ou)==EOF) {
			debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),output_file,strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}
