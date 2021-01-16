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

void convlog(const char *arq, char df, const struct ReadLogDataStruct *ReadFilter)
{
	FileObject *fp_in;
	char *buf;
	char data[30];
	char dia[11];
	time_t tt;
	int idata=0;
	struct tm *t;
	struct getwordstruct gwarea;
	longline line;

	if (arq[0] == '\0')
		arq="/var/log/squid/access.log";

	if ((fp_in=FileObject_Open(arq))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),arq,FileObject_GetLastOpenError());
		exit(EXIT_FAILURE);
	}

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),arq);
		exit(EXIT_FAILURE);
	}

	while((buf=longline_read(fp_in,line))!=NULL) {
		getword_start(&gwarea,buf);
		if (getword(data,sizeof(data),&gwarea,' ')<0) {
			debuga(__FILE__,__LINE__,_("Invalid record in file \"%s\"\n"),arq);
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

		if (df=='e')
			strftime(dia, sizeof(dia), "%d/%m/%Y", t);
		else if (df=='u')
			strftime(dia, sizeof(dia), "%m/%d/%Y", t);
		else //if (df=='w')
			strftime(dia, sizeof(dia), "%Y.%U", t);

		printf("%s %02d:%02d:%02d %s\n",dia,t->tm_hour,t->tm_min,t->tm_sec,gwarea.current);
	}

	longline_destroy(&line);
	if (FileObject_Close(fp_in)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),arq,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}
}
