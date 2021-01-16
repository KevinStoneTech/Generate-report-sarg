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

void dansguardian_log(const struct ReadLogDataStruct *ReadFilter)
{
	FILE *fp_in = NULL, *fp_ou = NULL, *fp_guard = NULL;
	char buf[MAXLEN];
	char guard_in[MAXLEN];
	char guard_ou[MAXLEN];
	char loglocation[MAXLEN] = "/var/log/dansguardian/access.log";
	int year, mon, day;
	int hour,min,sec;
	char user[MAXLEN], code1[255], code2[255];
	char ip[45];
	char *url;
	char tmp6[MAXLEN];
	int  idata=0;
	int cstatus;
	int dfrom, duntil;
	struct getwordstruct gwarea;

	getperiod_torange(&period,&dfrom,&duntil);

	format_path(__FILE__, __LINE__, guard_in, sizeof(guard_in), "%s/dansguardian.int_unsort", tmp);
	format_path(__FILE__, __LINE__, guard_ou, sizeof(guard_ou), "%s/dansguardian.int_log", tmp);

	if (access(DansGuardianConf, R_OK) != 0) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),DansGuardianConf,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((fp_guard=fopen(DansGuardianConf,"r"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),DansGuardianConf,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((fp_ou=MY_FOPEN(guard_in,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),guard_in,strerror(errno));
		exit(EXIT_FAILURE);
	}

	while(fgets(buf,sizeof(buf),fp_guard)!=NULL) {
		fixendofline(buf);
		if (buf[0]=='#')
			continue;
		if (strstr(buf,"loglocation ") != 0) {
			getword_start(&gwarea,buf);
			if (getword_skip(MAXLEN,&gwarea,'\'')<0 || getword(loglocation,sizeof(loglocation),&gwarea,'\'')<0) {
				debuga(__FILE__,__LINE__,_("Invalid record in file \"%s\"\n"),DansGuardianConf);
				exit(EXIT_FAILURE);
			}
			if (debug) debuga(__FILE__,__LINE__,_("Using the dansguardian log file \"%s\" found in your configuration file \"%s\"\n"),
				loglocation,DansGuardianConf);
			break;
		}
	}
	if (fclose(fp_guard)==EOF) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),DansGuardianConf,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (debug)
		debuga(__FILE__,__LINE__,_("Reading DansGuardian log file \"%s\"\n"),loglocation);

	if ((fp_in=MY_FOPEN(loglocation,"r"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),loglocation,strerror(errno));
		exit(EXIT_FAILURE);
	}

	while(fgets(buf,sizeof(buf),fp_in) != NULL) {
		if (strstr(buf," *DENIED* ") == 0)
			continue;
		getword_start(&gwarea,buf);
		if (getword_atoi(&year,&gwarea,'.')<0 || getword_atoi(&mon,&gwarea,'.')<0 ||
		    getword_atoi(&day,&gwarea,' ')<0) {
			debuga(__FILE__,__LINE__,_("Invalid date in file \"%s\"\n"),loglocation);
			exit(EXIT_FAILURE);
		}
		if (getword_atoi(&hour,&gwarea,':')<0 || getword_atoi(&min,&gwarea,':')<0 || getword_atoi(&sec,&gwarea,' ')<0) {
			debuga(__FILE__,__LINE__,_("Invalid time in file \"%s\"\n"),loglocation);
			exit(EXIT_FAILURE);
		}
		if (getword(user,sizeof(user),&gwarea,' ')<0) {
			debuga(__FILE__,__LINE__,_("Invalid user in file \"%s\"\n"),loglocation);
			exit(EXIT_FAILURE);
		}
		if (getword(ip,sizeof(ip),&gwarea,' ')<0) {
			debuga(__FILE__,__LINE__,_("Invalid IP address in file \"%s\"\n"),loglocation);
			exit(EXIT_FAILURE);
		}
		if (getword_skip(MAXLEN,&gwarea,'/')<0 || getword_skip(MAXLEN,&gwarea,'/')<0) {
			debuga(__FILE__,__LINE__,_("Invalid record in file \"%s\"\n"),loglocation);
			exit(EXIT_FAILURE);
		}
		if (getword_ptr(buf,&url,&gwarea,' ')<0) {
			debuga(__FILE__,__LINE__,_("Invalid url in file \"%s\"\n"),loglocation);
			exit(EXIT_FAILURE);
		}
		if (getword_skip(255,&gwarea,' ')<0 ||
		    getword(code1,sizeof(code1),&gwarea,' ')<0 || getword(code2,sizeof(code2),&gwarea,' ')<0) {
			debuga(__FILE__,__LINE__,_("Invalid record in file \"%s\"\n"),loglocation);
			exit(EXIT_FAILURE);
		}
		idata = year*10000+mon*100+day;

		if (DansguardianFilterOutDate)
		{
			if (idata < dfrom || idata > duntil)
				continue;
			if (ReadFilter->StartTime>=0 || ReadFilter->EndTime>=0)
			{
				int hmr=hour*100+min;
				if (hmr<ReadFilter->StartTime || hmr>=ReadFilter->EndTime)
					continue;
			}
		}

		if (strcmp(user,"-") == 0) {
			strcpy(user,ip);
			ip[0]='\0';
		}
		fprintf(fp_ou,"%s\t%d\t%02d:%02d:%02d\t%s\t%s\t%s\t%s\n",user,idata,hour,min,sec,ip,url,code1,code2);
		dansguardian_count++;
	}

	if (fclose(fp_in)==EOF) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),loglocation,strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),guard_in,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (debug)
		debuga(__FILE__,__LINE__,_("Sorting file \"%s\"\n"),guard_ou);

	if (snprintf(tmp6, sizeof(tmp6), "sort -t \"\t\" -k 1,1 -k 2,2 -k 4,4 \"%s\" -o \"%s\"", guard_in, guard_ou) >= sizeof(tmp6)) {
		debuga(__FILE__,__LINE__,_("Sort command too long when sorting file \"%s\" to \"%s\"\n"), guard_in, guard_ou);
		debuga_more("sort -t \"\t\" -k 1,1 -k 2,2 -k 4,4 \"%s\" -o \"%s\"", guard_in, guard_ou);
		exit(EXIT_FAILURE);
	}
	cstatus=system(tmp6);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(__FILE__,__LINE__,_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),tmp6);
		exit(EXIT_FAILURE);
	}
	if (!KeepTempLog && unlink(guard_in)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),guard_in,strerror(errno));
		exit(EXIT_FAILURE);
	}
}
