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

FileListObject UserAgentLog=NULL;

//! Log file where the user agent data are written.
static char UserAgentTempLog[MAXLEN]="";

static struct tm UserAgentStartDate;
static struct tm UserAgentEndDate;

/*!
 * Open the temporary file to store the useragent entries to be
 * reported.
 *
 * \return The file handle. It must be closed when the data have
 * been written.
 */
FILE *UserAgent_Open(void)
{
	FILE *fp_ou=NULL;

	if (UserAgentTempLog[0]) {
		debuga(__FILE__,__LINE__,_("Useragent log already opened\n"));
		exit(EXIT_FAILURE);
	}
	if ((ReportType & REPORT_TYPE_USERAGENT)!=0) {
		format_path(__FILE__, __LINE__, UserAgentTempLog, sizeof(UserAgentTempLog), "%s/squagent.int_unsort", tmp);
		if ((fp_ou=fopen(UserAgentTempLog,"w"))==NULL) {
			debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),UserAgentTempLog,strerror(errno));
			exit(EXIT_FAILURE);
		}
		memset(&UserAgentStartDate,0,sizeof(UserAgentStartDate));
		memset(&UserAgentEndDate,0,sizeof(UserAgentEndDate));
	}
	return(fp_ou);
}

/*!
 * Write a user agent entry into the temporary log.
 *
 * \param fp The file opened by UserAgent_Open().
 * \param Ip The IP address using this agent.
 * \param User The user name.
 * \param Agent The user agent string.
 */
void UserAgent_Write(FILE *fp,const struct tm *Time,const char *Ip,const char *User,const char *Agent)
{
	if (fp) {
		if (useragent_count==0 || compare_date(&UserAgentStartDate,Time)>0)
			memcpy(&UserAgentStartDate,Time,sizeof(UserAgentStartDate));
		if (useragent_count==0 || compare_date(&UserAgentEndDate,Time)<0)
			memcpy(&UserAgentEndDate,Time,sizeof(UserAgentEndDate));
		fprintf(fp,"%s\t%s\t%s\n",Ip,Agent,User);
		useragent_count++;
	}
}

/*!
 * Read the user provided useragent file and create
 * a temporary file with the data to report.
 */
void UserAgent_Readlog(const struct ReadLogDataStruct *ReadFilter)
{
	FileObject *fp_log;
	FILE *fp_ou = NULL;
	char *ptr;
	char ip[80], data[50], agent[MAXLEN], user[MAXLEN];
	int day,month,year;
	char monthname[5];
	int hour,min;
	const char *FileName;
	unsigned long totregsl=0;
	int ndate;
	struct getwordstruct gwarea, gwarea1;
	longline line;
	FileListIterator FIter;
	struct tm logtime;
	int dfrom;
	int duntil;

	fp_ou=UserAgent_Open();

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read useragent log\n"));
		exit(EXIT_FAILURE);
	}
	memset(&logtime,0,sizeof(logtime));
	getperiod_torange(&period,&dfrom,&duntil);

	FIter=FileListIter_Open(UserAgentLog);
	while ((FileName=FileListIter_Next(FIter))!=NULL)
	{
		longline_reset(line);
		if ((fp_log=decomp(FileName))==NULL) {
			debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),FileName,FileObject_GetLastOpenError());
			exit(EXIT_FAILURE);
		}

		if (debug) {
			debuga(__FILE__,__LINE__,_("Reading useragent log \"%s\"\n"),FileName);
		}

		while ((ptr=longline_read(fp_log,line))!=NULL) {
			totregsl++;
			getword_start(&gwarea,ptr);
			if (getword(ip,sizeof(ip),&gwarea,' ')<0 || getword_skip(10,&gwarea,'[')<0 ||
				getword(data,sizeof(data),&gwarea,' ')<0) {
				debuga(__FILE__,__LINE__,_("Invalid record in file \"%s\"\n"),FileName);
				exit(EXIT_FAILURE);
			}
			getword_start(&gwarea1,data);
			if (getword_atoi(&day,&gwarea1,'/')<0 || getword(monthname,sizeof(monthname),&gwarea1,'/')<0 ||
				getword_atoi(&year,&gwarea1,':')<0) {
				debuga(__FILE__,__LINE__,_("Invalid date in file \"%s\"\n"),FileName);
				exit(EXIT_FAILURE);
			}
			month=month2num(monthname)+1;
			if (month>12) {
				debuga(__FILE__,__LINE__,_("Invalid month name \"%s\" found in user agent file \"%s\""),monthname,FileName);
				exit(EXIT_FAILURE);
			}
			if (dfrom!=0 || duntil!=0){
				ndate=year*10000+month*100+day;
				if (ndate<dfrom) continue;
				if (ndate>duntil) break;
			}
			if (getword_atoi(&hour,&gwarea1,':')<0 || getword_atoi(&min,&gwarea1,':')<0) {
				debuga(__FILE__,__LINE__,_("Invalid time in file \"%s\"\n"),FileName);
				exit(EXIT_FAILURE);
			}
			if (ReadFilter->StartTime>=0 || ReadFilter->EndTime>=0)
			{
				int hmr=hour*100+min;
				if (hmr<ReadFilter->StartTime || hmr>=ReadFilter->EndTime)
					continue;
			}
			logtime.tm_year=year-1900;
			logtime.tm_mon=month-1;
			logtime.tm_mday=day;
			if (getword_skip(MAXLEN,&gwarea,'"')<0 || getword(agent,sizeof(agent),&gwarea,'"')<0) {
				debuga(__FILE__,__LINE__,_("Invalid useragent in file \"%s\"\n"),FileName);
				exit(EXIT_FAILURE);
			}

			if (gwarea.current[0]!='\0') {
				if (getword_skip(MAXLEN,&gwarea,' ')<0 || getword(user,sizeof(user),&gwarea,'\n')<0) {
					debuga(__FILE__,__LINE__,_("Invalid record in file \"%s\"\n"),FileName);
					exit(EXIT_FAILURE);
				}
				if (user[0] == '-')
					strcpy(user,ip);
				if (user[0] == '\0')
					strcpy(user,ip);
			} else {
				strcpy(user,ip);
			}

			UserAgent_Write(fp_ou,&logtime,ip,user,agent);
		}

		if (FileObject_Close(fp_log)==EOF) {
			debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),FileName,FileObject_GetLastCloseError());
			exit(EXIT_FAILURE);
		}
	}
	FileListIter_Close(FIter);
	longline_destroy(&line);

	if (debug) {
		debuga(__FILE__,__LINE__,_("   Records read: %ld\n"),totregsl);
	}

	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),UserAgentTempLog,strerror(errno));
		exit(EXIT_FAILURE);
	}
}

void UserAgent(void)
{
	FILE *fp_in = NULL, *fp_ou = NULL, *fp_ht = NULL;
	char buf[MAXLEN];
	char ip[80], agent[MAXLEN], user[MAXLEN];
	char ipbefore[MAXLEN]="";
	char namebefore[MAXLEN]="";
	char tagent[MAXLEN];
	char user_old[MAXLEN]="";
	char agent_old[MAXLEN]="";
	char hfile[MAXLEN];
	char idate[100], fdate[100];
	char tmp2[MAXLEN];
	char tmp3[MAXLEN];
	char csort[MAXLEN];
	int  agentot=0, agentot2=0, agentdif=0, cont=0, nagent;
	int cstatus;
	double perc;
	struct getwordstruct gwarea;

	if (!UserAgentTempLog[0] || useragent_count==0) return;

	format_path(__FILE__, __LINE__, tmp2, sizeof(tmp2), "%s/squagent.int_log", tmp);
	if (debug) {
		debuga(__FILE__,__LINE__,_("Sorting file \"%s\"\n"),tmp2);
	}

	if (snprintf(csort,sizeof(csort),"sort -n -t \"\t\" -k 3,3 -k 2,2 -k 1,1 -o \"%s\" \"%s\"",tmp2,UserAgentTempLog)>=sizeof(csort)) {
		debuga(__FILE__,__LINE__,_("Sort command too long when sorting file \"%s\" to \"%s\"\n"),tmp2,UserAgentTempLog);
		exit(EXIT_FAILURE);
	}
	cstatus=system(csort);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(__FILE__,__LINE__,_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}
	if ((fp_in=fopen(tmp2,"r"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),tmp2,strerror(errno));
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}

	if (!KeepTempLog && unlink(UserAgentTempLog)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),UserAgentTempLog,strerror(errno));
		exit(EXIT_FAILURE);
	}

	format_path(__FILE__, __LINE__, hfile, sizeof(hfile), "%s/useragent.html", outdirname);
	if ((fp_ht=fopen(hfile,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),hfile,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (debug)
		debuga(__FILE__,__LINE__,_("Making Useragent report\n"));

	write_html_header(fp_ht,(IndexTree == INDEX_TREE_DATE) ? 3 : 1,_("Squid Useragent's Report"),HTML_JS_NONE);
	fprintf(fp_ht,"<tr><th class=\"header_c\">%s</th></tr>\n",_("Squid Useragent's Report"));
	strftime(idate,sizeof(idate),"%x",&UserAgentStartDate);
	strftime(fdate,sizeof(fdate),"%x",&UserAgentEndDate);
	fprintf(fp_ht,"<tr><td class=\"header_c\">%s: %s - %s</td></tr>\n",_("Period"),idate,fdate);
	close_html_header(fp_ht);

	fputs("<br><br>\n",fp_ht);

	fputs("<div class=\"report\"><table cellpadding=\"0\" cellspacing=\"0\">\n",fp_ht);
	fputs("<tr><td>&nbsp;</td><td>&nbsp;</td></tr>",fp_ht);

	fprintf(fp_ht,"<tr><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th></tr>\n",_("USERID"),_("AGENT"));

	while (fgets(buf,sizeof(buf),fp_in)!=NULL) {
		getword_start(&gwarea,buf);
		if (getword(ip,sizeof(ip),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid IP address in file \"%s\"\n"),tmp2);
			exit(EXIT_FAILURE);
		}

		if (Ip2Name) {
			if (strcmp(ip,ipbefore) != 0) {
				strcpy(ipbefore,ip);
				ip2name(ip,sizeof(ip));
				strcpy(namebefore,ip);
			} else strcpy(ip,namebefore);
		}

		if (getword(agent,sizeof(agent),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid useragent in file \"%s\"\n"),tmp2);
			exit(EXIT_FAILURE);
		}
		if (getword(user,sizeof(user),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid user ID in file \"%s\"\n"),tmp2);
			exit(EXIT_FAILURE);
		}

		if (strcmp(user,user_old) != 0) {
			fprintf(fp_ht,"<tr><td class=\"data2\">%s</td><td class=\"data2\">",user);
			output_html_string(fp_ht,agent,250);
			fputs("</td></tr>\n",fp_ht);
			strcpy(user_old,user);
			strcpy(agent_old,agent);
		} else if (strcmp(agent,agent_old) != 0) {
			fputs("<tr><td></td><td class=\"data2\">",fp_ht);
			output_html_string(fp_ht,agent,250);
			fputs("</td></tr>\n",fp_ht);
			strcpy(agent_old,agent);
		}
	}

	fputs("</table>\n",fp_ht);
	if (fclose(fp_in)==EOF) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),tmp2,strerror(errno));
		exit(EXIT_FAILURE);
	}

	format_path(__FILE__, __LINE__, tmp3, sizeof(tmp3), "%s/squagent2.int_log", tmp);
	if (snprintf(csort,sizeof(csort),"sort -t \"\t\" -k 2,2 -o \"%s\" \"%s\"",tmp3,tmp2)>=sizeof(csort)) {
		debuga(__FILE__,__LINE__,_("Sort command too long when sorting file \"%s\" to \"%s\"\n"),tmp2,tmp3);
		exit(EXIT_FAILURE);
	}
	cstatus=system(csort);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(__FILE__,__LINE__,_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}
	if ((fp_in=fopen(tmp3,"r"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),tmp3,strerror(errno));
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}

	if (!KeepTempLog && unlink(tmp2)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),tmp2,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((fp_ou=fopen(tmp2,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),tmp2,strerror(errno));
		exit(EXIT_FAILURE);
	}

	agent_old[0]='\0';
	cont=0;

	while (fgets(buf,sizeof(buf),fp_in)!=NULL) {
		getword_start(&gwarea,buf);
		if (getword(ip,sizeof(ip),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid IP address in file \"%s\"\n"),tmp3);
			exit(EXIT_FAILURE);
		}
		if (getword(agent,sizeof(agent),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid useragent in file \"%s\"\n"),tmp3);
			exit(EXIT_FAILURE);
		}

		if (!cont) {
			cont++;
			strcpy(agent_old,agent);
		}

		if (strcmp(agent,agent_old) != 0) {
			agentdif++;
			fprintf(fp_ou,"%06d %s\n",agentot,agent_old);
			strcpy(agent_old,agent);
			agentot2+=agentot;
			agentot=0;
		}
		agentot++;
	}
	agentdif++;
	fprintf(fp_ou,"%06d %s\n",agentot,agent);
	agentot2+=agentot;

	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),tmp2,strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (fclose(fp_in)==EOF) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),tmp3,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!KeepTempLog && unlink(tmp3)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),tmp3,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (snprintf(csort,sizeof(csort),"sort -n -r -k 1,1 -o \"%s\" \"%s\"",tmp3,tmp2)>=sizeof(csort)) {
		debuga(__FILE__,__LINE__,_("Sort command too long when sorting file \"%s\" to \"%s\"\n"),tmp2,tmp3);
		exit(EXIT_FAILURE);
	}
	cstatus=system(csort);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(__FILE__,__LINE__,_("sort command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}
	if ((fp_in=fopen(tmp3,"r"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),tmp3,strerror(errno));
		debuga(__FILE__,__LINE__,_("sort command: %s\n"),csort);
		exit(EXIT_FAILURE);
	}

	if (!KeepTempLog && unlink(tmp2)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),tmp2,strerror(errno));
		exit(EXIT_FAILURE);
	}

	fputs("<br><br>\n",fp_ht);

	fputs("<table cellpadding=\"0\" cellspacing=\"0\">\n",fp_ht);
	fprintf(fp_ht,"<tr><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_c\">%%</th></tr>\n",_("AGENT"),_("TOTAL"));

	perc=0.;
	while(fgets(buf,sizeof(buf),fp_in)!=NULL) {
		fixendofline(buf);
		getword_start(&gwarea,buf);
		if (getword(tagent,sizeof(tagent),&gwarea,' ')<0) {
			debuga(__FILE__,__LINE__,_("Invalid useragent in file \"%s\"\n"),tmp3);
			exit(EXIT_FAILURE);
		}
		nagent=atoi(tagent);
		perc=(agentot2>0) ? nagent * 100. / agentot2 : 0.;

		fputs("<tr><td class=\"data2\">",fp_ht);
		output_html_string(fp_ht,gwarea.current,250);
		fprintf(fp_ht,"</td><td class=\"data\">%d</td><td class=\"data\">%3.2lf</td></tr>\n",nagent,perc);
	}
	if (fclose(fp_in)==EOF) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),tmp3,strerror(errno));
		exit(EXIT_FAILURE);
	}

	fputs("</table></div>\n",fp_ht);
	write_html_trailer(fp_ht);
	if (fclose(fp_ht)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),hfile,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!KeepTempLog && unlink(tmp3)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),tmp3,strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}
