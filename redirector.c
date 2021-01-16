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

static char **files_done = NULL;
static int nfiles_done = 0;

//! The number of invalid lines found in the redirector report.
static int RedirectorErrors=0;
//! The file containing the sorted entries.
static char redirector_sorted[MAXLEN]="";

extern char StripUserSuffix[MAX_USER_LEN];
extern int StripSuffixLen;

static void parse_log(FILE *fp_ou,char *buf,int dfrom,int duntil,const struct ReadLogDataStruct *ReadFilter)
{
	char leks[5], sep[2], res[MAXLEN];
	char hour[15];
	char source[128], list[128];
	char full_url[MAX_URL_LEN];
	const char *url;
	char UserBuf[MAX_USER_LEN];
	const char *user;
	char ip[45];
	char userlabel[MAX_USER_LEN];
	char IpBuf[MAX_USER_LEN];
	long long int lmon, lday, lyear;
	int mon, day, year;
	int  idata=0;
	bool id_is_ip;
	struct getwordstruct gwarea;
	struct getwordstruct gwarea1;
	struct userinfostruct *uinfo;
	enum UserProcessError PUser;

	getword_start(&gwarea,buf);
	if (RedirectorLogFormat[0] != '\0') {
		getword_start(&gwarea1,RedirectorLogFormat);
		leks[0]='\0';
		if (getword(leks,sizeof(leks),&gwarea1,'#')<0) {
			debuga(__FILE__,__LINE__,_("Invalid \"redirector_log_format\" option in your sarg.conf (too many characters before first tag)\n"));
			exit(EXIT_FAILURE);
		}
		year=0;
		mon=0;
		day=0;
		hour[0]='\0';
		source[0]='\0';
		list[0]='\0';
		ip[0]='\0';
		UserBuf[0]='\0';
		full_url[0]='\0';
		while(strcmp(leks,"end") != 0) {
			if (getword(leks,sizeof(leks),&gwarea1,'#')<0) {
				debuga(__FILE__,__LINE__,_("Invalid \"redirector_log_format\" option in your sarg.conf (missing # at end of tag)\n"));
				exit(EXIT_FAILURE);
			}
			if (getword(sep,sizeof(sep),&gwarea1,'#')<0) {
				debuga(__FILE__,__LINE__,_("Invalid \"redirector_log_format\" option in your sarg.conf (too many characters in column separator)\n"));
				exit(EXIT_FAILURE);
			}
			if (strcmp(leks,"end") != 0) {
				if (getword_limit(res,sizeof(res),&gwarea,sep[0])<0) {
					debuga(__FILE__,__LINE__,_("Parsing of tag \"%s\" in redirector log \"%s\" returned no result\n"),leks,wentp);
					RedirectorErrors++;
					return;
				}
				if (strcmp(leks,"year") == 0) {
					year=atoi(res);
				} else if (strcmp(leks,"mon") == 0) {
					mon=atoi(res);
				} else if (strcmp(leks,"day") == 0) {
					day=atoi(res);
				} else if (strcmp(leks,"hour") == 0) {
					if (strlen(res)>=sizeof(hour)) {
						debuga(__FILE__,__LINE__,_("Hour string too long in redirector log file \"%s\"\n"),wentp);
						RedirectorErrors++;
						return;
					}
					strcpy(hour,res);
				} else if (strcmp(leks,"source") == 0) {
					if (strlen(res)>=sizeof(source)) {
						debuga(__FILE__,__LINE__,_("Banning source name too long in redirector log file \"%s\"\n"),wentp);
						RedirectorErrors++;
						return;
					}
					strcpy(source,res);
				} else if (strcmp(leks,"list") == 0) {
					if (strlen(res)>=sizeof(list)) {
						debuga(__FILE__,__LINE__,_("Banning list name too long in redirector log file \"%s\"\n"),wentp);
						RedirectorErrors++;
						return;
					}
					strcpy(list,res);
				} else if (strcmp(leks,"ip") == 0) {
					if (strlen(res)>=sizeof(ip)) {
						debuga(__FILE__,__LINE__,_("IP address too long in redirector log file \"%s\"\n"),wentp);
						RedirectorErrors++;
						return;
					}
					strcpy(ip,res);
				} else if (strcmp(leks,"user") == 0) {
					if (strlen(res)>=sizeof(UserBuf)) {
						debuga(__FILE__,__LINE__,_("User ID too long in redirector log file \"%s\"\n"),wentp);
						RedirectorErrors++;
						return;
					}
					strcpy(UserBuf,res);
				} else if (strcmp(leks,"url") == 0) {
					/*
					 * Don't worry about the url being truncated as we only keep the host name
					 * any way...
					 */
					safe_strcpy(full_url,res,sizeof(full_url));
				}
			}
		}
	} else {
		if (getword_atoll(&lyear,&gwarea,'-')<0 || getword_atoll(&lmon,&gwarea,'-')<0 ||
				getword_atoll(&lday,&gwarea,' ')<0) {
			debuga(__FILE__,__LINE__,_("Invalid date in file \"%s\"\n"),wentp);
			RedirectorErrors++;
			return;
		}
		year=(int)lyear;
		mon=(int)lmon;
		day=(int)lday;
		if (getword(hour,sizeof(hour),&gwarea,' ')<0) {
			debuga(__FILE__,__LINE__,_("Invalid time in file \"%s\"\n"),wentp);
			RedirectorErrors++;
			return;
		}
		if (getword_skip(MAXLEN,&gwarea,'(')<0 || getword(source,sizeof(source),&gwarea,'/')<0) {
			debuga(__FILE__,__LINE__,_("Invalid redirected source in file \"%s\"\n"),wentp);
			RedirectorErrors++;
			return;
		}
		if (getword(list,sizeof(list),&gwarea,'/')<0) {
			debuga(__FILE__,__LINE__,_("Invalid redirected list in file \"%s\"\n"),wentp);
			RedirectorErrors++;
			return;
		}
		if (getword_skip(MAXLEN,&gwarea,' ')<0 || getword_limit(full_url,sizeof(full_url),&gwarea,' ')<0) {
			debuga(__FILE__,__LINE__,_("Invalid url in file \"%s\"\n"),wentp);
			RedirectorErrors++;
			return;
		}
		if (getword(ip,sizeof(ip),&gwarea,'/')<0) {
			debuga(__FILE__,__LINE__,_("Invalid source IP in file \"%s\"\n"),wentp);
			RedirectorErrors++;
			return;
		}
		if (getword_skip(MAXLEN,&gwarea,' ')<0 || getword(UserBuf,sizeof(UserBuf),&gwarea,' ')<0) {
			debuga(__FILE__,__LINE__,_("Invalid user in file \"%s\"\n"),wentp);
			RedirectorErrors++;
			return;
		}
	}
	url=process_url(full_url,false);

	//sprintf(warea,"%04d%02d%02d",year,mon,day);

	if (RedirectorFilterOutDate)
	{
		idata = year*10000+mon*100+day;
		if (idata<dfrom || idata>duntil)
			return;
		if (ReadFilter->StartTime>=0 && ReadFilter->EndTime>=0)
		{
			int h,m,hmr;

			if (sscanf(hour,"%d:%d",&h,&m)!=2)
			{
				debuga(__FILE__,__LINE__,_("Can't parse time \"%s\" found in \"%s\"\n"),hour,wentp);
				RedirectorErrors++;
				return;
			}
			hmr=h*100+m;
			if (hmr<ReadFilter->StartTime || hmr>=ReadFilter->EndTime)
				return;
		}
	}

	user=UserBuf;
	PUser=process_user(&user,ip,&id_is_ip);
	if (PUser!=USERERR_NoError) return;

	uinfo=userinfo_find_from_id(user);
	if (!uinfo) {
		uinfo=userinfo_create(user,(id_is_ip) ? NULL : ip);
		uinfo->no_report=true;
		if (Ip2Name && id_is_ip) {
			strcpy(IpBuf,user);
			ip2name(IpBuf,sizeof(IpBuf));
			user=IpBuf;
		}
		user_find(userlabel,MAX_USER_LEN, user);
		userinfo_label(uinfo,userlabel);
	}
	fprintf(fp_ou,"%s\t%04d%02d%02d\t%s\t%s\t%s\t",uinfo->id,year,mon,day,hour,ip,url);
	if (source[0] && list[0])
		fprintf(fp_ou,"%s/%s\n",source,list);
	else if (source[0])
		fprintf(fp_ou,"%s\n",source);
	else
		fprintf(fp_ou,"%s\n",list);
	redirector_count++;
}

static void read_log(const char *wentp, FILE *fp_ou,int dfrom,int duntil,const struct ReadLogDataStruct *ReadFilter)
{
	FileObject *fp_in = NULL;
	char *buf;
	int  i;
	longline line;

	if (debug) {
		debuga(__FILE__,__LINE__,_("Reading redirector log file \"%s\"\n"),wentp);
	}

	/* With squidGuard, you can log groups in only one log file.
		We must parse each log files only one time.  Example :
		dest porn {
			domainlist porn/domains
			urllist    porn/urls
			log file1.log
		}
		dest aggressive {
			domainlist aggressive/domains
			urllist    aggressive/urls
			log file2.log
		}
		dest audio-video {
			domainlist audio-video/domains
			urllist    audio-video/urls
			log file1.log
		}
	*/
	for (i=0; i<nfiles_done; i++)
		if (!strcmp(wentp, files_done[i])) return;

	nfiles_done++;
	files_done = realloc(files_done, nfiles_done*sizeof(char *));
	if (!files_done) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store the name of the new redirector log to be read - %s\n"),strerror(errno));
		exit(EXIT_FAILURE);
	}
	files_done[nfiles_done-1] = strdup(wentp);
	if (!files_done[nfiles_done-1]) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store the name of the new redirector log to be read - %s\n"),strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((fp_in=decomp(wentp))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),wentp,FileObject_GetLastOpenError());
		exit(EXIT_FAILURE);
	}

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),wentp);
		exit(EXIT_FAILURE);
	}

	while ((buf=longline_read(fp_in,line)) != NULL) {
		parse_log(fp_ou,buf,dfrom,duntil,ReadFilter);
	}
	if (FileObject_Close(fp_in)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),wentp,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}
	longline_destroy(&line);
	return;
}


void redirector_log(const struct ReadLogDataStruct *ReadFilter)
{
	FILE *fp_ou = NULL, *fp_guard = NULL;
	char buf[MAXLEN];
	char guard_in[MAXLEN];
	char logdir[MAXLEN];
	char user[MAXLEN];
	char tmp6[MAXLEN];
	int i;
	int  y;
	int cstatus;
	int dfrom, duntil;
	char *str;
	char *str2;

	str2 = user;

	if (SquidGuardConf[0] == '\0' && NRedirectorLogs == 0) {
		if (debugz>=LogLevel_Process) debugaz(__FILE__,__LINE__,_("No redirector logs provided to produce that kind of report\n"));
		return;
	}

	format_path(__FILE__, __LINE__, guard_in, sizeof(guard_in), "%s/redirector.int_unsort", tmp);
	if ((fp_ou=fopen(guard_in,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),guard_in,strerror(errno));
		exit(EXIT_FAILURE);
	}

	getperiod_torange(&period,&dfrom,&duntil);

	if (NRedirectorLogs>0) {
		for (i=0 ; i<NRedirectorLogs ; i++)
			read_log(RedirectorLogs[i],fp_ou,dfrom,duntil,ReadFilter);
	} else {
		if (access(SquidGuardConf, R_OK) != 0) {
			debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),SquidGuardConf,strerror(errno));
			exit(EXIT_FAILURE);
		}

		if ((fp_guard=fopen(SquidGuardConf,"r"))==NULL) {
			debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),SquidGuardConf,strerror(errno));
			exit(EXIT_FAILURE);
		}

		logdir[0]=0;
		while(fgets(buf,sizeof(buf),fp_guard)!=NULL) {
			fixendofline(buf);
			if ((str=get_param_value("logdir",buf))!=NULL) {
				/*
				We want to tolerate spaces inside the directory name but we must also
				remove the trailing spaces left by the editor after the directory name.
				This should not be a problem as nobody use a file name with trailing spaces.
				*/
				for (y=strlen(str)-1 ; y>=0 && (unsigned char)str[y]<=' ' ; y--);
				if (y>=sizeof(logdir)-1) y=sizeof(logdir)-2;
				logdir[y+1] = '\0';
				while (y>=0) {
					logdir[y] = str[y];
					y--;
				}
			} else if ((str=get_param_value("log",buf))!=NULL) {
				if ((str2=get_param_value("anonymous",str))!=NULL)
					str=str2;

				/*
				If logdir is defined, we prepend it to the log file name, otherwise, we assume
				the log directive provides an absolute file name to the log file. Therefore,
				we don't need to add an additionnal / at the beginning of the log file name.
				*/
				y=(logdir[0]) ? format_path(__FILE__, __LINE__, wentp, sizeof(wentp),"%s/", logdir) : 0;
				/*
				Spaces are allowed in the name of the log file. The file name ends at the first #
				because it is assumed it is an end of line comment. Any space before the # is then
				removed. Any control character (i.e. a character with a code lower than 32) ends
				the file name. That includes the terminating zero.
				*/
				while((unsigned char)*str>=' ' && *str!='#' && y<sizeof(wentp)-1)
					wentp[y++]=*str++;
				if (*str=='#') {
					str--;
					while(*str==' ' && y>0) {
						str--;
						y--;
					}
				}
				wentp[y]=0;
				read_log(wentp,fp_ou,dfrom,duntil,ReadFilter);
			}
		}
		if (fclose(fp_guard)==EOF) {
			debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),SquidGuardConf,strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (fp_ou && fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),guard_in,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (files_done) {
		for (y=0; y<nfiles_done; y++)
			if (files_done[y]) free(files_done[y]);
		free(files_done);
	}

	if (redirector_count) {
		format_path(__FILE__,__LINE__, redirector_sorted, sizeof(redirector_sorted), "%s/redirector.int_log", tmp);
		if (debug) {
			debuga(__FILE__,__LINE__,_("Sorting file \"%s\"\n"),redirector_sorted);
		}

		if (snprintf(tmp6,sizeof(tmp6),"sort -t \"\t\" -k 1,1 -k 2,2 -k 4,4 \"%s\" -o \"%s\"",guard_in, redirector_sorted)>=sizeof(tmp6)) {
			debuga(__FILE__,__LINE__,_("Sort command too long when sorting file \"%s\" to \"%s\"\n"),guard_in,redirector_sorted);
			exit(EXIT_FAILURE);
		}
		cstatus=system(tmp6);
		if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
			debuga(__FILE__,__LINE__,_("sort command return status %d\n"),WEXITSTATUS(cstatus));
			debuga(__FILE__,__LINE__,_("sort command: %s\n"),tmp6);
			exit(EXIT_FAILURE);
		}
	}

	if (!KeepTempLog && unlink(guard_in)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),guard_in,strerror(errno));
		exit(EXIT_FAILURE);
	}
	return;
}

static void show_ignored_redirector(FILE *fp_ou,int count)
{
	char ignored[80];

	snprintf(ignored,sizeof(ignored),ngettext("%d more redirector entry not shown here&hellip;","%d more redirector entries not shown here&hellip;",count),count);
	fprintf(fp_ou,"<tr><td class=\"data\"></td><td class=\"data\"></td><td class=\"data\"></td><td class=\"data2 more\">%s</td><td class=\"data\"></td></tr>\n",ignored);
}

void redirector_report(void)
{
	FileObject *fp_in = NULL;
	FILE *fp_ou = NULL;

	char *buf;
	char *url;
	char report[MAXLEN];
	char ip[45];
	char rule[255];
	char oip[45];
	char user[MAXLEN];
	char ouser[MAXLEN];
	char data[15];
	char hora[15];
	char ouser2[255];
	char oname[MAXLEN];
	bool  z=false;
	int  count=0;
	long long int data2;
	bool new_user;
	struct getwordstruct gwarea;
	const struct userinfostruct *uinfo;
	struct tm t;
	longline line;

	ouser[0]='\0';
	ouser2[0]='\0';

	if (!redirector_count) {
		if (debugz>=LogLevel_Process) {
			if (redirector_sorted[0])
				debugaz(__FILE__,__LINE__,_("Redirector report not generated because it is empty\n"));
		}
		return;
	}

	format_path(__FILE__,__LINE__, report, sizeof(report), "%s/redirector.html", outdirname);

	if ((fp_in=FileObject_Open(redirector_sorted))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),redirector_sorted,FileObject_GetLastOpenError());
		exit(EXIT_FAILURE);
	}

	if ((fp_ou=fopen(report,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),report,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),redirector_sorted);
		exit(EXIT_FAILURE);
	}

	write_html_header(fp_ou,(IndexTree == INDEX_TREE_DATE) ? 3 : 1,_("Redirector report"),HTML_JS_NONE);
	fputs("<tr><td class=\"header_c\">",fp_ou);
	fprintf(fp_ou,_("Period: %s"),period.html);
	fputs("</td></tr>\n",fp_ou);
	fprintf(fp_ou,"<tr><th class=\"header_c\">%s</th></tr>\n",_("Redirector report"));
	close_html_header(fp_ou);

	fputs("<div class=\"report\"><table cellpadding=1 cellspacing=2>\n",fp_ou);
	fprintf(fp_ou,"<tr><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th></tr>\n",_("USERID"),_("IP/NAME"),_("DATE/TIME"),_("ACCESSED SITE"),_("RULE"));

	while((buf=longline_read(fp_in,line))!=NULL) {
		getword_start(&gwarea,buf);
		if (getword(user,sizeof(user),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid user in file \"%s\"\n"),redirector_sorted);
			exit(EXIT_FAILURE);
		}
		if (getword_atoll(&data2,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid date in file \"%s\"\n"),redirector_sorted);
			exit(EXIT_FAILURE);
		}
		if (getword(hora,sizeof(hora),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid time in file \"%s\"\n"),redirector_sorted);
			exit(EXIT_FAILURE);
		}
		if (getword(ip,sizeof(ip),&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid IP address in file \"%s\"\n"),redirector_sorted);
			exit(EXIT_FAILURE);
		}
		if (getword_ptr(buf,&url,&gwarea,'\t')<0) {
			debuga(__FILE__,__LINE__,_("Invalid url in file \"%s\"\n"),redirector_sorted);
			exit(EXIT_FAILURE);
		}
		if (getword(rule,sizeof(rule),&gwarea,'\n')<0) {
			debuga(__FILE__,__LINE__,_("Invalid rule in file \"%s\"\n"),redirector_sorted);
			exit(EXIT_FAILURE);
		}

		uinfo=userinfo_find_from_id(user);
		if (!uinfo) {
			debuga(__FILE__,__LINE__,_("Unknown user ID %s in file \"%s\"\n"),user,redirector_sorted);
			exit(EXIT_FAILURE);
		}

		computedate(data2/10000,(data2/100)%100,data2%100,&t);
		strftime(data,sizeof(data),"%x",&t);

		new_user=false;
		if (!z) {
			strcpy(ouser,user);
			strcpy(oip,ip);
			strcpy(oname,ip);
			if (Ip2Name && !uinfo->id_is_ip) ip2name(oname,sizeof(oname));
			z=true;
			new_user=true;
		} else {
			if (strcmp(ouser,user) != 0) {
				strcpy(ouser,user);
				new_user=true;
			}
			if (strcmp(oip,ip) != 0) {
				strcpy(oip,ip);
				strcpy(oname,ip);
				if (Ip2Name && !uinfo->id_is_ip) ip2name(oname,sizeof(oname));
				new_user=true;
			}
		}

		if (SquidGuardReportLimit) {
			if (strcmp(ouser2,uinfo->label) == 0) {
				count++;
			} else {
				if (count>SquidGuardReportLimit && SquidGuardReportLimit>0)
					show_ignored_redirector(fp_ou,count-SquidGuardReportLimit);
				count=1;
				strcpy(ouser2,uinfo->label);
			}
			if (count > SquidGuardReportLimit)
				continue;
		}

		if (new_user)
			fprintf(fp_ou,"<tr><td class=\"data2\">%s</td><td class=\"data2\">%s</td>",uinfo->label,ip);
		else
			fputs("<tr><td class=\"data2\"></td><td class=\"data2\"></td>",fp_ou);
		fprintf(fp_ou,"<td class=\"data2\">%s-%s</td><td class=\"data2\">",data,hora);
		output_html_link(fp_ou,url,100);
		fprintf(fp_ou,"</td><td class=\"data2\">%s</td></tr>\n",rule);
	}
	if (FileObject_Close(fp_in)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),redirector_sorted,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}
	longline_destroy(&line);

	if (count>SquidGuardReportLimit && SquidGuardReportLimit>0)
		show_ignored_redirector(fp_ou,count-SquidGuardReportLimit);

	fputs("</table>\n",fp_ou);

	if (RedirectorErrors>0)
	{
		fputs("<div class=\"warn\"><span>",fp_ou);
		fprintf(fp_ou,ngettext("%d error found in the log file. Some entries may be missing.","%d errors found in the log file. Some entries may be missing.",RedirectorErrors),RedirectorErrors);
		fputs("</span></div>\n",fp_ou);
	}

	fputs("</div>\n",fp_ou);
	write_html_trailer(fp_ou);
	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),report,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!KeepTempLog && unlink(redirector_sorted)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),redirector_sorted,strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}
