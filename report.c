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

//! The global statistics of the whole log read.
struct globalstatstruct globstat;
//! \c True to enable the smart filter.
bool smartfilter=false;

extern FileListObject UserAgentLog;

//! The file to store the HTML page where the time of access is reported for one site and one user.
static FILE *fp_tt=NULL;
//! The name of the file containing the access time of the site/user.
static char arqtt[4096]="";

static FILE *maketmp(const char *user, const char *dirname, int debug);
static void gravatmp(FILE *fp_ou, const char *oldurl, long long int nacc, long long int nbytes, const char *oldmsg, long long int nelap, long long int incache, long long int oucache);
static void closett(void);
static void gravaporuser(const struct userinfostruct *uinfo, const char *dirname, const char *url, const char *ip, const char *data, const char *hora, long long int tam, long long int elap);
static void gravager(FILE *fp_gen,const char *filename, const struct userinfostruct *uinfo, long long int nacc, const char *url, long long int nbytes, const char *ip, const char *hora, const char *dia, long long int nelap, long long int incache, long long int oucache);
static void grava_SmartFilter(const char *dirname, const char *user, const char *ip, const char *data, const char *hora, const char *url, const char *smart);

void gerarel(const struct ReadLogDataStruct *ReadFilter)
{
	FileObject *fp_in;
	FILE *fp_gen;
	FILE *fp_tmp=NULL;

	char *buf;
	char accdia[11], acchora[9], accip[256], *accurl;
	char oldaccdia[11], oldacchora[9], oldaccip[256];
	char oldacciptt[256];
	char wdirname[MAXLEN];
	char *oldurl=NULL;
	const char *oldmsg;
	char acccode[MAXLEN/2 - 1], oldacccode[MAXLEN/2 - 1];
	char ipantes[256], nameantes[MAXLEN];
	char accsmart[MAXLEN];
	char crc2[MAXLEN/2 -1];
	char siteind[MAX_TRUNCATED_URL];
	char *oldurltt=NULL;
	char oldaccdiatt[11],oldacchoratt[9];
	char tmp3[MAXLEN];
	char u2[MAX_USER_LEN];
	char userlabel[MAX_USER_LEN];
	long long int nbytes=0;
	long long int nelap=0;
	long long int nacc=0;
	long long int incache=0;
	long long int oucache=0;
	long long int accbytes, accelap;
	char *str;
	userscan uscan;
	const char *sort_field;
	const char *sort_order;
	const char *user;
	int url_len;
	int ourl_size=0;
	int ourltt_size=0;
	int same_url;
	bool new_user;
	struct getwordstruct gwarea;
	longline line;
	struct userinfostruct *uinfo;
	DayObject daystat;

	ipantes[0]='\0';
	smartfilter=false;
	memset(&globstat,0,sizeof(globstat));

	if (email[0]=='\0') {
		if (vrfydir(&period, addr, site, us)<0) {
			debuga(__FILE__,__LINE__,_("Cannot create the output directory name containing the period as part of the name\n"));
			exit(EXIT_FAILURE);
		}
	} else {
		if (snprintf(outdirname,sizeof(outdirname),"%s/emailrep",tmp)>=sizeof(outdirname)) {
			debuga(__FILE__,__LINE__,_("Path too long: "));
			debuga_more("%s/emailrep\n",tmp);
			exit(EXIT_FAILURE);
		}
		my_mkdir(outdirname);
	}

	if (debugz>=LogLevel_Process){
		debugaz(__FILE__,__LINE__,_("outdirname=%s\n"),outdirname);
	}

	if (email[0] == '\0' && !FileList_IsEmpty(UserAgentLog))
		UserAgent_Readlog(ReadFilter);

	UserAgent();
	init_usertab(UserTabFile);

	format_path(__FILE__, __LINE__, wdirname, sizeof(wdirname), "%s/sarg-general", outdirname);
	if ((fp_gen=MY_FOPEN(wdirname,"w"))==NULL){
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),wdirname,strerror(errno));
		exit(EXIT_FAILURE);
	}

	fp_tt=NULL;
	sort_labels(&sort_field,&sort_order);

	if (indexonly || datetimeby==0)
		daystat=NULL;
	else
		daystat=day_prepare();

	uscan=userinfo_startscan();
	if (uscan == NULL) {
		debuga(__FILE__,__LINE__,_("Cannot enumerate the user list\n"));
		exit(EXIT_FAILURE);
	}
	while ((uinfo = userinfo_advancescan(uscan)) != NULL ) {
		sort_users_log(tmp,debug,uinfo);
		if (snprintf(tmp3,sizeof(tmp3),"%s/%s.user_log",tmp,uinfo->filename)>=sizeof(tmp3)) {
			debuga(__FILE__,__LINE__,_("Path too long: "));
			debuga_more("%s/%s.user_log\n",tmp,uinfo->filename);
			exit(EXIT_FAILURE);
		}
		if ((fp_in=FileObject_Open(tmp3))==NULL){
			debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),tmp3,FileObject_GetLastOpenError());
			exit(EXIT_FAILURE);
		}
		user=uinfo->filename;
		day_newuser(daystat);

		strcpy(u2,uinfo->id);
		if (Ip2Name && uinfo->id_is_ip) {
			safe_strcpy(ipantes,u2,sizeof(ipantes));
			ip2name(u2,sizeof(u2));
			strcpy(nameantes,u2);
		}
		user_find(userlabel,MAX_USER_LEN, u2);
		userinfo_label(uinfo,userlabel);

		if (!indexonly) {
			fp_tmp=maketmp(user,tmp,debug);
		}

		ttopen=0;
		oldurl=NULL;
		oldurltt=NULL;
		ourltt_size=0;
		memset(oldaccdiatt,0,sizeof(oldaccdiatt));
		memset(oldacchoratt,0,sizeof(oldacchoratt));
		memset(oldacciptt,0,sizeof(oldacciptt));
		new_user=true;
		nacc=0;
		nbytes=0;
		nelap=0;
		incache=0;
		oucache=0;

		if ((line=longline_create())==NULL) {
			debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),tmp3);
			exit(EXIT_FAILURE);
		}

		while((buf=longline_read(fp_in,line))!=NULL) {
			getword_start(&gwarea,buf);
			if (getword(accdia,sizeof(accdia),&gwarea,'\t')<0 || getword(acchora,sizeof(acchora),&gwarea,'\t')<0 ||
			    getword(accip,sizeof(accip),&gwarea,'\t')<0 ||
			    getword_ptr(buf,&accurl,&gwarea,'\t')<0 || getword_atoll(&accbytes,&gwarea,'\t')<0 ||
			    getword(acccode,sizeof(acccode),&gwarea,'\t')<0) {
				debuga(__FILE__,__LINE__,_("Invalid record in file \"%s\"\n"),tmp3);
				exit(EXIT_FAILURE);
			}
			if (strncmp(acccode,"TCP_DENIED/407",14) == 0) continue;
			if (getword_atoll(&accelap,&gwarea,'\t')<0) {
				debuga(__FILE__,__LINE__,_("Invalid elapsed time in file \"%s\"\n"),tmp3);
				exit(EXIT_FAILURE);
			}
			if (getword_skip(20000,&gwarea,'"')<0 || getword(accsmart,sizeof(accsmart),&gwarea,'"')<0) {
				debuga(__FILE__,__LINE__,_("Invalid smart info in file \"%s\"\n"),tmp3);
				exit(EXIT_FAILURE);
			}

			if (accsmart[0] != '\0') {
				smartfilter=true;
				grava_SmartFilter(tmp,uinfo->id,accip,accdia,acchora,accurl,accsmart);
			}

			if (Ip2Name) {
				if (strcmp(accip,ipantes) != 0) {
					strcpy(ipantes,accip);
					ip2name(accip,sizeof(accip));
					strcpy(nameantes,accip);
				} else safe_strcpy(accip,nameantes,sizeof(accip));
			}

			if (!indexonly) {
				day_addpoint(daystat,accdia,acchora,accelap,accbytes);
				if (iprel) gravaporuser(uinfo,outdirname,accurl,accip,accdia,acchora,accbytes,accelap);
			}

			if (new_user){
				url_len=strlen(accurl);
				if (!oldurl || url_len>=ourl_size) {
					ourl_size=url_len+1;
					oldurl=realloc(oldurl,ourl_size);
					if (!oldurl) {
						debuga(__FILE__,__LINE__,_("Not enough memory to store the url\n"));
						exit(EXIT_FAILURE);
					}
				}
				strcpy(oldurl,accurl);
				strcpy(oldacccode,acccode);
				strcpy(oldaccip,accip);
				strcpy(oldaccdia,accdia);
				strcpy(oldacchora,acchora);
				new_user=false;
			}
			same_url=(strcmp(oldurl,accurl) == 0);

			if (site[0] == '\0') {
				if (!same_url){
					if (strstr(oldacccode,"DENIED") != 0)
						oldmsg="DENIED";
					else
						oldmsg="OK";
					if (fp_tmp) gravatmp(fp_tmp,oldurl,nacc,nbytes,oldmsg,nelap,incache,oucache);
					gravager(fp_gen,wdirname,uinfo,nacc,oldurl,nbytes,oldaccip,oldacchora,oldaccdia,nelap,incache,oucache);
					nacc=0;
					nbytes=0;
					nelap=0;
					incache=0;
					oucache=0;
				}
			}
			nacc++;
			nbytes+=accbytes;
			nelap+=accelap;

			if ((ReportType & REPORT_TYPE_SITE_USER_TIME_DATE) != 0 && !indexonly &&
			    (!oldurltt || strcmp(oldurltt,accurl) || strcmp(oldaccdiatt,accdia) || strcmp(oldacchoratt,acchora) ||
						strcmp(oldacciptt,accip))) {

				if (!ttopen) {
					format_path(__FILE__, __LINE__, arqtt, sizeof(arqtt), "%s/%s", outdirname, uinfo->filename);
					if (access(arqtt, R_OK) != 0)
						my_mkdir(arqtt);
					format_path(__FILE__, __LINE__, arqtt, sizeof(arqtt), "%s/%s/tt.html", outdirname, uinfo->filename);
					if ((fp_tt = fopen(arqtt, "w")) == 0) {
						debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),arqtt,strerror(errno));
						exit(EXIT_FAILURE);
					}
					ttopen=1;

					/*
					if (Privacy)
						sprintf(httplink,"<font size=%s color=%s><href=http://%s>%s",FontSize,PrivacyStringColor,PrivacyString,PrivacyString);
					else
						sprintf(httplink,"<font size=%s><a href=\"http://%s\">%s</a>",FontSize,accurl,accurl);
					*/

					write_html_header(fp_tt,(IndexTree == INDEX_TREE_DATE) ? 4 : 2,_("Site access report"),HTML_JS_NONE);
					fprintf(fp_tt,"<tr><td class=\"header_c\">%s:&nbsp;%s</td></tr>\n",_("Period"),period.html);
					fprintf(fp_tt,"<tr><td class=\"header_c\">%s:&nbsp;%s</td></tr>\n",_("User"),uinfo->label);
					fputs("<tr><td class=\"header_c\">",fp_tt);
					fprintf(fp_tt,_("Sort:&nbsp;%s, %s"),sort_field,sort_order);
					fputs("</td></tr>\n",fp_tt);
					fprintf(fp_tt,"<tr><th class=\"header_c\">%s</th></tr>\n",_("User"));
					close_html_header(fp_tt);

					fputs("<div class=\"report\"><table cellpadding=\"0\" cellspacing=\"2\">\n",fp_tt);
				}
				if (!oldurltt || strcmp(oldurltt,accurl)) {
					const char *url=accurl;
					if (*url==ALIAS_PREFIX) url++;
					url_to_anchor(accurl,siteind,sizeof(siteind));
					fprintf(fp_tt,"<tr class=\"tt\"><td colspan=\"3\"><a name=\"%s\">",siteind);
					fprintf(fp_tt,"<b>%s</b>",_("Accessed site: "));
					output_html_string(fp_tt,url,100);
					fputs("</a></td></tr>\n",fp_tt);
					fprintf(fp_tt,"<tr><th class=\"header_l\">%s</th>",_("IP"));
					fprintf(fp_tt,"<th class=\"header_l\">%s</th><th class=\"header_l\">%s</th></tr>\n",_("DATE"),pgettext("wall clock","TIME"));
				}

				fprintf(fp_tt,"<tr><td class=\"data2\">%s</td>",accip);
				fprintf(fp_tt,"<td class=\"data\">%s</td><td class=\"data\">%s</td></tr>\n",accdia,acchora);

				url_len=strlen(accurl);
				if (!oldurltt || url_len>=ourltt_size) {
					ourltt_size=url_len+1;
					oldurltt=realloc(oldurltt,ourltt_size);
					if (!oldurltt) {
						debuga(__FILE__,__LINE__,_("Not enough memory to store the url\n"));
						exit(EXIT_FAILURE);
					}
				}
				strcpy(oldurltt,accurl);
				strcpy(oldaccdiatt,accdia);
				strcpy(oldacchoratt,acchora);
				strcpy(oldacciptt,accip);
			}

			strcpy(crc2,acccode);
			str=strchr(crc2,'/');
			if (str) *str='\0';
			if (strstr(crc2,"MISS") != 0)
				oucache+=accbytes;
			else
				incache+=accbytes;

			strcpy(oldacccode,acccode);
			strcpy(oldaccip,accip);
			if (!same_url) {
				url_len=strlen(accurl);
				if (url_len>=ourl_size) {
					ourl_size=url_len+1;
					oldurl=realloc(oldurl,ourl_size);
					if (!oldurl) {
						debuga(__FILE__,__LINE__,_("Not enough memory to store the url\n"));
						exit(EXIT_FAILURE);
					}
				}
				strcpy(oldurl,accurl);
			}
			strcpy(oldaccdia,accdia);
			strcpy(oldacchora,acchora);
		}
		if (FileObject_Close(fp_in)) {
			debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),tmp3,FileObject_GetLastCloseError());
			exit(EXIT_FAILURE);
		}
		longline_destroy(&line);
		if (oldurltt) free(oldurltt);
		if (oldurl) {
			if (strstr(oldacccode,"DENIED") != 0)
				oldmsg="DENIED";
			else
				oldmsg="OK";
			if (fp_tmp) gravatmp(fp_tmp,oldurl,nacc,nbytes,oldmsg,nelap,incache,oucache);
			closett();
			gravager(fp_gen,wdirname,uinfo,nacc,oldurl,nbytes,oldaccip,oldacchora,oldaccdia,nelap,incache,oucache);
			free(oldurl);
			oldurl=NULL;
		}
		if (!new_user) {
			day_totalize(daystat,tmp,uinfo);
		}
		if (fp_tmp) {
			if (fclose(fp_tmp)==EOF) {
				debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),uinfo->filename,strerror(errno));
				exit(EXIT_FAILURE);
			}
			fp_tmp=NULL;
		}
		if (!KeepTempLog && unlink(tmp3)) {
			debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),tmp3,strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	userinfo_stopscan(uscan);
	day_cleanup(daystat);

	totalger(fp_gen,wdirname);
	if (fclose(fp_gen)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),wdirname,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (email[0] == '\0') {
		if (!indexonly) {
			if (DansGuardianConf[0] != '\0')
				dansguardian_log(ReadFilter);
			else if (debugz>=LogLevel_Process)
				debugaz(__FILE__,__LINE__,_("Dansguardian report not produced because no dansguardian configuration file was provided\n"));

			redirector_log(ReadFilter);
		}

		topuser();

		if (!indexonly) {
			if ((ReportType & REPORT_TYPE_DOWNLOADS) != 0)
				download_report();
			else if (debugz>=LogLevel_Process)
				debugaz(__FILE__,__LINE__,_("Downloaded files report not requested in report_type\n"));

			if ((ReportType & REPORT_TYPE_TOPSITES) != 0)
				topsites();
			else if (debugz>=LogLevel_Process)
				debugaz(__FILE__,__LINE__,_("Top sites report not requested in report_type\n"));

			if ((ReportType & REPORT_TYPE_SITES_USERS) != 0)
				siteuser();
			else if (debugz>=LogLevel_Process)
				debugaz(__FILE__,__LINE__,_("Sites & users report not requested in report_type\n"));

			if ((ReportType & REPORT_TYPE_DENIED) != 0)
				gen_denied_report();
			else if (debugz>=LogLevel_Process)
				debugaz(__FILE__,__LINE__,_("Denied accesses report not requested in report_type\n"));

			if ((ReportType & REPORT_TYPE_AUTH_FAILURES) != 0)
				authfail_report();
			else if (debugz>=LogLevel_Process)
				debugaz(__FILE__,__LINE__,_("Authentication failures report not requested in report_type\n"));

			if (smartfilter) smartfilter_report();

			if (DansGuardianConf[0] != '\0')
				dansguardian_report();

			redirector_report();

			if ((ReportType & REPORT_TYPE_USERS_SITES) != 0)
				htmlrel();
			else if (debugz>=LogLevel_Process)
				debugaz(__FILE__,__LINE__,_("User's detailed report not requested in report_type\n"));
		}

		make_index();

		if (SuccessfulMsg) debuga(__FILE__,__LINE__,_("Successful report generated on %s\n"),outdirname);
	} else {
		topuser();

		if ((strcmp(email,"stdout") != 0) && SuccessfulMsg)
			debuga(__FILE__,__LINE__,_("Successful report generated and sent to %s\n"),email);
	}

	if (indexonly) index_only(outdirname, debug);

	removetmp(outdirname);
	return;
}

static FILE *maketmp(const char *user, const char *dirname, int debug)
{
	FILE *fp_ou;
	char wdirname[MAXLEN];

	if ((ReportType & REPORT_TYPE_USERS_SITES) == 0) return(NULL);
	if ((ReportType & REPORT_TYPE_TOPUSERS) == 0) return(NULL);

	if (debug) debuga(__FILE__,__LINE__,_("Making file %s/%s\n"),tmp,user);
	if (snprintf(wdirname,sizeof(wdirname),"%s/%s.utmp",tmp,user)>=sizeof(wdirname)) {
		debuga(__FILE__,__LINE__,_("Path too long: "));
		debuga_more("%s/%s.utmp\n",tmp,user);
		exit(EXIT_FAILURE);
	}

	if ((fp_ou=fopen(wdirname,"w"))==NULL){
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),wdirname,strerror(errno));
		exit(EXIT_FAILURE);
	}

	return(fp_ou);
}


static void gravatmp(FILE *fp_ou, const char *oldurl, long long int nacc, long long int nbytes, const char *oldmsg, long long int nelap, long long int incache, long long int oucache)
{
	/*
	This complicated printf is due to Microsoft's inability to comply with any standard. Msvcrt is unable
	to print a long long int unless it is exactly 64-bits long.
	*/
	fprintf(fp_ou,"%"PRIu64"\t%"PRIu64"\t%s\t%s\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\n",(uint64_t)nacc,(uint64_t)nbytes,oldurl,oldmsg,(uint64_t)nelap,(uint64_t)incache,(uint64_t)oucache);

	return;
}

static void closett(void)
{
	ttopen=0;

	if (fp_tt) {
		fputs("</table>\n</div>\n",fp_tt);
		fputs("</body>\n</html>\n",fp_tt);
		if (fclose(fp_tt)==EOF) {
			debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),arqtt,strerror(errno));
			exit(EXIT_FAILURE);
		}
		fp_tt=NULL;
	}
}

static void gravaporuser(const struct userinfostruct *uinfo, const char *dirname, const char *url, const char *ip, const char *data, const char *hora, long long int tam, long long int elap)
{
	FILE *fp_ou;
	char wdirname[MAXLEN];

	if ((ReportType & REPORT_TYPE_USERS_SITES) == 0) return;

	if (snprintf(wdirname,sizeof(wdirname),"%s/%s.ip",tmp,uinfo->filename)>=sizeof(wdirname)) {
		debuga(__FILE__,__LINE__,_("Path too long: "));
		debuga_more("%s/%s.ip\n",tmp,uinfo->filename);
		exit(EXIT_FAILURE);
	}

	if ((fp_ou=MY_FOPEN(wdirname,"a"))==NULL){
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),wdirname,strerror(errno));
		exit(EXIT_FAILURE);
	}

	/*
	This complicated printf is due to Microsoft's inability to comply with any standard. Msvcrt is unable
	to print a long long int unless it is exactly 64-bits long.
	*/
	fprintf(fp_ou,"%s\t%s\t%s\t%s\t%"PRIu64"\t%"PRIu64"\n",ip,url,data,hora,(uint64_t)tam,(uint64_t)elap);

	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),wdirname,strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}


static void gravager(FILE *fp_gen,const char *filename, const struct userinfostruct *uinfo, long long int nacc, const char *url, long long int nbytes, const char *ip, const char *hora, const char *dia, long long int nelap, long long int incache, long long int oucache)
{
	/*
	This complicated printf is due to Microsoft's inability to comply with any standard. Msvcrt is unable
	to print a long long int unless it is exactly 64-bits long.
	*/
	if (fprintf(fp_gen,"%s\t%"PRIu64"\t%"PRIu64"\t%s\t%s\t%s\t%s\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\n",uinfo->id,(uint64_t)nacc,(uint64_t)nbytes,url,ip,hora,dia,(uint64_t)nelap,(uint64_t)incache,(uint64_t)oucache)<0) {
		debuga(__FILE__,__LINE__,_("Write error in file \"%s\": %s\n"),filename,strerror(errno));
		exit(EXIT_FAILURE);
	}

	globstat.nacc+=nacc;
	globstat.nbytes+=nbytes;
	globstat.elap+=nelap;
	globstat.incache+=incache;
	globstat.oucache+=oucache;
	return;
}

/*!
Write the total line at the end of the general file.
*/
void totalger(FILE *fp_gen,const char *filename)
{
	/*
	This complicated printf is due to Microsoft's inability to comply with any standard. Msvcrt is unable
	to print a long long int unless it is exactly 64-bits long.
	*/
	if (fprintf(fp_gen,"TOTAL\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\n",(uint64_t)globstat.nacc,(uint64_t)globstat.nbytes,(uint64_t)globstat.elap,(uint64_t)globstat.incache,(uint64_t)globstat.oucache)<0) {
		debuga(__FILE__,__LINE__,_("Failed to write the total line in \"%s\"\n"),filename);
		exit(EXIT_FAILURE);
	}
}

int ger_read(char *buffer,struct generalitemstruct *item,const char *filename)
{
	int i;
	int sign;
	long long int number;

	if (strncmp(buffer,"TOTAL\t",6)==0) {
		item->total=1;
		buffer+=6;

		sign=+1;
		if (*buffer == '-') {
			buffer++;
			sign=-1;
		} else if (*buffer == '+') {
			buffer++;
		}
		number=0LL;
		while (isdigit(*buffer))
			number=(number * 10) + (*buffer++)-'0';
		if (*buffer!='\t') {
			debuga(__FILE__,__LINE__,_("Invalid total number of accesses in file \"%s\"\n"),filename);
			exit(EXIT_FAILURE);
		}
		buffer++;
		item->nacc=number*sign;

		sign=+1;
		if (*buffer == '-') {
			buffer++;
			sign=-1;
		} else if (*buffer == '+') {
			buffer++;
		}
		number=0LL;
		while (isdigit(*buffer))
			number=(number * 10) + (*buffer++)-'0';
		if (*buffer!='\t') {
			debuga(__FILE__,__LINE__,_("Invalid total size in file \"%s\"\n"),filename);
			exit(EXIT_FAILURE);
		}
		buffer++;
		item->nbytes=number*sign;

		sign=+1;
		if (*buffer == '-') {
			buffer++;
			sign=-1;
		} else if (*buffer == '+') {
			buffer++;
		}
		number=0LL;
		while (isdigit(*buffer))
			number=(number * 10) + (*buffer++)-'0';
		if (*buffer!='\t') {
			debuga(__FILE__,__LINE__,_("Invalid total elapsed time in file \"%s\"\n"),filename);
			exit(EXIT_FAILURE);
		}
		buffer++;
		item->nelap=number*sign;

		sign=+1;
		if (*buffer == '-') {
			buffer++;
			sign=-1;
		} else if (*buffer == '+') {
			buffer++;
		}
		number=0LL;
		while (isdigit(*buffer))
			number=(number * 10) + (*buffer++)-'0';
		if (*buffer!='\t') {
			debuga(__FILE__,__LINE__,_("Invalid total cache hit in file \"%s\"\n"),filename);
			exit(EXIT_FAILURE);
		}
		buffer++;
		item->incache=number*sign;

		sign=+1;
		if (*buffer == '-') {
			buffer++;
			sign=-1;
		} else if (*buffer == '+') {
			buffer++;
		}
		number=0LL;
		while (isdigit(*buffer))
			number=(number * 10) + (*buffer++)-'0';
		if (*buffer!='\0') {
			debuga(__FILE__,__LINE__,_("Invalid total cache miss in file \"%s\"\n"),filename);
			exit(EXIT_FAILURE);
		}
		item->oucache=number*sign;
	} else {
		item->total=0;

		item->user=buffer;
		for (i=0 ; i<MAX_USER_LEN-1 && (unsigned char)*buffer>=' ' ; i++) buffer++;
		if (*buffer!='\t') {
			debuga(__FILE__,__LINE__,_("User name too long or invalid in file \"%s\"\n"),filename);
			exit(EXIT_FAILURE);
		}
		*buffer++='\0';

		sign=+1;
		if (*buffer == '-') {
			buffer++;
			sign=-1;
		} else if (*buffer == '+') {
			buffer++;
		}
		number=0LL;
		while (isdigit(*buffer))
			number=(number * 10) + (*buffer++)-'0';
		if (*buffer!='\t') {
			debuga(__FILE__,__LINE__,_("Invalid number of accesses in file \"%s\"\n"),filename);
			exit(EXIT_FAILURE);
		}
		buffer++;
		item->nacc=number*sign;

		sign=+1;
		if (*buffer == '-') {
			buffer++;
			sign=-1;
		} else if (*buffer == '+') {
			buffer++;
		}
		number=0LL;
		while (isdigit(*buffer))
			number=(number * 10) + (*buffer++)-'0';
		if (*buffer!='\t') {
			debuga(__FILE__,__LINE__,_("Invalid number of bytes in file \"%s\"\n"),filename);
			exit(EXIT_FAILURE);
		}
		buffer++;
		item->nbytes=number*sign;

		item->url=buffer;
		while ((unsigned char)*buffer>=' ') buffer++;
		if (*buffer!='\t') {
			debuga(__FILE__,__LINE__,_("URL too long or invalid in file \"%s\"\n"),filename);
			exit(EXIT_FAILURE);
		}
		*buffer++='\0';

		item->ip=buffer;
		for (i=0 ; i<MAX_IP_LEN-1 && (unsigned char)*buffer>=' ' ; i++) buffer++;
		if (*buffer!='\t') {
			debuga(__FILE__,__LINE__,_("IP address too long or invalid in file \"%s\"\n"),filename);
			exit(EXIT_FAILURE);
		}
		*buffer++='\0';

		item->time=buffer;
		for (i=0 ; i<MAX_DATETIME_LEN-1 && (unsigned char)*buffer>=' ' ; i++) buffer++;
		if (*buffer!='\t') {
			debuga(__FILE__,__LINE__,_("Time too long or invalid in file \"%s\"\n"),filename);
			exit(EXIT_FAILURE);
		}
		*buffer++='\0';

		item->date=buffer;
		for (i=0 ; i<MAX_DATETIME_LEN-1 && (unsigned char)*buffer>=' ' ; i++) buffer++;
		if (*buffer!='\t') {
			debuga(__FILE__,__LINE__,_("Date too long or invalid in file \"%s\"\n"),filename);
			exit(EXIT_FAILURE);
		}
		*buffer++='\0';

		sign=+1;
		if (*buffer == '-') {
			buffer++;
			sign=-1;
		} else if (*buffer == '+') {
			buffer++;
		}
		number=0LL;
		while (isdigit(*buffer))
			number=(number * 10) + (*buffer++)-'0';
		if (*buffer!='\t') {
			debuga(__FILE__,__LINE__,_("Invalid elapsed time in file \"%s\"\n"),filename);
			exit(EXIT_FAILURE);
		}
		buffer++;
		item->nelap=number*sign;

		sign=+1;
		if (*buffer == '-') {
			buffer++;
			sign=-1;
		} else if (*buffer == '+') {
			buffer++;
		}
		number=0LL;
		while (isdigit(*buffer))
			number=(number * 10) + (*buffer++)-'0';
		if (*buffer!='\t') {
			debuga(__FILE__,__LINE__,_("Invalid cache hit size in file \"%s\"\n"),filename);
			exit(EXIT_FAILURE);
		}
		buffer++;
		item->incache=number*sign;

		sign=+1;
		if (*buffer == '-') {
			buffer++;
			sign=-1;
		} else if (*buffer == '+') {
			buffer++;
		}
		number=0LL;
		while (isdigit(*buffer))
			number=(number * 10) + (*buffer++)-'0';
		if (*buffer!='\0') {
			debuga(__FILE__,__LINE__,_("Invalid cache miss size in file \"%s\"\n"),filename);
			exit(EXIT_FAILURE);
		}
		item->oucache=number*sign;
	}
	return(0);
}

static void grava_SmartFilter(const char *dirname, const char *user, const char *ip, const char *data, const char *hora, const char *url, const char *smart)
{
	FILE *fp_ou;
	char wdirname[MAXLEN];

	if (snprintf(wdirname,sizeof(wdirname),"%s/smartfilter.int_unsort",dirname)>=sizeof(wdirname)) {
		debuga(__FILE__,__LINE__,_("Path too long: "));
		debuga_more("%s/smartfilter.int_unsort\n",dirname);
		exit(EXIT_FAILURE);
	}

	if ((fp_ou=MY_FOPEN(wdirname,"a"))==NULL){
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),wdirname,strerror(errno));
		exit(EXIT_FAILURE);
	}

	fprintf(fp_ou,"%s\t%s\t%s\t%s\t%s\t%s\n",user,data,hora,ip,url,smart);
	fputs("</body>\n</html>\n",fp_tt);

	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),wdirname,strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}
