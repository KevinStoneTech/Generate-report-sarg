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
#include "include/readlog.h"
#include "include/filelist.h"

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

//! The log file filtering.
struct ReadLogDataStruct ReadFilter;

//! The list of the system users.
/*@null@*/char *userfile=NULL;

//! List of the input log files to process.
FileListObject AccessLog=NULL;
//! Selected locale set through the environment variable.
char *CurrentLocale=NULL;
//! Set to \c true if a useragent log is provided on the command line.
bool UserAgentFromCmdLine=false;

extern FileListObject UserAgentLog;

static void getusers(const char *pwdfile, int debug);
static void CleanTemporaryDir();

int main(int argc,char *argv[])
{
	extern int optind;
	extern int optopt;
	extern char *optarg;

	char hm_str[15];
	char hexclude[MAXLEN];
	char splitprefix[MAXLEN];
	int  ch;
	int  errflg=0;
	bool  dns=false;
	int  iarq=0;
	int lastlog=-1;
	int LogStatus;
	bool realt;
	bool userip;
	time_t start_time;
	time_t end_time;
	time_t read_start_time;
	time_t read_end_time;
	time_t process_start_time;
	time_t process_end_time;
	double read_elapsed;
	double process_elapsed;
	FileListIterator FIter;
	static int split=0;
	static int convert=0;
	static int output_css=0;
	static int show_statis=0;
	static int show_version=0;
	int option_index;
	static struct option long_options[]=
	{
		{"convert",no_argument,&convert,1},
		{"css",no_argument,&output_css,1},
		{"help",no_argument,NULL,'h'},
		{"lastlog",required_argument,NULL,2},
		{"keeplogs",no_argument,NULL,3},
		{"split",no_argument,&split,1},
		{"splitprefix",required_argument,NULL,'P'},
		{"statistics",no_argument,&show_statis,1},
		{"version",no_argument,&show_version,'V'},
		{0,0,0,0}
	};

	start_time=time(NULL);

#ifdef HAVE_LOCALE_H
	setlocale(LC_TIME,"");
#endif

#if defined(ENABLE_NLS) && defined(HAVE_LOCALE_H)
	CurrentLocale=setlocale (LC_ALL, "");
	if (!CurrentLocale) {
		fprintf(stderr,"SARG: Cannot set the locale LC_ALL to the environment variable\n");
		exit(EXIT_FAILURE);
	}
	if (!bindtextdomain (PACKAGE_NAME, LOCALEDIR)) {
		fprintf(stderr,"SARG: Cannot bind to text domain %s in directory %s (%s)\n",PACKAGE_NAME,LOCALEDIR,strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (!textdomain (PACKAGE_NAME)) {
		fprintf(stderr,"SARG: Cannot set gettext domain for %s PACKAGE_NAME (%s)\n",PACKAGE_NAME,strerror(errno));
		exit(EXIT_FAILURE);
	}
#endif //ENABLE_NLS

	BgImage[0]='\0';
	LogoImage[0]='\0';
	LogoText[0]='\0';
	PasswdFile[0]='\0';
	OutputEmail[0]='\0';
	ExcludeHosts[0]='\0';
	ExcludeUsers[0]='\0';
	ConfigFile[0]='\0';
	code[0]='\0';
	LastLog=0;
	ReportType=0UL;
	UserTabFile[0]='\0';
	BlockIt[0]='\0';
	ExternalCSSFile[0]='\0';
	RedirectorLogFormat[0]='\0';
	NRedirectorLogs=0;

	snprintf(ExcludeCodes,sizeof(ExcludeCodes),"%s/exclude_codes",SYSCONFDIR);
	strcpy(GraphDaysBytesBarColor,"orange");
	strcpy(BgColor,"#ffffff");
	strcpy(TxColor,"#000000");
	strcpy(TxBgColor,"lavender");
	strcpy(TiColor,"darkblue");
	strcpy(Width,"80");
	strcpy(Height,"45");
	strcpy(LogoTextColor,"#000000");
	strcpy(HeaderColor,"darkblue");
	strcpy(HeaderBgColor,"#dddddd");
	strcpy(LogoTextColor,"#006699");
	strcpy(FontSize,"9px");
	strcpy(TempDir,"/tmp");
	TempDirPath[0] = '\0';
	strcpy(OutputDir,"/var/www/html/squid-reports");
	AnonymousOutputFiles=false;
	Ip2Name=false;
	DateFormat='u';
	OverwriteReport=false;
	RemoveTempFiles=true;
	strcpy(ReplaceIndex,INDEX_HTML_FILE);
	Index=INDEX_YES;
	RecordsWithoutUser=RECORDWITHOUTUSER_IP;
	UseComma=0;
	strcpy(MailUtility,"mailx");
	TopSitesNum=100;
	TopUsersNum=0;
	UserIp=0;
	TopuserSort=TOPUSER_SORT_BYTES | TOPUSER_SORT_REVERSE;
	UserSort=USER_SORT_BYTES | USER_SORT_REVERSE;
	TopsitesSort=TOPSITE_SORT_CONNECT | TOPSITE_SORT_REVERSE;
	LongUrl=0;
	strcpy(FontFace,"Verdana,Tahoma,Arial");
	datetimeby=DATETIME_BYTE;
	strcpy(CharSet,"ISO-8859-1");
	Privacy=0;
	strcpy(PrivacyString,"***.***.***.***");
	strcpy(PrivacyStringColor,"blue");
	SuccessfulMsg=true;
	TopUserFields=TOPUSERFIELDS_NUM | TOPUSERFIELDS_DATE_TIME | TOPUSERFIELDS_USERID | TOPUSERFIELDS_CONNECT |
	      TOPUSERFIELDS_BYTES | TOPUSERFIELDS_SETYB | TOPUSERFIELDS_IN_CACHE_OUT |
	      TOPUSERFIELDS_USED_TIME | TOPUSERFIELDS_MILISEC | TOPUSERFIELDS_PTIME |
	      TOPUSERFIELDS_TOTAL | TOPUSERFIELDS_AVERAGE;
	UserReportFields=USERREPORTFIELDS_CONNECT | USERREPORTFIELDS_BYTES | USERREPORTFIELDS_SETYB |
	      USERREPORTFIELDS_IN_CACHE_OUT | USERREPORTFIELDS_USED_TIME | USERREPORTFIELDS_MILISEC |
	      USERREPORTFIELDS_PTIME | USERREPORTFIELDS_TOTAL | USERREPORTFIELDS_AVERAGE;
	strcpy(DataFileDelimiter,";");
	DataFileFields=DATA_FIELD_USER | DATA_FIELD_DATE | DATA_FIELD_TIME | DATA_FIELD_URL | DATA_FIELD_CONNECT |
	      DATA_FIELD_BYTES | DATA_FIELD_IN_CACHE | DATA_FIELD_OUT_CACHE | DATA_FIELD_ELAPSED;
	ShowReadStatistics=true;
	ShowReadPercent=false;
	strcpy(IndexSortOrder,"D");
	ShowSargInfo=true;
	ShowSargLogo=true;
	ParsedOutputLog[0]='\0';
	strcpy(ParsedOutputLogCompress,"/bin/gzip -f");
	DisplayedValues=DISPLAY_ABBREV;
	strcpy(HeaderFontSize,"9px");
	strcpy(TitleFontSize,"11px");
	strcpy(AuthUserTemplateFile,"sarg_htaccess");
	set_download_suffix("7z,ace,arj,avi,bat,bin,bz2,bzip,cab,com,cpio,dll,doc,dot,exe,gz,iso,lha,lzh,mdb,mov,mp3,mpeg,mpg,mso,nrg,ogg,ppt,rar,rtf,shs,src,sys,tar,tgz,vcd,vob,wma,wmv,zip");
	Graphs=true;
#if defined(FONTDIR)
	strcpy(GraphFont,FONTDIR"/DejaVuSans.ttf");
#else
	GraphFont[0]='\0';
#endif
	strcpy(Ulimit,"20000");
	NtlmUserFormat=NTLMUSERFORMAT_DOMAINUSER;
	IndexTree=INDEX_TREE_FILE;
	IndexFields=INDEXFIELDS_DIRSIZE;
	strcpy(RealtimeTypes,"GET,PUT,CONNECT,POST");
	RealtimeUnauthRec=REALTIME_UNAUTH_REC_SHOW;
	RedirectorFilterOutDate=true;
	DansguardianFilterOutDate=true;
	DataFileUrl=DATAFILEURL_IP;
	strcpy(MaxElapsed,"28800000");
	BytesInSitesUsersReport=0;
	UserAuthentication=0;
	strcpy(LDAPHost,"127.0.0.1");
	LDAPPort=389;
	LDAPProtocolVersion=3;
	LDAPBindDN[0]='\0';
	LDAPBindPW[0]='\0';
	LDAPBaseSearch[0]='\0';
	strcpy(LDAPFilterSearch, "(uid=%s)");
	strcpy(LDAPTargetAttr, "cn");
	LDAPNativeCharset[0]='\0';
	SortTableJs[0]='\0';

	tmp[0]='\0';
	us[0]='\0';
	ReadFilter.DateRange[0]='\0';
	df='\0';
	hexclude[0]='\0';
	addr[0]='\0';
	ReadFilter.StartTime=-1;
	ReadFilter.EndTime=-1;
	site[0]='\0';
	outdir[0]='\0';
	splitprefix[0]='\0';
	email[0]='\0';
	UserInvalidChar[0]='\0';
	DataFile[0]='\0';
	SquidGuardConf[0]='\0';
	DansGuardianConf[0]='\0';
	hm_str[0]='\0';
	HostAliasFile[0]='\0';
	UserAliasFile[0]='\0';

	dansguardian_count=0;
	redirector_count=0;
	useragent_count=0;
	DeniedReportLimit=10;
	SiteUsersReportLimit=0;
	AuthfailReportLimit=10;
	DansGuardianReportLimit=10;
	SquidGuardReportLimit=10;
	DownloadReportLimit=50;
	UserReportLimit=0;
	debug=0;
	debugz=0;
	iprel=false;
	userip=false;
	realt=false;
	realtime_refresh=3;
	realtime_access_log_lines=1000;
	cost=0.01;
	nocost=50000000;
	squid24=false;
	ReadFilter.StartDate=0;
	ReadFilter.EndDate=0;
	KeepTempLog=false;
	NumLogSuccessiveErrors=3;
	NumLogTotalErrors=50;
	lines_read=0UL;
	records_kept=0UL;
	nusers=0UL;

	memset(IncludeUsers,0,sizeof(IncludeUsers));
	memset(ExcludeString,0,sizeof(ExcludeString));
	memset(&period,0,sizeof(period));

	AccessLogFromCmdLine=0;
	RedirectorLogFromCmdLine=0;

	strcpy(Title,_("Squid User Access Report"));

	while((ch = getopt_long(argc, argv, "a:b:c:d:e:f:g:hikl:L:no:P:prs:t:u:Vw:xyz",long_options,&option_index)) != -1){
		switch(ch)
		{
			case 0:
				break;
			case 2:
				lastlog=atoi(optarg);
				break;
			case 3:
				lastlog=0;
				break;
			case 'a':
				safe_strcpy(addr,optarg,sizeof(addr));
				break;
			case 'b': //unused option
				UserAgentFromCmdLine=true;
				if (!UserAgentLog)
					UserAgentLog=FileList_Create();
				if (!FileList_AddFile(UserAgentLog,optarg)) {
					debuga(__FILE__,__LINE__,_("Not enough memory to store a user agent file name\n"));
					exit(EXIT_FAILURE);
				}
				break;
			case 'c':
				safe_strcpy(hexclude,optarg,sizeof(hexclude));
				break;
			case 'd':
				safe_strcpy(ReadFilter.DateRange,optarg,sizeof(ReadFilter.DateRange));
				date_from(&ReadFilter);
				break;
			case 'e':
				safe_strcpy(email,optarg,sizeof(email));
				break;
			case 'f':
				safe_strcpy(ConfigFile,optarg,sizeof(ConfigFile));
				break;
			case 'g':
				df=*optarg;
				break;
			case 'h':
				usage(argv[0]);
				exit(EXIT_SUCCESS);
			case 'i':
				iprel=true;
				break;
			case 'k':
				KeepTempLog=true;
				break;
			case 'l':
				if (!AccessLog)
					AccessLog=FileList_Create();
				if (!FileList_AddFile(AccessLog,optarg)) {
					debuga(__FILE__,__LINE__,_("Not enough memory to store the input log file names\n"));
					exit(EXIT_FAILURE);
				}
				AccessLogFromCmdLine++;
				break;
			case 'L':
				if (NRedirectorLogs>MAX_REDIRECTOR_LOGS) {
					debuga(__FILE__,__LINE__,_("Too many redirector logs passed on command line with option -L.\n"));
					exit(EXIT_FAILURE);
				}
				if (strlen(optarg)>=MAX_REDIRECTOR_FILELEN) {
					debuga(__FILE__,__LINE__,_("Redirector log file name too long passed on command line with opton -L: %s\n"),optarg);
					exit(EXIT_FAILURE);
				}
				strcpy(RedirectorLogs[NRedirectorLogs],optarg);
				NRedirectorLogs++;
				RedirectorLogFromCmdLine++;
				break;
			case 'n':
				dns=true;
				break;
			case 'o':
				safe_strcpy(outdir,optarg,sizeof(outdir));
				break;
			case 'p':
				userip=true;
				break;
			case 'P':
				safe_strcpy(splitprefix,optarg,sizeof(splitprefix));
				break;
			case 'r':
				realt=true;
				break;
			case 's':
				safe_strcpy(site,optarg,sizeof(site));
				break;
			case 't':
			{
				int h1,m1,h2,m2;

				if (strstr(optarg,"-") == 0) {
					if (sscanf(optarg,"%d:%d",&h1,&m1)!=2) {
						debuga(__FILE__,__LINE__,_("Time period passed on the command line with option -t must be HH:MM\n"));
						exit(EXIT_FAILURE);
					}
					ReadFilter.StartTime=h1*100+m1;
					ReadFilter.EndTime=ReadFilter.StartTime+1;
					snprintf(hm_str,sizeof(hm_str),"%02d:%02d",h1,m1);
				} else {
					if (sscanf(optarg,"%d:%d-%d:%d",&h1,&m1,&h2,&m2)!=4) {
						debuga(__FILE__,__LINE__,_("Time range passed on the command line with option -t must be HH:MM-HH:MM\n"));
						exit(EXIT_FAILURE);
					}
					ReadFilter.StartTime=h1*100+m1;
					ReadFilter.EndTime=h2*100+m2;
					snprintf(hm_str,sizeof(hm_str),"%02d:%02d-%02d:%02d",h1,m1,h2,m2);
				}
				break;
			}
			case 'u':
				safe_strcpy(us,optarg,sizeof(us));
				break;
			case 'V':
				show_version=1;
				break;
			case 'w':
				safe_strcpy(tmp,optarg,sizeof(tmp));
				break;
			case 'x':
				debug++;
				break;
			case 'y': //unused option
				langcode++;
				break;
			case 'z':
				debugz++;
				break;
			case ':':
				debuga(__FILE__,__LINE__,_("Option -%c requires an argument\n"),optopt);
				exit(EXIT_FAILURE);
			case '?':
				usage(argv[0]);
				exit(EXIT_FAILURE);
			default:
				abort();
		}
	}

	if (errflg>0) {
		usage(argv[0]);
		exit(2);
	}
	if (show_version) {
		version();
	}

	if (output_css) {
		css_content(stdout);
		exit(EXIT_SUCCESS);
	}

	if (optind<argc) {
		if (!AccessLog)
			AccessLog=FileList_Create();
		for (iarq=optind ; iarq<argc ; iarq++) {
			if (!FileList_AddFile(AccessLog,argv[iarq])) {
				debuga(__FILE__,__LINE__,_("Not enough memory to store the input log file names\n"));
				exit(EXIT_FAILURE);
			}
			AccessLogFromCmdLine++;
		}
	}

	if (debug) debuga(__FILE__,__LINE__,_("Init\n"));

	if (ConfigFile[0] == '\0') snprintf(ConfigFile,sizeof(ConfigFile),"%s/sarg.conf",SYSCONFDIR);
	if (access(ConfigFile, R_OK) != 0) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),ConfigFile,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (access(ConfigFile, R_OK) == 0)
		getconf(ConfigFile);

	if (userip) UserIp=true;

	if (dns) ip2name_forcedns();

	if (lastlog>=0) LastLog=lastlog;

	if (outdir[0] == '\0') strcpy(outdir,OutputDir);
	if (outdir[0] != '\0') strcat(outdir,"/");

	if (IndexTree == INDEX_TREE_FILE)
		strcpy(ImageFile,"../images");
	else
		strcpy(ImageFile,"../../../images");

	dataonly=(DataFile[0] != '\0');

	if (df=='\0') df=DateFormat;
	if (df=='\0') df='u';
	if (df=='w')
		IndexTree=INDEX_TREE_FILE;

	if (AccessLog==NULL) {
		AccessLog=FileList_Create();
		if (!FileList_AddFile(AccessLog,"/var/log/squid/access.log")) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store the input log file names\n"));
			exit(EXIT_FAILURE);
		}
	}

	if (realt) {
		realtime();
		exit(EXIT_SUCCESS);
	}
	if (split) {
		const char *file;

		FIter=FileListIter_Open(AccessLog);
		while ((file=FileListIter_Next(FIter))!=NULL)
			splitlog(file, df, &ReadFilter, convert, splitprefix);
		FileListIter_Close(FIter);
		exit(EXIT_SUCCESS);
	}
	if (convert) {
		const char *file;

		FIter=FileListIter_Open(AccessLog);
		while ((file=FileListIter_Next(FIter))!=NULL)
			convlog(file, df, &ReadFilter);
		FileListIter_Close(FIter);
		exit(EXIT_SUCCESS);
	}

	load_excludecodes(ExcludeCodes);

	if (access(PasswdFile, R_OK) == 0) {
		getusers(PasswdFile,debug);
		ReadFilter.SysUsers=true;
	} else {
		ReadFilter.SysUsers=false;
	}

	if (hexclude[0] == '\0')
		strcpy(hexclude,ExcludeHosts);
	if (hexclude[0] != '\0') {
		gethexclude(hexclude,debug);
		ReadFilter.HostFilter=true;
	} else {
		ReadFilter.HostFilter=false;
	}

	if (ReportType == 0) {
		ReportType=REPORT_TYPE_TOPUSERS | REPORT_TYPE_TOPSITES | REPORT_TYPE_USERS_SITES |
		           REPORT_TYPE_SITES_USERS | REPORT_TYPE_DATE_TIME | REPORT_TYPE_DENIED |
				   REPORT_TYPE_AUTH_FAILURES | REPORT_TYPE_SITE_USER_TIME_DATE |
				   REPORT_TYPE_DOWNLOADS | REPORT_TYPE_USERAGENT;
	}
	if (!FileList_IsEmpty(UserAgentLog))
		ReportType|=REPORT_TYPE_USERAGENT;

	if (access(ExcludeUsers, R_OK) == 0) {
		getuexclude(ExcludeUsers,debug);
		ReadFilter.UserFilter=true;
	} else {
		ReadFilter.UserFilter=false;
	}
	if (HostAliasFile[0] != '\0')
		read_hostalias(HostAliasFile);
	if (UserAliasFile[0] != '\0')
		read_useralias(UserAliasFile);

	indexonly=false;
	if (ReadFilter.UserFilter) {
		if (is_indexonly())
			indexonly=true;
	}
	if (strcmp(ExcludeUsers,"indexonly") == 0) indexonly=true;
	if (Index == INDEX_ONLY) indexonly=true;

	if (MaxElapsed[0] != '\0')
		ReadFilter.max_elapsed=atol(MaxElapsed);
	else
		ReadFilter.max_elapsed=0;

	if (tmp[0] == '\0') strcpy(tmp,TempDir);
	else strcpy(TempDir,tmp);
	/*
	For historical reasons, the temporary directory used to be subdirectory "sarg" of the path
	provided by the user. The full temporary directory was the predictable name /tmp/sarg. It is unsafe
	to use a predictable name in the world writable /tmp as malicious users might use that knowledge
	to lure sarg into some kind of nasty activity it was not designed for.
	The default is now to use a random name safely created by the system but it is still possible to
	use a known fixed path set with a parameter in sarg.conf.
	*/
	if (TempDirPath[0]) {
		append_to_path(tmp, sizeof(tmp), TempDirPath);
	} else {
		append_to_path(tmp, sizeof(tmp), "sargXXXXXX");
		if (mkdtemp(tmp) == NULL) {
			debuga(__FILE__,__LINE__,_("Failed to get a unique temporary directory name based on template \"%s\": %s\n"), tmp, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (tmp[0]!='\0' && strncmp(outdir,tmp,strlen(tmp))==0) {
		debuga(__FILE__,__LINE__,_("The output directory \"%s\" must be outside of the temporary directory \"%s\"\n"),outdir,tmp);
		exit(EXIT_FAILURE);
	}
	atexit(CleanTemporaryDir);

	if (email[0] == '\0' && OutputEmail[0] != '\0') strcpy(email,OutputEmail);

	if (email[0] != '\0') {
		my_mkdir(tmp);
		strcpy(outdir,tmp);
		strcat(outdir,"/");
	}

	makeTmpDir(tmp);

	if (debug) {
		const char *file;

		debuga(__FILE__,__LINE__,_("Parameters:\n"));
		debuga(__FILE__,__LINE__,_("          Hostname or IP address (-a) = %s\n"),addr);
		FIter=FileListIter_Open(UserAgentLog);
		while ((file=FileListIter_NextWithMask(FIter))!=NULL)
			debuga(__FILE__,__LINE__,_("                   Useragent log (-b) = %s\n"),file);
		FileListIter_Close(FIter);
		debuga(__FILE__,__LINE__,_("                    Exclude file (-c) = %s\n"),hexclude);
		debuga(__FILE__,__LINE__,_("                 Date from-until (-d) = %s\n"),ReadFilter.DateRange);
		debuga(__FILE__,__LINE__,_("   Email address to send reports (-e) = %s\n"),email);
		debuga(__FILE__,__LINE__,_("                     Config file (-f) = %s\n"),ConfigFile);
		if (df=='e')
			debuga(__FILE__,__LINE__,_("                     Date format (-g) = Europe (dd/mm/yyyy)\n"));
		else if (df=='u')
			debuga(__FILE__,__LINE__,_("                     Date format (-g) = USA (mm/dd/yyyy)\n"));
		else if (df=='w')
			debuga(__FILE__,__LINE__,_("                     Date format (-g) = Sites & Users (yyyy/ww)\n"));
		debuga(__FILE__,__LINE__,_("                       IP report (-i) = %s\n"),(iprel) ? _("Yes") : _("No"));
		debuga(__FILE__,__LINE__,_("            Keep temporary files (-k) = %s\n"),(KeepTempLog) ? _("Yes") : _("No"));
		FIter=FileListIter_Open(AccessLog);
		while ((file=FileListIter_NextWithMask(FIter))!=NULL)
			debuga(__FILE__,__LINE__,_("                       Input log (-l) = %s\n"),file);
		FileListIter_Close(FIter);
		for (iarq=0 ; iarq<NRedirectorLogs ; iarq++)
			debuga(__FILE__,__LINE__,_("                  Redirector log (-L) = %s\n"),RedirectorLogs[iarq]);
		debuga(__FILE__,__LINE__,_("              Resolve IP Address (-n) = %s\n"),(Ip2Name) ? _("Yes") : _("No"));
		debuga(__FILE__,__LINE__,_("                      Output dir (-o) = %s\n"),outdir);
		debuga(__FILE__,__LINE__,_("Use Ip Address instead of userid (-p) = %s\n"),(UserIp) ? _("Yes") : _("No"));
		debuga(__FILE__,__LINE__,_("                   Accessed site (-s) = %s\n"),site);
		debuga(__FILE__,__LINE__,_("                            Time (-t) = %s\n"),hm_str);
		debuga(__FILE__,__LINE__,_("                            User (-u) = %s\n"),us);
		debuga(__FILE__,__LINE__,_("                   Temporary dir (-w) = %s\n"),tmp);
		debuga(__FILE__,__LINE__,_("                  Debug messages (-x) = %s\n"),(debug) ? _("Yes") : _("No"));
		debuga(__FILE__,__LINE__,_("                Process messages (-z) = %d\n"),debugz);
		debuga(__FILE__,__LINE__,_(" Previous reports to keep (--lastlog) = %d\n"),LastLog);
		debuga(__FILE__,__LINE__,"\n");
	}

	if (debug)
		debuga(__FILE__,__LINE__,_("sarg version: %s\n"),VERSION);

#ifdef ENABLE_DOUBLE_CHECK_DATA
	debuga(__FILE__,__LINE__,_("Sarg compiled to report warnings if the output is inconsistent\n"));
#endif

#ifdef HAVE_RLIM_T
	if (Ulimit[0] != '\0') {
		struct rlimit rl;
		long l1, l2;
		int rc=0;

#if defined(RLIMIT_NOFILE)
		getrlimit (RLIMIT_NOFILE, &rl);
#elif defined(RLIMIT_OFILE)
		getrlimit (RLIMIT_OFILE, &rl);
#else
#warning "No rlimit resource for the number of open files"
#endif
		l1 = rl.rlim_cur;
		l2 = rl.rlim_max;

		rl.rlim_cur = atol(Ulimit);
		rl.rlim_max = atol(Ulimit);
#if defined(RLIMIT_NOFILE)
		rc=setrlimit (RLIMIT_NOFILE, &rl);
#elif defined(RLIMIT_OFILE)
		rc=setrlimit (RLIMIT_OFILE, &rl);
#else
#warning "No rlimit resource for the number of open files"
#endif
		if (rc == -1) {
			debuga(_("setrlimit error: %s\n"),strerror(errno));
		}

		if (debug)
			debuga("Maximum file descriptor: cur=%ld max=%ld, changed to cur="RLIM_STRING" max="RLIM_STRING"\n",l1,l2,rl.rlim_cur,rl.rlim_max);
	}
#endif

	read_start_time=time(NULL);
	LogStatus=ReadLogFile(&ReadFilter);
	read_end_time=time(NULL);
	read_elapsed=(double)read_end_time-(double)read_start_time;

	FileList_Destroy(&AccessLog);
	free_download();
	free_excludecodes();
	free_exclude();

	if (debug) {
		char date0[30], date1[30];
		struct tm Start,End;

		if (GetLogPeriod(&Start,&End)) {
			strftime(date0,sizeof(date0),"%x",&Start);
			strftime(date1,sizeof(date1),"%x",&End);
			// TRANSLATORS: The %s are the start and end dates in locale format.
			debuga(__FILE__,__LINE__,_("Period covered by log files: %s-%s\n"),date0,date1);
		}
	}

	if (!LogStatus){
		debuga(__FILE__,__LINE__,_("No records found\n"));
		debuga(__FILE__,__LINE__,_("End\n"));
		userinfo_free();
		if (userfile) free(userfile);
		close_usertab();
		exit(EXIT_SUCCESS);
	}

	if (debug) {
		char date0[30], date1[30];

		strftime(date0,sizeof(date0),"%x",&period.start);
		strftime(date1,sizeof(date1),"%x",&period.end);
		// TRANSLATORS: The %s are the start and end dates in locale format.
		debuga(__FILE__,__LINE__,_("Period extracted from log files: %s-%s\n"),date0,date1);
	}
	if (ReadFilter.DateRange[0] != '\0') {
		getperiod_fromrange(&period,&ReadFilter);
	}
	if (getperiod_buildtext(&period)<0) {
		debuga(__FILE__,__LINE__,_("Failed to build the string representation of the date range\n"));
		exit(EXIT_FAILURE);
	}

	process_start_time=time(NULL);
	if (DataFile[0] != '\0')
		data_file(tmp);
	else
		gerarel(&ReadFilter);
	process_end_time=time(NULL);
	process_elapsed=(double)process_end_time-(double)process_start_time;

	denied_cleanup();
	authfail_cleanup();
	download_cleanup();
	CleanTemporaryDir();

	ip2name_cleanup();
	free_hostalias();
	free_useralias();
	userinfo_free();
	if (userfile)
		free(userfile);
	close_usertab();
	FileList_Destroy(&UserAgentLog);

	end_time=time(NULL);

	if (show_statis) {
		double elapsed=(double)end_time-(double)start_time;
		debuga(__FILE__,__LINE__,_("Total execution time: %.0lf seconds\n"),elapsed);
		if (read_elapsed>0.) {
			debuga(__FILE__,__LINE__,_("Lines read: %lu lines in %.0lf seconds (%.0lf lines/s)\n"),lines_read,read_elapsed,(double)lines_read/read_elapsed);
		}
		if (process_elapsed>0.) {
			debuga(__FILE__,__LINE__,_("Processed records: %lu records in %.0lf seconds (%.0lf records/s)\n"),records_kept,process_elapsed,(double)records_kept/process_elapsed);
			debuga(__FILE__,__LINE__,_("Users: %lu users in %.0lf seconds (%.0lf users/s)\n"),nusers,process_elapsed,(double)nusers/process_elapsed);
		}
	}

	if (debug)
		debuga(__FILE__,__LINE__,_("End\n"));

	exit(EXIT_SUCCESS);
}

static void getusers(const char *pwdfile, int debug)
{
	FILE *fp_usr;
	char buf[255];
	char *str;
	long int nreg=0;

	if (debug)
		debuga(__FILE__,__LINE__,_("Loading password file \"%s\"\n"),pwdfile);

	if ((fp_usr = fopen(pwdfile, "r")) == NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),pwdfile,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (fseek(fp_usr, 0, SEEK_END)==-1) {
		debuga(__FILE__,__LINE__,_("Failed to move till the end of file \"%s\": %s\n"),pwdfile,strerror(errno));
		exit(EXIT_FAILURE);
	}
	nreg = ftell(fp_usr);
	if (nreg<0) {
		debuga(__FILE__,__LINE__,_("Cannot get the size of file \"%s\"\n"),pwdfile);
		exit(EXIT_FAILURE);
	}
	nreg = nreg+5000;
	if (fseek(fp_usr, 0, SEEK_SET)==-1) {
		debuga(__FILE__,__LINE__,_("Failed to rewind file \"%s\": %s\n"),pwdfile,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((userfile=(char *) malloc(nreg))==NULL){
		debuga(__FILE__,__LINE__,_("malloc error (%ld bytes required)\n"),nreg);
		exit(EXIT_FAILURE);
	}

	memset(userfile,0,nreg);
	strcpy(userfile,":");

	while(fgets(buf,sizeof(buf),fp_usr)!=NULL) {
		str=strchr(buf,':');
		if (!str) {
			debuga(__FILE__,__LINE__,_("Invalid user in file \"%s\"\n"),pwdfile);
			exit(EXIT_FAILURE);
		}
		str[1]='\0';
		strcat(userfile,buf);
	}

	if (fclose(fp_usr)==EOF) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),pwdfile,strerror(errno));
		exit(EXIT_FAILURE);
	}

	return;
}

static void CleanTemporaryDir()
{
	if (!KeepTempLog && strcmp(tmp,"/tmp") != 0) {
		unlinkdir(tmp,0);
	}
}
