#include "config.h"
#include "info.h"
#include "btree_cache.h"

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif
#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#if defined(HAVE_SYS_DIRENT_H) && !defined(HAVE_DIRENT_H)
#include <sys/dirent.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_TYPES_H
#include <types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_GD_H
#define HAVE_GD 1
#include <gd.h>
#endif
#ifdef HAVE_GDFONTL_H
#include <gdfontl.h>
#endif
#ifdef HAVE_GDFONTT_H
#include <gdfontt.h>
#endif
#ifdef HAVE_GDFONTS_H
#include <gdfonts.h>
#endif
#ifdef HAVE_GDFONTMB_H
#include <gdfontmb.h>
#endif
#ifdef HAVE_GDFONTG_H
#include <gdfontg.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#ifdef HAVE_MATH_H
#include <math.h>
#endif
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_EXECINFO_H
#include <execinfo.h>
#endif
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#else
typedef int bool;
#define true 1
#define false 0
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_FNMATCH_H
#include <fnmatch.h>
#endif

#if defined(HAVE_FOPEN64)
#define _FILE_OFFSET_BITS 64
#define MY_FOPEN fopen64
#else
#define MY_FOPEN fopen
#endif

#if !defined(HAVE_BZERO)
#define bzero(mem,size) memset(mem,0,size)
#endif

#if defined(IBERTY_LIB) && !defined(HAVE_MKSTEMP)
int mkstemps(char *template, int suffixlen);
#define mkstemp(template) mkstemps(template,0)
#endif

#ifdef __MINGW32__
#define pgettext(msgctxt,msgid) (msgid)
#define ngettext(singular,plural,number) (plural)
#else
#include "gettext.h"
#endif
#if defined(ENABLE_NLS) && defined(HAVE_LIBINTL_H)
#define _(String) gettext(String)
#ifdef gettext_noop
#define N_(String) gettext_noop(String)
#else
#define N_(String) (String)
#endif
#else /* No NLS */
#define _(String) (String)
#define N_(String) (String)
#endif //NLS

#if defined(__MINGW32__)
#define mkdir(p,m) _mkdir(p)

#ifndef WIFEXITED
  #define WIFEXITED(S) 1
#endif

#ifndef WEXITSTATUS
  #define WEXITSTATUS(S) (S)
#endif

#endif /*__MINGW32__*/

#ifndef __GNUC__
#  define  __attribute__(x)
#endif

#define MAXLEN 20000
#define MAX_URL_LEN 40000
#define MAX_TRUNCATED_URL 250
#define MAX_USER_LEN 256
#define MAX_USER_FNAME_LEN 128
#define MAX_IP_LEN 64
#define MAX_DATETIME_LEN 32
#define MAX_REDIRECTOR_LOGS 64
#define MAX_REDIRECTOR_FILELEN 1024
/*!
Arbitrary limit on the number of days that are accepted in the selected range of the log file.
Sarg will complain that there are too many days in the files if this limit is overrun.
*/
#define MAX_DATETIME_DAYS 1000

#define REPORT_TYPE_USERS_SITES         0x0001UL
#define REPORT_TYPE_SITE_USER_TIME_DATE 0x0002UL
#define REPORT_TYPE_TOPUSERS            0x0004UL
#define REPORT_TYPE_TOPSITES            0x0008UL
#define REPORT_TYPE_SITES_USERS         0x0010UL
#define REPORT_TYPE_DATE_TIME           0x0020UL
#define REPORT_TYPE_DENIED              0x0040UL
#define REPORT_TYPE_AUTH_FAILURES       0x0080UL
#define REPORT_TYPE_DOWNLOADS           0x0100UL
#define REPORT_TYPE_USERAGENT           0x0200UL

#define DATA_FIELD_USER      0x0001UL
#define DATA_FIELD_DATE      0x0002UL
#define DATA_FIELD_TIME      0x0004UL
#define DATA_FIELD_URL       0x0008UL
#define DATA_FIELD_CONNECT   0x0010UL
#define DATA_FIELD_BYTES     0x0020UL
#define DATA_FIELD_IN_CACHE  0x0040UL
#define DATA_FIELD_OUT_CACHE 0x0080UL
#define DATA_FIELD_ELAPSED   0x0100UL

#define TOPUSERFIELDS_NUM          0x0001UL
#define TOPUSERFIELDS_DATE_TIME    0x0002UL
#define TOPUSERFIELDS_USERID       0x0004UL
#define TOPUSERFIELDS_CONNECT      0x0008UL
#define TOPUSERFIELDS_BYTES        0x0010UL
#define TOPUSERFIELDS_SETYB        0x0020UL
#define TOPUSERFIELDS_IN_CACHE_OUT 0x0040UL
#define TOPUSERFIELDS_USED_TIME    0x0080UL
#define TOPUSERFIELDS_MILISEC      0x0100UL
#define TOPUSERFIELDS_PTIME        0x0200UL
#define TOPUSERFIELDS_TOTAL        0x0400UL
#define TOPUSERFIELDS_AVERAGE      0x0800UL
#define TOPUSERFIELDS_USERIP       0x1000UL

#define USERREPORTFIELDS_CONNECT      0x0001UL
#define USERREPORTFIELDS_BYTES        0x0002UL
#define USERREPORTFIELDS_SETYB        0x0004UL
#define USERREPORTFIELDS_IN_CACHE_OUT 0x0008UL
#define USERREPORTFIELDS_USED_TIME    0x0010UL
#define USERREPORTFIELDS_MILISEC      0x0020UL
#define USERREPORTFIELDS_PTIME        0x0040UL
#define USERREPORTFIELDS_TOTAL        0x0080UL
#define USERREPORTFIELDS_AVERAGE      0x0100UL

#define INDEX_YES  0x0001UL
#define INDEX_NO   0x0002UL
#define INDEX_ONLY 0x0004UL

#define INDEX_TREE_DATE 0x0001UL
#define INDEX_TREE_FILE 0x0002UL

#define INDEXFIELDS_DIRSIZE 0x0001UL

#define NTLMUSERFORMAT_USER       0x0001UL
#define NTLMUSERFORMAT_DOMAINUSER 0x0002UL

#define RECORDWITHOUTUSER_IP        0x0001UL
#define RECORDWITHOUTUSER_IGNORE    0x0002UL
#define RECORDWITHOUTUSER_EVERYBODY 0x0004UL

#define DATAFILEURL_IP   0x0001UL
#define DATAFILEURL_NAME 0x0002UL

#define DISPLAY_BYTES 0x0001UL
#define DISPLAY_ABBREV 0x0002UL

#define DATETIME_ELAP 0x0001UL
#define DATETIME_BYTE 0x0002UL

#define REALTIME_UNAUTH_REC_SHOW   0x0001UL
#define REALTIME_UNAUTH_REC_IGNORE 0x0002UL

#define SORT_REVERSE 0x0001

#define TOPUSER_SORT_REVERSE SORT_REVERSE
#define TOPUSER_SORT_BYTES   0x0002UL
#define TOPUSER_SORT_USER    0x0004UL
#define TOPUSER_SORT_CONNECT 0x0008UL
#define TOPUSER_SORT_TIME    0x0010UL

#define TOPSITE_SORT_REVERSE SORT_REVERSE
#define TOPSITE_SORT_BYTES   0x0002UL
#define TOPSITE_SORT_CONNECT 0x0004UL
#define TOPSITE_SORT_TIME    0x0008UL
#define TOPSITE_SORT_USER    0x0010UL

#define USER_SORT_REVERSE SORT_REVERSE
#define USER_SORT_BYTES   0x0002UL
#define USER_SORT_SITE    0x0004UL
#define USER_SORT_CONNECT 0x0008UL
#define USER_SORT_TIME    0x0010UL

//! Value to exclude all the javascripts from the html page.
#define HTML_JS_NONE 0x0000
//! Bit to include sorttable.js in the html plage.
#define HTML_JS_SORTTABLE 0x0001

//! The character prefixed in front of the host names that are aliased.
#define ALIAS_PREFIX '*'

//! Maximum number of limit files that can be stored.
#define MAX_USER_LIMITS 16

//! Name of the html file containing the index of a report file.
#define INDEX_HTML_FILE "index.html"

struct periodstruct
{
   //! The first date of the period.
   struct tm start;
   //! The last date of the period.
   struct tm end;
   //! The textual representation of the date.
   char text[90];
   //! The HTML representation of the date.
   char html[90];
};

char outdir[MAXLEN];
char outdirname[MAXLEN];
struct periodstruct period;
char code[MAXLEN];
char code2[MAXLEN];
char tmp[MAXLEN];
char parse_out[MAXLEN];
char html[MAXLEN];
char ConfigFile[MAXLEN];
char df;
int LastLog;
bool RemoveTempFiles;
char ReplaceIndex[256];
unsigned long int Index;
bool OverwriteReport;
unsigned long int RecordsWithoutUser;
bool UseComma;
char MailUtility[PATH_MAX];
int TopSitesNum;
int TopUsersNum;
char ExcludeCodes[256];
unsigned long int TopsitesSort;
unsigned long int ReportType;
char UserTabFile[255];
char warea[MAXLEN];
char name[MAXLEN];
bool LongUrl;
bool Ip2Name;
int AccessLogFromCmdLine;
char Title[MAXLEN];
char BgColor[MAXLEN];
char BgImage[MAXLEN];
char TxColor[MAXLEN];
char TxBgColor[MAXLEN];
char TiColor[MAXLEN];
char LogoImage[MAXLEN];
char LogoText[MAXLEN];
char LogoTextColor[MAXLEN];
char Width[MAXLEN];
char Height[MAXLEN];
char FontFace[MAXLEN];
char HeaderColor[MAXLEN];
char HeaderBgColor[MAXLEN];
char FontSize[MAXLEN];
char PasswdFile[MAXLEN];
char TempDir[MAXLEN];
char TempDirPath[MAXLEN];
char OutputDir[MAXLEN];
char OutputEmail[MAXLEN];
unsigned long int TopuserSort;
unsigned long int UserSort;
char module[255];
char ExcludeHosts[255];
char ExcludeUsers[255];
char DateFormat;
bool UserIp;
char MaxElapsed[255];
unsigned long int datetimeby;
char CharSet[255];
char UserInvalidChar[255];
bool Graphs;
char GraphDaysBytesBarColor[255];
bool Privacy;
char PrivacyString[255];
char PrivacyStringColor[30];
char IncludeUsers[MAXLEN];
char ExcludeString[MAXLEN];
bool SuccessfulMsg;
unsigned long int TopUserFields;
unsigned long int UserReportFields;
char DataFile[MAXLEN];
char DataFileDelimiter[3];
unsigned long int DataFileFields;
unsigned long int DataFileUrl;
//! if \c true, show the number of lines read from the input log file during the reading of the file.
bool ShowReadStatistics;
/*!
If \c true, the read statistics also includes the percent of the number of lines read.

Beware that it requires two readings of the input log file. It is not possible if the
input log file is stdin or a pipe.
*/
bool ShowReadPercent;
char IndexSortOrder[5];
char DansGuardianConf[MAXLEN];
bool DansguardianFilterOutDate;
char SquidGuardConf[MAXLEN];
char SquidGuarddbHome[255];
char RedirectorLogFormat[4096];
int NRedirectorLogs;
char RedirectorLogs[MAX_REDIRECTOR_LOGS][MAX_REDIRECTOR_FILELEN];
int RedirectorLogFromCmdLine;
bool RedirectorFilterOutDate;
bool ShowSargInfo;
bool BytesInSitesUsersReport;
bool ShowSargLogo;
char ParsedOutputLog[MAXLEN];
char ParsedOutputLogCompress[512];
unsigned long int DisplayedValues;
char HeaderFontSize[5];
char TitleFontSize[5];
char wwwDocumentRoot[MAXLEN];
char ExternalCSSFile[MAXLEN];
char BlockIt[255];
unsigned long int NtlmUserFormat;
//! How to display the index of the reports.
unsigned long int IndexTree;
//! The columns to show in the index of the reports.
unsigned long int IndexFields;
bool UserAuthentication;
char AuthUserTemplateFile[1024];
//! \c True to use anonymous file and directory names in the report.
bool AnonymousOutputFiles;
char val1[MAXLEN];
char val3[MAXLEN];
char val5[MAXLEN];
char val6[MAXLEN];
char val7[MAXLEN];
char val8[MAXLEN];
char val9[MAXLEN];
char val10[MAXLEN];
char val11[MAXLEN];
char mask[MAXLEN];
char site[MAXLEN];
char us[50];
char email[MAXLEN];
char test[1];
char user2[MAXLEN];
char wentp[512];
char addr[MAXLEN];
char Ulimit[6];
char RealtimeTypes[1024];
char cmd[255];
char ImageFile[255];
unsigned long int RealtimeUnauthRec;
char LDAPHost[255];
char LDAPBindDN[512];
char LDAPBindPW[255];
int LDAPPort;
int LDAPProtocolVersion;
char LDAPBaseSearch[255];
char LDAPFilterSearch[512];
char LDAPTargetAttr[64];
//! Character set to convert the LDAP returned string to.
char LDAPNativeCharset[20];
char GraphFont[MAXLEN];
//! The full path to sorttable.js if the table in the reports must be dynamicaly sorted.
char SortTableJs[256];
//! The name of the file containing the host names to replace by an alias in the report.
char HostAliasFile[512];
//! The name of the file containing the user names to replace by an alias in the report.
char UserAliasFile[512];
//! The number of consecutive errors allowed in an input log file before the process is interrupted.
int NumLogSuccessiveErrors;
/*!
The total number of errors allowed in an input log file before the process is interrupted. A negative
value means the process should never fails irrespective of the number of errors found in the input
log files.
*/
int NumLogTotalErrors;
//! Count the number of lines read from the input log files.
unsigned long int lines_read;
//! Count the number of records kept for the processing.
unsigned long int records_kept;
//! Count the number of users.
unsigned long int nusers;

int  idate;
int  dansguardian_count;
int  redirector_count;
int  useragent_count;
int  z1, z2, z3;
int  ttopen;
int  sarglog;
int  isalog;
bool dataonly;
bool indexonly;
bool iprel;
int  langcode;
int  debug;
int  debugz;
int  AuthfailReportLimit;
int  DeniedReportLimit;
int  DownloadReportLimit;
int  SiteUsersReportLimit;
int  DansGuardianReportLimit;
int  SquidGuardReportLimit;
int  UserReportLimit;
int  realtime_refresh;
int  realtime_access_log_lines;
int  rc;
int  ntopsites;
int  nrepday;
bool  squid24;
//! \c True to keep the temporary files for inspection.
bool KeepTempLog;

long long int nocost;
float cost;
