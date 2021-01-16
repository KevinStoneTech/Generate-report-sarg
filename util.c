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

// #define LEGACY_MY_ATOLL
// #define LEGACY_TESTVALIDUSERCHAR

#include "include/conf.h"
#include "include/defs.h"

#if defined(__MINGW32__) && defined(HAVE_DIRECT_H)
#define NO_OLDNAMES 1
#include <direct.h>
#endif

#if defined(HAVE_BACKTRACE)
#define USE_GETWORD_BACKTRACE 1
#else
#define USE_GETWORD_BACKTRACE 0
#endif

static char mtab1[12][4]={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};

//! The list of the HTTP codes to exclude from the report.
static char *excludecode=NULL;

//! Directory where the images are stored.
char ImageDir[MAXLEN]=IMAGEDIR;

extern char *CurrentLocale;

#if USE_GETWORD_BACKTRACE
static void getword_backtrace(void)
{
	void *buffer[5];
	int i, n;
	char **calls;

	n=backtrace(buffer,sizeof(buffer)/sizeof(buffer[0]));
	if (n<=0) return;
	calls=backtrace_symbols(buffer,n);
	if (calls) {
		debuga(__FILE__,__LINE__,_("getword backtrace:\n"));
		for (i=0 ; i<n ; i++) {
			fprintf(stderr,"SARG: %d:%s\n",i+1,calls[i]);
		}
		free(calls);
	}
}
#endif //USE_GETWORD_BACKTRACE

void getword_start(struct getwordstruct *gwarea, const char *line)
{
	gwarea->beginning=line;
	gwarea->current=line;
	gwarea->modified=0;
}

void getword_restart(struct getwordstruct *gwarea)
{
	if (gwarea->modified) {
		debuga(__FILE__,__LINE__,_("Cannot parse again the line as it was modified\n"));
		exit(EXIT_FAILURE);
	}
	gwarea->current=gwarea->beginning;
}

int getword(char *word, int limit, struct getwordstruct *gwarea, char stop)
{
	int x;

	for (x=0;((gwarea->current[x]) && (gwarea->current[x] != stop ));x++) {
		if (x>=limit) {
			/*
			 TRANSLATORS: The %s is the name of the function reporting the
			 error message.
			 */
			debuga(__FILE__,__LINE__,_("End of word not found in %s after %d bytes.\n"),__func__,x);
			debuga(__FILE__,__LINE__,_("Line=\"%s\"\n"),gwarea->beginning);
			debuga(__FILE__,__LINE__,_("Record=\"%s\"\n"),gwarea->current);
			debuga(__FILE__,__LINE__,_("searching for \'x%x\'\n"),stop);
			word[(limit>0) ? limit-1 : 0]='\0';
#if USE_GETWORD_BACKTRACE
			getword_backtrace();
#endif
			return(-1);
		}
		word[x] = gwarea->current[x];
	}

	word[x] = '\0';
	if (gwarea->current[x]) ++x;
	gwarea->current+=x;
	return(0);
}

int getword_limit(char *word, int limit, struct getwordstruct *gwarea, char stop)
{
	int x;

	limit--;
	for (x=0; x<limit && gwarea->current[x] && gwarea->current[x] != stop ;x++) {
		word[x] = gwarea->current[x];
	}
	word[x] = '\0';
	gwarea->current+=x;
	while (*gwarea->current && *gwarea->current != stop)  gwarea->current++;
	if (*gwarea->current) ++gwarea->current;
	return(0);
}

int getword_multisep(char *word, int limit, struct getwordstruct *gwarea, char stop)
{
	int x;

	for (x=0;((gwarea->current[x]) && (gwarea->current[x] != stop ));x++) {
		if (x>=limit) {
			debuga(__FILE__,__LINE__,_("End of word not found in %s after %d bytes.\n"),__func__,x);
			debuga(__FILE__,__LINE__,_("Line=\"%s\"\n"),gwarea->beginning);
			debuga(__FILE__,__LINE__,_("Record=\"%s\"\n"),gwarea->current);
			debuga(__FILE__,__LINE__,_("searching for \'x%x\'\n"),stop);
			if (limit>0) word[limit-1]='\0';
#if USE_GETWORD_BACKTRACE
			getword_backtrace();
#endif
			//exit(EXIT_FAILURE);
			return(-1);
		}
		word[x] = gwarea->current[x];
	}

	word[x] = '\0';
	while (gwarea->current[x] && gwarea->current[x]==stop) ++x;
	gwarea->current+=x;
	return(0);
}

int getword_skip(int limit, struct getwordstruct *gwarea, char stop)
{
	int x;

	for (x=0;(gwarea->current[x] && (gwarea->current[x] != stop ));x++) {
		if (x>=limit) {
			debuga(__FILE__,__LINE__,_("End of word not found in %s after %d bytes.\n"),__func__,x);
			debuga(__FILE__,__LINE__,_("Line=\"%s\"\n"),gwarea->beginning);
			debuga(__FILE__,__LINE__,_("Record=\"%s\"\n"),gwarea->current);
			debuga(__FILE__,__LINE__,_("searching for \'x%x\'\n"),stop);
#if USE_GETWORD_BACKTRACE
			getword_backtrace();
#endif
			return(-1);
		}
	}

	if (gwarea->current[x]) ++x;
	gwarea->current+=x;
	return(0);
}

int getword_atoll(long long int *number, struct getwordstruct *gwarea, char stop)
{
	int x;
	int sign=+1;
	int digit;

	if (gwarea->current[0] == '-') {
		gwarea->current++;
		sign=-1;
	} else if (gwarea->current[0] == '+') {
		gwarea->current++;
	}
	*number=0LL;
	for (x=0;isdigit(gwarea->current[x]);x++) {
		digit=gwarea->current[x]-'0';
		if (*number >= (LLONG_MAX-digit)/10) {
			/*
			 TRANSLATORS: The first %s is the function name (in the source code) where the
			 overflow is detected.
			*/
			debuga(__FILE__,__LINE__,_("Integer overflow detected in %s in line %s\n"),__func__,gwarea->beginning);
			return(-1);
		}
		*number=(*number * 10) + digit;
	}
	if (gwarea->current[x] && gwarea->current[x]!=stop) {
		/*
		 TRANSLATORS: The %s is the function name, in the source code, where the problem occured.
		*/
		debuga(__FILE__,__LINE__,_("End of number not found in %s after %d bytes.\n"),__func__,x);
		debuga(__FILE__,__LINE__,_("Line=\"%s\"\n"),gwarea->beginning);
		debuga(__FILE__,__LINE__,_("Record=\"%s\"\n"),gwarea->current);
		debuga(__FILE__,__LINE__,_("searching for \'x%x\'\n"),stop);
#if USE_GETWORD_BACKTRACE
		getword_backtrace();
#endif
		return(-1);
	}
	*number*=sign;

	if (gwarea->current[x]) ++x;
	gwarea->current+=x;
	return(0);
}

int getword_atoi(int *number, struct getwordstruct *gwarea, char stop)
{
	int x;
	int sign=+1;
	int digit;

	if (gwarea->current[0] == '-') {
		gwarea->current++;
		sign=-1;
	} else if (gwarea->current[0] == '+') {
		gwarea->current++;
	}
	*number=0;
	for (x=0;isdigit(gwarea->current[x]);x++) {
		digit=gwarea->current[x]-'0';
		if (*number > (INT_MAX-digit)/10) {
			debuga(__FILE__,__LINE__,_("Integer overflow detected in %s in line %s\n"),__func__,gwarea->beginning);
			return(-1);
		}
		*number=(*number * 10) + digit;
	}
	if (gwarea->current[x] && gwarea->current[x]!=stop) {
		debuga(__FILE__,__LINE__,_("End of number not found in %s after %d bytes.\n"),__func__,x);
		debuga(__FILE__,__LINE__,_("Line=\"%s\"\n"),gwarea->beginning);
		debuga(__FILE__,__LINE__,_("Record=\"%s\"\n"),gwarea->current);
		debuga(__FILE__,__LINE__,_("searching for \'x%x\'\n"),stop);
#if USE_GETWORD_BACKTRACE
		getword_backtrace();
#endif
		return(-1);
	}
	*number*=sign;

	if (gwarea->current[x]) ++x;
	gwarea->current+=x;
	return(0);
}

int getword_atol(long int *number, struct getwordstruct *gwarea, char stop)
{
	int x;
	long int sign=+1;
	int digit;

	if (gwarea->current[0] == '-') {
		gwarea->current++;
		sign=-1;
	} else if (gwarea->current[0] == '+') {
		gwarea->current++;
	}
	*number=0;
	for (x=0;isdigit(gwarea->current[x]);x++) {
		digit=gwarea->current[x]-'0';
		if (*number > (LONG_MAX-digit)/10) {
			debuga(__FILE__,__LINE__,_("Integer overflow detected in %s in line %s\n"),__func__,gwarea->beginning);
			return(-1);
		}
		*number=(*number * 10) + digit;
	}
	if (gwarea->current[x] && gwarea->current[x]!=stop) {
		debuga(__FILE__,__LINE__,_("End of number not found in %s after %d bytes.\n"),__func__,x);
		debuga(__FILE__,__LINE__,_("Line=\"%s\"\n"),gwarea->beginning);
		debuga(__FILE__,__LINE__,_("Record=\"%s\"\n"),gwarea->current);
		debuga(__FILE__,__LINE__,_("searching for \'x%x\'\n"),stop);
#if USE_GETWORD_BACKTRACE
		getword_backtrace();
#endif
		return(-1);
	}
	*number*=sign;

	if (gwarea->current[x]) ++x;
	gwarea->current+=x;
	return(0);
}

int getword_atolu(unsigned long int *number, struct getwordstruct *gwarea, char stop)
{
	int x;
	int digit;

	if (gwarea->current[0] == '-') {
		debuga(__FILE__,__LINE__,_("getword_atolu got a negative number.\n"));
		debuga(__FILE__,__LINE__,_("Line=\"%s\"\n"),gwarea->beginning);
		debuga(__FILE__,__LINE__,_("Record=\"%s\"\n"),gwarea->current);
		return(-1);
	}
	if (gwarea->current[0] == '+') {
		gwarea->current++;
	}
	*number=0;
	for (x=0;isdigit(gwarea->current[x]);x++) {
		digit=gwarea->current[x]-'0';
		if (*number > (ULONG_MAX-digit)/10) {
			debuga(__FILE__,__LINE__,_("Integer overflow detected in %s in line %s\n"),__func__,gwarea->beginning);
			return(-1);
		}
		*number=(*number * 10) + digit;
	}
	if (gwarea->current[x] && gwarea->current[x]!=stop) {
		debuga(__FILE__,__LINE__,_("End of number not found in %s after %d bytes.\n"),__func__,x);
		debuga(__FILE__,__LINE__,_("Line=\"%s\"\n"),gwarea->beginning);
		debuga(__FILE__,__LINE__,_("Record=\"%s\"\n"),gwarea->current);
		debuga(__FILE__,__LINE__,_("searching for \'x%x\'\n"),stop);
#if USE_GETWORD_BACKTRACE
		getword_backtrace();
#endif
		return(-1);
	}

	if (gwarea->current[x]) ++x;
	gwarea->current+=x;
	return(0);
}


int getword_ptr(char *orig_line,char **word, struct getwordstruct *gwarea, char stop)
{
	/*!
	\note Why pass the original buffer to the function ? Because we must modify it to
	insert the terminating ASCII zero for the word we return and that's not compatible
	with getword_restart(). Moreover, getword_start() sometime works on constant strings
	so this function require the original buffer to detect any missuse.
	*/
	int x;
	int sep;
	int start;

	if (orig_line && orig_line!=gwarea->beginning) {
		debuga(__FILE__,__LINE__,_("Invalid buffer passed to getword_ptr\n"));
		return(-1);
	}

	start=(gwarea->current-gwarea->beginning);
	if (word && orig_line) *word=orig_line+start;
	for (x=0;((gwarea->current[x]) && (gwarea->current[x] != stop ));x++);
	sep=(gwarea->current[x]!='\0');
	if (word && orig_line) orig_line[start+x] = '\0';
	if (sep) ++x;
	gwarea->current+=x;
	gwarea->modified=1;
	return(0);
}

#define MAXLLL 30 //!< Maximum number of digits in long long (a guess).
long long int my_atoll (const char *nptr)
{
	long long int returnval=0LL;
	int max_digits = MAXLLL ;

	// Soak up all the white space
	while (isspace( *nptr )) {
		nptr++;
	}

	//For each character left to right
	//change the character to a single digit
	//multiply what we had before by 10 and add the new digit

	while (--max_digits && isdigit( *nptr ))
	{
		returnval = ( returnval * 10 ) + ( *nptr++ - '0' ) ;
	}

	return returnval;
}

int is_absolute(const char *path)
{
	if (*path=='/') return(1);
#ifdef _WIN32
	if (isalpha(path[0]) && path[1]==':') return(1);
#endif
	return(0);
}

int PortableMkDir(const char *path,int mode)
{
#if defined(__linux__)
	int mkerror=mkdir(path,mode);
#else //mingw
	(void)mode;
	int mkerror=_mkdir(path);
#endif
	return(mkerror);
}

/*!
 * Recursively create a path by adding missing directory until the whole path is created.
 * \param name The path to create.
 * \return True if the directory was created or false if it already existed
 */
bool my_mkdir(const char *name)
{
	char w0[MAXLEN];
	int i;
	int chars;
	bool created = false;
	struct stat st;

	if (!is_absolute(name)) {
		debuga(__FILE__,__LINE__,_("Invalid path (%s). Please, use absolute paths only.\n"),name);
		exit(EXIT_FAILURE);
	}

	chars=0;
	for (i=0 ; name[i] ; i++) {
		if (i>=sizeof(w0)) {
			debuga(__FILE__,__LINE__,_("Path too long: "));
			debuga_more("%s\n",name);
			exit(EXIT_FAILURE);
		}
		if (chars>0 && name[i] == '/') {
			w0[i] = '\0';
			if (access(w0, R_OK) != 0) {
				if (PortableMkDir(w0,0755)) {
					debuga(__FILE__,__LINE__,_("Cannot create directory \"%s\": %s\n"),w0,strerror(errno));
					exit(EXIT_FAILURE);
				}
			}
		}
		if (name[i] != '/') chars++;
		w0[i] = name[i];
	}

	if (access(name, R_OK) != 0) {
		if (PortableMkDir(name,0755)) {
			debuga(__FILE__,__LINE__,_("Cannot create directory \"%s\": %s\n"),name,strerror(errno));
			exit(EXIT_FAILURE);
		}
		created = true;
	}
	if (!created) {
		/*
		 * Check the final path is a directory (symlink to a directory is ok).
		 */
		if (stat(name, &st)) {
			debuga(__FILE__,__LINE__,_("Cannot stat \"%s\": %s\n"), name, strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (!S_ISDIR(st.st_mode)) {
			debuga(__FILE__,__LINE__,_("Directory \"%s\" can't be created because the path already exists and is not a directory\n"), name);
			exit(EXIT_FAILURE);
		}
	}
	return created;
}

void makeTmpDir(const char *tmp)
{
	/*
	 * We must ensure the temporary directory is ours. In particular, we must make sure no malicious
	 * users managed to create or replace the temporary directory with a symlink to a system directory.
	 * As sarg purges the content of the temporary directory upon exit, should the temporary directory
	 * be hijacked, sarg could be tricked in deleting system files such as /bin or users files in /home
	 * or logs in /var/log.
	 *
	 * The code first create the temporary directory. If it wasn't created, the content is checked and
	 * purged if it looks safe to delete every file and directory it contains.
	 */
	if (!my_mkdir(tmp)) {
		if (debug) debuga(__FILE__, __LINE__, _("Purging temporary directory \"%s\"\n"), tmp);
		emptytmpdir(tmp);
	}
}

void my_lltoa(unsigned long long int n, char *s, int ssize, int len)
{
	int i;
	int slen = 0;
	int j;
	char c;

	ssize--;
	if (len>ssize) {
		debuga(__FILE__,__LINE__,_("The requested number of digits passed to my_lltoa (%d) is bigger than the output buffer size (%d)\n"),len,ssize);
		abort();
	}

	do {
		s[slen++] = (n % 10) + '0';
	} while ((n /= 10) > 0 && slen<ssize);
	s[slen] = '\0';

	for (i = 0, j = slen-1; i<j; i++, j--) {
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}

	if (len>slen) {
		i=len-slen;
		for (j=slen; j>=0; j--)
			s[j+i]=s[j];
		for (j=0 ; j<i ; j++)
			s[j]='0';
	}
}

int month2num(const char *month)
{
	int m;

	for (m=0 ; m<12 && strcmp(mtab1[m],month) != 0; m++);
	return(m);
}

int builddia(int day, int month, int year)
{
	return(year*10000+month*100+day);
}

/*!
Compare two dates.

\param date1 The first date to compare.
\param date2 The second date to compare.

\retval -1 If date1<date2.
\retval 0 If date1==date2.
\retval 1 if date1>date2.
*/
int compare_date(const struct tm *date1,const struct tm *date2)
{
	if (date1->tm_year<date2->tm_year) return(-1);
	if (date1->tm_year>date2->tm_year) return(1);
	if (date1->tm_mon<date2->tm_mon) return(-1);
	if (date1->tm_mon>date2->tm_mon) return(1);
	if (date1->tm_mday<date2->tm_mday) return(-1);
	if (date1->tm_mday>date2->tm_mday) return(1);
	if (date1->tm_hour<date2->tm_hour) return(-1);
	if (date1->tm_hour>date2->tm_hour) return(1);
	if (date1->tm_min<date2->tm_min) return(-1);
	if (date1->tm_min>date2->tm_min) return(1);
	if (date1->tm_sec<date2->tm_sec) return(-1);
	if (date1->tm_sec>date2->tm_sec) return(1);
	return(0);
}

void buildymd(const char *dia, const char *mes, const char *ano, char *wdata,int wdata_size)
{
	int nmes;

	nmes=month2num(mes);
	snprintf(wdata,wdata_size,"%04d%02d%02d",atoi(ano),nmes+1,atoi(dia));
}


int conv_month(const char *month)
{
	int  x;

	for (x=0; x<12 && strncmp(mtab1[x],month,3)!=0; x++);
	return(x+1);
}


const char *conv_month_name(int month)
{
	static char str[4];

	if (month<1 || month>12) {
		snprintf(str,sizeof(str),"%03d",month);
		return(str);
	}
	return(mtab1[month-1]);
}

/*!
Write a debug message to stderr. The message is prefixed by "SARG:" to identify its origin.

\param msg The printf like message to format.
\param ... The arguments to format in the message.
*/
void debuga(const char *File,int Line,const char *msg,...)
{
	va_list ap;

	if (debugz>=LogLevel_Source) {
		/* The path is removed because every source file is in the same directory.
		 * There is no point in reporting the full path from the build directory.
		 */
		const char *ptr=strrchr(File,'/');
		if (!ptr) ptr=File;
		/* TRANSLATORS: This is the prefix to stderr messages when the debug level is
		 set to display the source file (%s) and the line number (%d). */
		fprintf(stderr,_("SARG(%s:%d): "),ptr,Line);
	} else {
		/* TRANSLATORS: This is the prefix to stderr messages when the debug level
		 is low. */
		fputs(_("SARG: "),stderr);
	}
	va_start(ap,msg);
	vfprintf(stderr,msg,ap);
	va_end(ap);
}

/*!
Write a debug message to stderr. The message is supposed
to be displayed after a message from debuga().

\param msg The printf like message to format.
\param ... The arguments to format in the message.
*/
void debuga_more(const char *msg,...)
{
	va_list ap;

	va_start(ap,msg);
	vfprintf(stderr,msg,ap);
	va_end(ap);
}

/*!
Write a debug message to stderr. The message is prefixed by "SARG: (info)".

\param msg The printf like message to format.
\param ... The arguments to format in the message.
*/
void debugaz(const char *File,int Line,const char *msg,...)
{
	va_list ap;

	if (debugz>=LogLevel_Source) {
		/* The path is removed because every source file is in the same directory.
		 * There is no point in reporting the full path from the build directory.
		 */
		const char *ptr=strrchr(File,'/');
		if (!ptr) ptr=File;
		/* TRANSLATORS: This is the prefix to information messages when the debug level is
		 set to display the source file (%s) and the line number (%d). */
		fprintf(stderr,_("SARG(%s:%d): (info) "),ptr,Line);
	} else {
		/* TRANSLATORS: This is the prefix to information messages when the debug level
		 is low. */
		fputs(_("SARG: (info) "),stderr);
	}
	va_start(ap,msg);
	vfprintf(stderr,msg,ap);
	va_end(ap);
}


char *fixnum(long long int value, int n)
{
#define MAXLEN_FIXNUM 256
	char num[MAXLEN_FIXNUM]="";
	char buf[MAXLEN_FIXNUM * 2];
	char *pbuf;
	static char ret[MAXLEN_FIXNUM * 2];
	char *pret;
	register int i, j, k;
	int numlen;
	static char abbrev[30]="";

	my_lltoa(value, num, sizeof(num), 0);

	if (DisplayedValues==DISPLAY_ABBREV) {
		numlen = strlen(num);
		if (numlen <= 3)
			strcpy(abbrev,num);
		else if (numlen%3 == 1) {
			abbrev[0]=num[0];
			abbrev[1]=(UseComma) ? ',' : '.';
			abbrev[2]=num[1];
			abbrev[3]=num[2];
			abbrev[4]='\0';
		}
		else if (numlen%3 == 2) {
			abbrev[0]=num[0];
			abbrev[1]=num[1];
			abbrev[2]=(UseComma) ? ',' : '.';
			abbrev[3]=num[2];
			abbrev[4]=num[3];
			abbrev[5]='\0';
		}
		else if (numlen%3 == 0) {
			abbrev[0]=num[0];
			abbrev[1]=num[1];
			abbrev[2]=num[2];
			abbrev[3]=(UseComma) ? ',' : '.';
			abbrev[4]=num[3];
			abbrev[5]=num[4];
			abbrev[6]='\0';
		}
		if (n) {
			if (numlen <= 3) {
				//no prefix
			}
			else if (numlen <= 6)
				strcat(abbrev,"K");
			else if (numlen <= 9)
				strcat(abbrev,"M");
			else if (numlen <= 12)
				strcat(abbrev,"G");
			else if (numlen <= 15)
				strcat(abbrev,"T");
			else if (numlen >= 18)
				strcat(abbrev,"P");
			else if (numlen <= 21)
				strcat(abbrev,"E");
			else if (numlen <= 24)
				strcat(abbrev,"Z");
			else if (numlen <= 27)
				strcat(abbrev,"Y");
			else
				strcat(abbrev,"???");
		}
		return(abbrev);
	}

	memset(buf,0,MAXLEN_FIXNUM*2);

	pbuf = buf;
	pret = ret;
	k = 0;

	for ( i = strlen(num) - 1, j = 0 ; i > -1; i--) {
		if ( k == 2 && i != 0 )  {
			k = 0;
			pbuf[j++] = num[i];
			pbuf[j++] = (UseComma) ? ',' : '.';
			continue;
		}
		pbuf[j] = num[i];
		j++;
		k++;
	}

	pret[0]='\0';

	for ( i = strlen(pbuf) - 1, j = 0 ; i > -1; i--, j++)
		pret[j] = pbuf[i];

	pret[j] = '\0';

	return pret;
}


char *fixnum2(long long int value, int n)
{
#define MAXLEN_FIXNUM2 1024
	char num[MAXLEN_FIXNUM2];
	char buf[MAXLEN_FIXNUM2 * 2];
	char *pbuf;
	static char ret[MAXLEN_FIXNUM2 * 2];
	char *pret;
	register int i, j, k;

	my_lltoa(value, num, sizeof(num), 0);
	memset(buf,0,MAXLEN_FIXNUM2*2);

	pbuf = buf;
	pret = ret;
	k = 0;

	for ( i = strlen(num) - 1, j = 0 ; i > -1; i--) {
		if ( k == 2 && i != 0 )  {
			k = 0;
			pbuf[j++] = num[i];
			pbuf[j++] = (UseComma) ? ',' : '.';
			continue;
		}
		pbuf[j] = num[i];
		j++;
		k++;
	}

	pret[0]='\0';

	for ( i = strlen(pbuf) - 1, j = 0 ; i > -1; i--, j++)
		pret[j] = pbuf[i];

	pret[j] = '\0';

	return pret;
}


char *buildtime(long long int elap)
{
	long int num = elap / 1000LL;
	int hor = 0;
	int min = 0;
	int sec = 0;
	static char buf[20];

	hor=num / 3600L;
	min=(num % 3600L) / 60L;
	sec=num % 60L;
	snprintf(buf,sizeof(buf),"%02d:%02d:%02d",hor,min,sec);

	return(buf);
}


/*!
Get the date stored in the <tt>sarg-date</tt> file of a directory with the connection data.

\param dirname The directory to look for the connection directory.
\param name The name of the directory whose <tt>sarg-date</tt> file must be read.
\param data The buffer to store the content of the file. It must be more than 80
bytes long.

\retval 0 No error.
\retval -1 File not found.
*/
int obtdate(const char *dirname, const char *name, char *data)
{
	FILE *fp_in;
	char wdir[MAXLEN];

	if (snprintf(wdir,sizeof(wdir),"%s%s/sarg-date",dirname,name)>=sizeof(wdir)) {
		debuga(__FILE__,__LINE__,_("Buffer too small to store "));
		debuga_more("%s%s/sarg-date",dirname,name);
		exit(EXIT_FAILURE);
	}
	if ((fp_in = fopen(wdir, "rt")) == 0) {
		if (snprintf(wdir,sizeof(wdir),"%s%s/date",dirname,name)>=sizeof(wdir)) {
			debuga(__FILE__,__LINE__,_("Buffer too small to store "));
			debuga_more("%s%s/date",dirname,name);
			exit(EXIT_FAILURE);
		}
		if ((fp_in = fopen(wdir, "rt")) == 0) {
			data[0]='\0';
			return(-1);
		}
	}

	if (!fgets(data,80,fp_in)) {
		debuga(__FILE__,__LINE__,_("Failed to read the date in file \"%s\"\n"),wdir);
		exit(EXIT_FAILURE);
	}
	if (fclose(fp_in)==EOF) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),wdir,strerror(errno));
		exit(EXIT_FAILURE);
	}
	fixendofline(data);

	return(0);
}


void formatdate(char *date,int date_size,int year,int month,int day,int hour,int minute,int second,int dst)
{
	struct tm ltm;
	time_t unixtime;
	struct tm *fulltm;

	memset(&ltm,0,sizeof(ltm));
	if (year>=1900) ltm.tm_year=year-1900;
	if (month>=1 && month<=12) ltm.tm_mon=month-1;
	if (day>=1 && day<=31) ltm.tm_mday=day;
	if (hour>=0 && hour<24) ltm.tm_hour=hour;
	if (minute>=0 && minute<60) ltm.tm_min=minute;
	if (second>=0 && second<60) ltm.tm_sec=second;
	ltm.tm_isdst=dst;
	unixtime=mktime(&ltm); //fill the missing entries
	fulltm=localtime(&unixtime);
	//strftime(date,date_size,"%a %b %d %H:%M:%S %Z %Y",fulltm);
	strftime(date,date_size,"%c",fulltm);
}


void computedate(int year,int month,int day,struct tm *t)
{
	memset(t,0,sizeof(*t));
	t->tm_year=year-1900;
	t->tm_mon=month-1;
	t->tm_mday=day;
}


int obtuser(const char *dirname, const char *name)
{
	FILE *fp_in;
	char wdir[MAXLEN];
	char tuser[20];
	int nuser;

	if (snprintf(wdir,sizeof(wdir),"%s%s/sarg-users",dirname,name)>=sizeof(wdir)) {
		debuga(__FILE__,__LINE__,_("Buffer too small to store "));
		debuga_more("%s%s/sarg-users",dirname,name);
		exit(EXIT_FAILURE);
	}
	if ((fp_in=fopen(wdir,"r"))==NULL) {
		if (snprintf(wdir,sizeof(wdir),"%s%s/users",dirname,name)>=sizeof(wdir)) {
			debuga(__FILE__,__LINE__,_("Buffer too small to store "));
			debuga_more("%s%s/users",dirname,name);
			exit(EXIT_FAILURE);
		}
		if ((fp_in=fopen(wdir,"r"))==NULL) {
			return(0);
		}
	}

	if (!fgets(tuser,sizeof(tuser),fp_in)) {
		debuga(__FILE__,__LINE__,_("Failed to read the number of users in file \"%s\"\n"),wdir);
		exit(EXIT_FAILURE);
	}
	if (fclose(fp_in)==EOF) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),wdir,strerror(errno));
		exit(EXIT_FAILURE);
	}
	nuser=atoi(tuser);

	return(nuser);
}


void obttotal(const char *dirname, const char *name, int nuser, long long int *tbytes, long long int *media)
{
	FileObject *fp_in;
	char *buf;
	char wdir[MAXLEN];
	char user[MAX_USER_LEN];
	char sep;
	struct getwordstruct gwarea;
	longline line;

	*tbytes=0;
	*media=0;

	if (snprintf(wdir,sizeof(wdir),"%s%s/sarg-general",dirname,name)>=sizeof(wdir)) {
		debuga(__FILE__,__LINE__,_("Buffer too small to store "));
		debuga_more("%s%s/sarg-general",dirname,name);
		exit(EXIT_FAILURE);
	}
	if ((fp_in = FileObject_Open(wdir)) == NULL) {
		if (snprintf(wdir,sizeof(wdir),"%s%s/general",dirname,name)>=sizeof(wdir)) {
			debuga(__FILE__,__LINE__,_("Buffer too small to store "));
			debuga_more("%s%s/general",dirname,name);
			exit(EXIT_FAILURE);
		}
		if ((fp_in = FileObject_Open(wdir)) == NULL) {
			return;
		}
	}

	if ((line=longline_create())==NULL) {
		debuga(__FILE__,__LINE__,_("Not enough memory to read file \"%s\"\n"),wdir);
		exit(EXIT_FAILURE);
	}

	while((buf=longline_read(fp_in,line))!=NULL) {
		if (strncmp(buf,"TOTAL\t",6) == 0)
			sep='\t'; //new file
		else if (strncmp(buf,"TOTAL ",6) == 0)
			sep=' '; //old file
		else
			continue;
		getword_start(&gwarea,buf);
		if (getword(user,sizeof(user),&gwarea,sep)<0) {
			debuga(__FILE__,__LINE__,_("Invalid user in file \"%s\"\n"),wdir);
			exit(EXIT_FAILURE);
		}
		if (strcmp(user,"TOTAL") != 0)
			continue;
		if (getword_skip(MAXLEN,&gwarea,sep)<0) {
			debuga(__FILE__,__LINE__,_("Invalid total number of accesses in file \"%s\"\n"),wdir);
			exit(EXIT_FAILURE);
		}
		if (getword_atoll(tbytes,&gwarea,sep)<0) {
			debuga(__FILE__,__LINE__,_("Invalid number of bytes in file \"%s\"\n"),wdir);
			exit(EXIT_FAILURE);
		}
		break;
	}
	if (FileObject_Close(fp_in)) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),wdir,FileObject_GetLastCloseError());
		exit(EXIT_FAILURE);
	}
	longline_destroy(&line);

	if (nuser <= 0)
		return;

	*media=*tbytes / nuser;
	return;
}

int getperiod_fromsarglog(const char *arqtt,struct periodstruct *period)
{
	const char *str;
	int day0, month0, year0, hour0, minute0;
	int day1, month1, year1, hour1, minute1;
	int i;

	memset(period,0,sizeof(*period));

	str=arqtt;
	while((str=strstr(str,"sarg-"))!=NULL) {
		str+=5;
		if (!isdigit(str[0]) || !isdigit(str[1])) continue;
		day0=(str[0]-'0')*10+(str[1]-'0');
		if (day0<1 || day0>31) continue;
		str+=2;
		month0=(str[0]-'0')*10+(str[1]-'0')-1;
		if (month0<0 || month0>11) continue;
		str+=2;
		year0=0;
		for (i=0 ; isdigit(str[i]) && i<4 ; i++) year0=year0*10+(str[i]-'0');
		if (i!=4 || year0<1900) continue;
		str+=4;
		if (str[0]!='_') continue;
		str++;

		if (!isdigit(str[0]) || !isdigit(str[1])) continue;
		hour0=(str[0]-'0')*10+(str[1]-'0');
		str+=2;
		if (!isdigit(str[0]) || !isdigit(str[1])) continue;
		minute0=(str[0]-'0')*10+(str[1]-'0');
		str+=2;

		if (*str != '-') continue;
		str++;

		if (!isdigit(str[0]) || !isdigit(str[1])) continue;
		day1=(str[0]-'0')*10+(str[1]-'0');
		if (day1<1 || day1>31) continue;
		str+=2;
		month1=(str[0]-'0')*10+(str[1]-'0')-1;
		if (month1<0 || month1>11) continue;
		str+=2;
		year1=0;
		for (i=0 ; isdigit(str[i]) && i<4 ; i++) year1=year1*10+(str[i]-'0');
		if (i!=4 || year1<1900) continue;
		str+=4;

		if (str[0]!='_') continue;
		str++;

		if (!isdigit(str[0]) || !isdigit(str[1])) continue;
		hour1=(str[0]-'0')*10+(str[1]-'0');
		str+=2;
		if (!isdigit(str[0]) || !isdigit(str[1])) continue;
		minute1=(str[0]-'0')*10+(str[1]-'0');
		str+=2;

		period->start.tm_mday=day0;
		period->start.tm_mon=month0;
		period->start.tm_year=year0-1900;
		period->start.tm_hour=hour0;
		period->start.tm_min=minute0;
		period->end.tm_mday=day1;
		period->end.tm_mon=month1;
		period->end.tm_year=year1-1900;
		period->end.tm_hour=hour1;
		period->end.tm_min=minute1;
		return(0);
	}
	return(-1);
}

/*!
Fill the period with the specified range.

\param period The period to change.
\param ReadFilter Filter containing the date range to write into the period.
*/
void getperiod_fromrange(struct periodstruct *period,const struct ReadLogDataStruct *ReadFilter)
{
	int dfrom=ReadFilter->StartDate;
	int duntil=ReadFilter->EndDate;

	memset(&period->start,0,sizeof(period->start));
	period->start.tm_mday=dfrom%100;
	period->start.tm_mon=(dfrom/100)%100-1;
	period->start.tm_year=(dfrom/10000)-1900;

	memset(&period->end,0,sizeof(period->end));
	period->end.tm_mday=duntil%100;
	period->end.tm_mon=(duntil/100)%100-1;
	period->end.tm_year=(duntil/10000)-1900;
}

/*!
Get the range from a period.

\param period The period to convert to a range.
\param dfrom The variable to store the range beginning. It can be NULL.
\param duntil The variable to store the range end. It can be NULL.
*/
void getperiod_torange(const struct periodstruct *period,int *dfrom,int *duntil)
{
	if (dfrom)
		*dfrom=(period->start.tm_year+1900)*10000+(period->start.tm_mon+1)*100+period->start.tm_mday;
	if (duntil)
		*duntil=(period->end.tm_year+1900)*10000+(period->end.tm_mon+1)*100+period->end.tm_mday;
}

/*!
Update the \a main period to encompass the period in \a candidate.
*/
void getperiod_merge(struct periodstruct *main,struct periodstruct *candidate)
{
	int cdate;
	int mdate;

	mdate=(main->start.tm_year)*10000+(main->start.tm_mon)*100+main->start.tm_mday;
	cdate=(candidate->start.tm_year)*10000+(candidate->start.tm_mon)*100+candidate->start.tm_mday;
	if (mdate==0 || cdate<mdate) memcpy(&main->start,&candidate->start,sizeof(struct tm));

	mdate=(main->end.tm_year)*10000+(main->end.tm_mon)*100+main->end.tm_mday;
	cdate=(candidate->end.tm_year)*10000+(candidate->end.tm_mon)*100+candidate->end.tm_mday;
	if (cdate>mdate) memcpy(&main->end,&candidate->end,sizeof(struct tm));
}

int getperiod_buildtext(struct periodstruct *period)
{
	int i;
	int range;
	char text1[40], text2[40];

	if (df=='u') {
		i=strftime(text1, sizeof(text1), "%Y %b %d", &period->start);
	} else if (df=='e') {
		i=strftime(text1, sizeof(text1), "%d %b %Y", &period->start);
	} else /*if (df=='w')*/ {
		IndexTree=INDEX_TREE_FILE;
		i=strftime(text1, sizeof(text1), "%Y.%U", &period->start);
	}
	if (i == 0) return(-1);

	range=(period->start.tm_year!=period->end.tm_year ||
	       period->start.tm_mon!=period->end.tm_mon ||
	       period->start.tm_mday!=period->end.tm_mday);
	if (range) {
		if (df=='u') {
			i=strftime(text2, sizeof(text2)-i, "%Y %b %d", &period->end);
		} else if (df=='e') {
			i=strftime(text2, sizeof(text2)-i, "%d %b %Y", &period->end);
		} else {
			i=strftime(text2, sizeof(text2)-i, "%Y.%U", &period->end);
		}
		if (i == 0) return(-1);
	}

	if (range) {
		snprintf(period->text,sizeof(period->text),"%s-%s",text1,text2);
		snprintf(period->html,sizeof(period->html),"%s&mdash;%s",text1,text2);
	} else {
		safe_strcpy(period->text,text1,sizeof(period->text));
		safe_strcpy(period->html,text1,sizeof(period->html));
	}
	return(0);
}

static void copy_images(void)
{
	FILE *img_in, *img_ou;
	char images[512];
	char srcfile[MAXLEN];
	char dstfile[MAXLEN];
	DIR *dirp;
	struct dirent *direntp;
	char buffer[MAXLEN];
	size_t nread;
	struct stat info;

	if (snprintf(images,sizeof(images),"%simages",outdir)>=sizeof(images)) {
		debuga(__FILE__,__LINE__,_("Cannot copy images to target directory %simages\n"),outdir);
		exit(EXIT_FAILURE);
	}
	if (access(images,R_OK)!=0) {
		if (PortableMkDir(images,0755)) {
			debuga(__FILE__,__LINE__,_("Cannot create directory \"%s\": %s\n"),images,strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	dirp = opendir(ImageDir);
	if (dirp==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open directory \"%s\": %s\n"),ImageDir,strerror(errno));
		return;
	}
	while ((direntp = readdir( dirp )) != NULL ){
		if (direntp->d_name[0]=='.')
			continue;
		if (snprintf(srcfile,sizeof(srcfile),"%s/%s",ImageDir,direntp->d_name)>=sizeof(srcfile)) {
			debuga(__FILE__,__LINE__,_("Buffer too small to store "));
			debuga_more("%s/%s",ImageDir,direntp->d_name);
			exit(EXIT_FAILURE);
		}
		if (stat(srcfile,&info)) {
			debuga(__FILE__,__LINE__,_("Cannot stat \"%s\": %s\n"),srcfile,strerror(errno));
			continue;
		}
		if (S_ISREG(info.st_mode)) {
			if (snprintf(dstfile,sizeof(dstfile),"%s/%s",images,direntp->d_name)>=sizeof(dstfile)) {
				debuga(__FILE__,__LINE__,_("Buffer too small to store "));
				debuga_more("%s/%s",images,direntp->d_name);
				exit(EXIT_FAILURE);
			}
			img_in = fopen(srcfile, "rb");
			if (img_in!=NULL) {
				img_ou = fopen(dstfile, "wb");
				if (img_ou!=NULL) {
					while ((nread = fread(buffer,1,sizeof(buffer),img_in))>0) {
						if (fwrite(buffer,1,nread,img_ou)!=nread) {
							debuga(__FILE__,__LINE__,_("Failed to copy image \"%s\" to \"%s\"\n"),srcfile,dstfile);
							break;
						}
					}
					if (fclose(img_ou)==EOF) {
						debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),dstfile,strerror(errno));
						exit(EXIT_FAILURE);
					}
				} else
					debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"), dstfile, strerror(errno));
				if (fclose(img_in)==EOF) {
					debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),srcfile,strerror(errno));
					exit(EXIT_FAILURE);
				}
			} else
				debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"), srcfile, strerror(errno));
		}
	}
	(void) closedir(dirp);

	return;
}

/*!
 * Check if the proposed file name conforms to the directory structure layed out
 * as a file tree. It is used to check if the file name enumerated while scanning
 * a directory content may have been created by sarg running with IndexTree set to
 * INDEX_TREE_FILE.
 */
bool IsTreeFileDirName(const char *Name)
{
	char DateFormat;
	int i;

	// start year (date format u) or start day (date format e)
	if (!isdigit(Name[0]) || !isdigit(Name[1])) return(false);

	if (isdigit(Name[2]) && isdigit(Name[3]))
	{
		// date format is either u or w
		if (Name[4]=='.')
		{
			// date format is w
			if (!isdigit(Name[5]) || !isdigit(Name[6])) return(false);
			return(true);//date format w is confirmed
		}

		// date format is u
		Name+=4;

		// start month
		if (!isalpha(Name[0]) || !isalpha(Name[1]) || !isalpha(Name[2])) return(false);
		for (i=11 ; i>=0 && memcmp(mtab1[i],Name,3) ; i--);
		if (i<0) return(false);
		Name+=3;

		// start day
		if (!isdigit(Name[0]) || !isdigit(Name[1])) return(false);
		Name+=2;

		DateFormat='u';
	}
	else if (isalpha(Name[2]) && isalpha(Name[3]) && isalpha(Name[4]))
	{
		// date format is e
		Name+=2;

		// start month
		if (!isalpha(Name[0]) || !isalpha(Name[1]) || !isalpha(Name[2])) return(false);
		for (i=11 ; i>=0 && memcmp(mtab1[i],Name,3) ; i--);
		if (i<0) return(false);
		Name+=3;

		// start day
		if (!isdigit(Name[0]) || !isdigit(Name[1]) || !isdigit(Name[2]) || !isdigit(Name[3])) return(false);
		Name+=4;

		DateFormat='e';
	}
	else
		return(false);

	if (Name[0]!='-') return(false);
	Name++;

	if (DateFormat=='u')
	{
		if (!isdigit(Name[0]) || !isdigit(Name[1]) || !isdigit(Name[2]) || !isdigit(Name[3])) return(false);
		Name+=4;

		if (!isalpha(Name[0]) || !isalpha(Name[1]) || !isalpha(Name[2])) return(false);
		for (i=11 ; i>=0 && memcmp(mtab1[i],Name,3) ; i--);
		if (i<0) return(false);
		Name+=3;

		if (!isdigit(Name[0]) || !isdigit(Name[1])) return(false);
		Name+=2;
	}
	else //DateFormat=='e'
	{
		if (!isdigit(Name[0]) || !isdigit(Name[1])) return(false);
		Name+=2;

		if (!isalpha(Name[0]) || !isalpha(Name[1]) || !isalpha(Name[2])) return(false);
		for (i=11 ; i>=0 && memcmp(mtab1[i],Name,3) ; i--);
		if (i<0) return(false);
		Name+=3;

		if (!isdigit(Name[0]) || !isdigit(Name[1]) || !isdigit(Name[2]) || !isdigit(Name[3])) return(false);
		Name+=4;
	}
	/*
	 * The directory name may contains additional characters such as a counter if
	 * a previous report is never overwritten.
	 */
	return(true);
}

/*!
 * Check if the proposed file name can be the year part of a report tree build with
 * IndexTree set to INDEX_TREE_DATE.
 */
bool IsTreeYearFileName(const char *Name)
{
	if (!isdigit(Name[0]) || !isdigit(Name[1]) || !isdigit(Name[2]) || !isdigit(Name[3])) return(false);
	Name+=4;
	if (Name[0]=='-')
	{
		Name++;
		if (!isdigit(Name[0]) || !isdigit(Name[1]) || !isdigit(Name[2]) || !isdigit(Name[3])) return(false);
		Name+=4;
	}
	if (Name[0]) return(false);
	return(true);
}

/*!
 * Check if the proposed file name can be the month part of a report tree build with
 * IndexTree set to INDEX_TREE_DATE.
 */
bool IsTreeMonthFileName(const char *Name)
{
	int m;

	if (!isdigit(Name[0]) || !isdigit(Name[1])) return(false);
	m=(Name[0]-'0')*10+(Name[1]-'0');
	if (m<1 || m>12) return(false);
	Name+=2;
	if (Name[0]=='-')
	{
		Name++;
		if (!isdigit(Name[0]) || !isdigit(Name[1])) return(false);
		m=(Name[0]-'0')*10+(Name[1]-'0');
		if (m<1 || m>12) return(false);
		Name+=2;
	}
	if (Name[0]) return(false);
	return(true);
}

/*!
 * Check if the proposed file name can be the day part of a report tree build with
 * IndexTree set to INDEX_TREE_DATE.
 */
bool IsTreeDayFileName(const char *Name)
{
	int d;

	if (!isdigit(Name[0]) || !isdigit(Name[1])) return(false);
	d=(Name[0]-'0')*10+(Name[1]-'0');
	if (d<1 || d>31) return(false);
	if (Name[2]=='-')
	{
		Name+=3;
		if (!isdigit(Name[0]) || !isdigit(Name[1])) return(false);
		d=(Name[0]-'0')*10+(Name[1]-'0');
		if (d<1 || d>31) return(false);
	}
	/*
	 * The directory name may contains additional characters such as a counter if
	 * a previous report is never overwritten.
	 */
	return(true);
}

/*!
 * Create a directory to generate a report for the specified connection data
 * and populate it with the a <tt>sarg-date</tt> file containing the current
 * date.
 *
 * The function also create an <tt>images</tt> directory in \a dir and copy all
 * the files from the <tt>SYSCONFDIR/images</tt> into that directory.
 *
 * \param per1 The date range in the form: YYYYMMMDD-YYYYMMMDD or DDMMMYYYY-DDMMMYYYY depending on the value of
 * ::DateFormat.
 * \param addr The ip address or host name to which the report is limited. If the string is empty, all the addresses are accepted.
 * \param site The destination site to which the report is limited. If the string is empty, all the sites are accepted.
 * \param us The user to whom the report is limited. It is an empty string if all the users are accepted.
 */
int vrfydir(const struct periodstruct *per1, const char *addr, const char *site, const char *us)
{
	FILE *fp_ou;
	char wdir[MAXLEN];
	int y1, y2;
	int m1, m2;
	int d1, d2;
	int wlen, wlen2;
	time_t curtime;
	struct tm *loctm;

	strcpy(wdir,outdir);
	wlen=strlen(wdir);
	y1=per1->start.tm_year+1900;
	y2=per1->end.tm_year+1900;
	m1=per1->start.tm_mon+1;
	m2=per1->end.tm_mon+1;
	d1=per1->start.tm_mday;
	d2=per1->end.tm_mday;
	if (IndexTree == INDEX_TREE_DATE) {
		wlen+=sprintf(wdir+wlen,"%04d",y1);
		if (y1!=y2) wlen+=sprintf(wdir+wlen,"-%04d",y2);
		if (access(wdir, R_OK) != 0)
			my_mkdir(wdir);

		wlen+=sprintf(wdir+wlen,"/%02d",m1);
		if (m1 != m2) wlen+=sprintf(wdir+wlen,"-%02d",m2);
		if (access(wdir, R_OK) != 0)
			my_mkdir(wdir);

		wlen+=sprintf(wdir+wlen,"/%02d",d1);
		if (d1!=d2) wlen+=sprintf(wdir+wlen,"-%02d",d2);
	} else {
		if (df == 'u') {
			wlen=snprintf(wdir+wlen,sizeof(wdir)-wlen,"%04d%s%02d-%04d%s%02d",y1,
			        conv_month_name(m1),d1,y2,conv_month_name(m2),d2);
		} else if (df == 'e') {
			wlen=snprintf(wdir+wlen,sizeof(wdir)-wlen,"%02d%s%04d-%02d%s%04d",d1,
			        conv_month_name(m1),y1,d2,conv_month_name(m2),y2);
		} else if (df == 'w') {
			wlen2=strftime(wdir+wlen, sizeof(wdir)-wlen, "%Y.%U", &per1->start);
			if (wlen2==0) return(-1);
			wlen+=wlen2;
		}
	}

	if (us[0] != '\0') {
		struct userinfostruct *uinfo=userinfo_find_from_id(us);
		if (uinfo) {
			strcat(wdir,"-");
			strcat(wdir,uinfo->filename);
		}
	}
	if (addr[0] != '\0') {
		strcat(wdir,"-");
		strcat(wdir,addr);
	}
	if (site[0] != '\0') {
		strcat(wdir,"-");
		strcat(wdir,site);
	}

	strcpy(outdirname,wdir);

	// manufacture a new unique name if configured to keep old reports or overwrite old report if configured to do so
	if (!OverwriteReport) {
		int num=1;

		while (access(wdir,R_OK)==0 || errno==EACCES) //file exist or can't be read
		{
			format_path(__FILE__, __LINE__, wdir, sizeof(wdir), "%s.%d", outdirname, num);
			num++;
		}
		if (num>1) {
			if (debug)
				debuga(__FILE__,__LINE__,_("File \"%s\" already exists, moved to \"%s\"\n"),outdirname,wdir);
			rename(outdirname,wdir);
		}
	} else {
		if (access(outdirname,R_OK) == 0) {
			unlinkdir(outdirname,1);
		}
	}
	my_mkdir(outdirname);

	// create sarg-date to keep track of the report creation date
	if (snprintf(wdir,sizeof(wdir),"%s/sarg-date",outdirname)>=sizeof(wdir)) {
		debuga(__FILE__,__LINE__,_("Buffer too small to store "));
		debuga_more("%s/sarg-date",outdirname);
		exit(EXIT_FAILURE);
	}
	if ((fp_ou = fopen(wdir, "wt")) == 0) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),wdir,strerror(errno));
		perror("SARG:");
		exit(EXIT_FAILURE);
	}
	time(&curtime);
	//strftime(wdir,sizeof(wdir),"%a %b %d %H:%M:%S %Z %Y",localtime(&curtime));
	loctm=localtime(&curtime);
	strftime(wdir,sizeof(wdir),"%Y-%m-%d %H:%M:%S",loctm);
	if (fprintf(fp_ou,"%s %d\n",wdir,loctm->tm_isdst)<0) {
		debuga(__FILE__,__LINE__,_("Failed to write the date in \"%s\"\n"),wdir);
		perror("SARG:");
		exit(EXIT_FAILURE);
	}
	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),wdir,strerror(errno));
		exit(EXIT_FAILURE);
	}

	copy_images();
	return(0);
}

/*!
  Copy a string without overflowing the buffer. The copied string
  is properly terminated by an ASCII zero.

  \param dest The destination buffer.
  \param src The source buffer.
  \param length The size of the destination buffer. The program is aborted
  if the length is negative or zero.
*/
void safe_strcpy(char *dest,const char *src,int length)
{
	if (length<=0) {
		debuga(__FILE__,__LINE__,_("Invalid buffer length passed to the function to safely copy a string\n"));
		exit(EXIT_FAILURE);
	}
	strncpy(dest,src,length-1);
	dest[length-1]='\0';
}

void strip_latin(char *line)
{
	int i,j;
	int skip;

	j=0;
	skip=0;
	for (i=0;line[i];i++){
		if (skip){
			if (line[i]==';') skip=0;
		} else {
			if (line[i]=='&')
				skip=1;
			else
				line[j++]=line[i];
		}
	}
	line[j]='\0';
	return;
}

void zdate(char *ftime,int ftimesize, char DateFormat)
{
	time_t t;
	struct tm *local;

	t = time(NULL);
	local = localtime(&t);
	if (DateFormat=='u')
		strftime(ftime, ftimesize, "%b/%d/%Y %H:%M", local);
	else if (DateFormat=='e')
		strftime(ftime, ftimesize, "%d/%b/%Y-%H:%M", local);
	else if (DateFormat=='w')
		strftime(ftime, ftimesize, "%W-%H-%M", local);
	return;
}


char *fixtime(long long int elap)
{
	long int num = elap / 1000LL;
	int hor = 0;
	int min = 0;
	int sec = 0;
	static char buf[20];

	hor=num / 3600L;
	min=(num % 3600L) / 60L;
	sec=num % 60L;

	if (hor==0 && min==0 && sec==0)
		strcpy(buf,"0");
	else
		snprintf(buf,sizeof(buf),"%d:%02d:%02d",hor,min,sec);

	return buf;
}


void date_from(struct ReadLogDataStruct *ReadFilter)
{
	int d0=0;
	int m0=0;
	int y0=0;
	int d1=0;
	int m1=0;
	int y1=0;

	if (isdigit(ReadFilter->DateRange[0])) {
		int next=-1;

		if (sscanf(ReadFilter->DateRange,"%d/%d/%d%n",&d0,&m0,&y0,&next)!=3 || y0<100 || m0<1 || m0>12 || d0<1 || d0>31 || next<0) {
			debuga(__FILE__,__LINE__,_("The date passed as argument is not formated as dd/mm/yyyy or dd/mm/yyyy-dd/mm/yyyy\n"));
			exit(EXIT_FAILURE);
		}
		if (ReadFilter->DateRange[next]=='-') {
			if (sscanf(ReadFilter->DateRange+next+1,"%d/%d/%d",&d1,&m1,&y1)!=3 || y1<100 || m1<1 || m1>12 || d1<1 || d1>31) {
				debuga(__FILE__,__LINE__,_("The date range passed as argument is not formated as dd/mm/yyyy or dd/mm/yyyy-dd/mm/yyyy\n"));
				exit(EXIT_FAILURE);
			}
		} else if (ReadFilter->DateRange[next]!='\0') {
			debuga(__FILE__,__LINE__,_("The date range passed as argument is not formated as dd/mm/yyyy or dd/mm/yyyy-dd/mm/yyyy\n"));
			exit(EXIT_FAILURE);
		} else {
			d1=d0;
			m1=m0;
			y1=y0;
		}
	} else {
		int i;
		time_t Today,t1;
		struct tm *Date0,Date1;

		if (time(&Today)==(time_t)-1) {
			debuga(__FILE__,__LINE__,_("Failed to get the current time\n"));
			exit(EXIT_FAILURE);
		}
		if (sscanf(ReadFilter->DateRange,"day-%d",&i)==1) {
			if (i<0) {
				debuga(__FILE__,__LINE__,_("Invalid number of days in -d parameter\n"));
				exit(EXIT_FAILURE);
			}
			Today-=i*24*60*60;
			Date0=localtime(&Today);
			if (Date0==NULL) {
				debuga(__FILE__,__LINE__,_("Cannot convert local time: %s\n"),strerror(errno));
				exit(EXIT_FAILURE);
			}
			y0=y1=Date0->tm_year+1900;
			m0=m1=Date0->tm_mon+1;
			d0=d1=Date0->tm_mday;
		} else if (sscanf(ReadFilter->DateRange,"week-%d",&i)==1) {
			/*
			There is no portable way to find the first day of the week even though the
			information is available in the locale. nl_langinfo has the unofficial
			parameters _NL_TIME_FIRST_WEEKDAY and _NL_TIME_WEEK_1STDAY but they are
			undocumented as is their return value and it is discouraged to use them.
			Beside, nl_langinfo isn't available on windows and the first day of the
			week isn't available at all on that system.
			*/
			const int FirstWeekDay=1;
			time_t WeekBegin;

			if (i<0) {
				debuga(__FILE__,__LINE__,_("Invalid number of weeks in -d parameter\n"));
				exit(EXIT_FAILURE);
			}
			Date0=localtime(&Today);
			if (Date0==NULL) {
				debuga(__FILE__,__LINE__,_("Cannot convert local time: %s\n"),strerror(errno));
				exit(EXIT_FAILURE);
			}
			WeekBegin=Today-((Date0->tm_wday-FirstWeekDay+7)%7)*24*60*60;
			WeekBegin-=i*7*24*60*60;
			Date0=localtime(&WeekBegin);
			if (Date0==NULL) {
				debuga(__FILE__,__LINE__,_("Cannot convert local time: %s\n"),strerror(errno));
				exit(EXIT_FAILURE);
			}
			y0=Date0->tm_year+1900;
			m0=Date0->tm_mon+1;
			d0=Date0->tm_mday;
			WeekBegin+=6*24*60*60;
			Date0=localtime(&WeekBegin);
			if (Date0==NULL) {
				debuga(__FILE__,__LINE__,_("Cannot convert local time: %s\n"),strerror(errno));
				exit(EXIT_FAILURE);
			}
			y1=Date0->tm_year+1900;
			m1=Date0->tm_mon+1;
			d1=Date0->tm_mday;
		} else if (sscanf(ReadFilter->DateRange,"month-%d",&i)==1) {
			if (i<0) {
				debuga(__FILE__,__LINE__,_("Invalid number of months in -d parameter\n"));
				exit(EXIT_FAILURE);
			}
			Date0=localtime(&Today);
			if (Date0==NULL) {
				debuga(__FILE__,__LINE__,_("Cannot convert local time: %s\n"),strerror(errno));
				exit(EXIT_FAILURE);
			}
			if (Date0->tm_mon<i%12) {
				y0=Date0->tm_year+1900-i/12-1;
				m0=(Date0->tm_mon+12-i%12)%12+1;
				d0=1;
			} else {
				y0=Date0->tm_year+1900-i/12;
				m0=Date0->tm_mon-i%12+1;
				d0=1;
			}
			memcpy(&Date1,Date0,sizeof(struct tm));
			Date1.tm_isdst=-1;
			Date1.tm_mday=1;
			if (m0<12) {
				Date1.tm_mon=m0;
				Date1.tm_year=y0-1900;
			} else {
				Date1.tm_mon=0;
				Date1.tm_year=y0-1900+1;
			}
			t1=mktime(&Date1);
			t1-=24*60*60;
			Date0=localtime(&t1);
			y1=Date0->tm_year+1900;
			m1=Date0->tm_mon+1;
			d1=Date0->tm_mday;
		} else {
			debuga(__FILE__,__LINE__,_("Invalid date range passed on command line\n"));
			exit(EXIT_FAILURE);
		}
	}

	ReadFilter->StartDate=y0*10000+m0*100+d0;
	ReadFilter->EndDate=y1*10000+m1*100+d1;
	snprintf(ReadFilter->DateRange,sizeof(ReadFilter->DateRange),"%02d/%02d/%04d-%02d/%02d/%04d",d0,m0,y0,d1,m1,y1);
	return;
}


char *strlow(char *string)
{
	char *s;

	if (string)
	{
		for (s = string; *s; ++s)
			*s = tolower(*s);
	}

	return string;
}




char *strup(char *string)
{
	char *s;

	if (string)
	{
		for (s = string; *s; ++s)
			*s = toupper(*s);
	}

	return string;
}


void removetmp(const char *outdir)
{
	FILE *fp_gen;
	char filename[256];

	if (!RemoveTempFiles)
		return;

	if (debug) {
		debuga(__FILE__,__LINE__,_("Purging temporary file sarg-general\n"));
	}
	if (snprintf(filename,sizeof(filename),"%s/sarg-general",outdir)>=sizeof(filename)) {
		debuga(__FILE__,__LINE__,_("Path too long: "));
		debuga_more("%s/sarg-period\n",outdir);
		exit(EXIT_FAILURE);
	}
	if ((fp_gen=fopen(filename,"w"))==NULL){
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),filename,strerror(errno));
		exit(EXIT_FAILURE);
	}
	totalger(fp_gen,filename);
	if (fclose(fp_gen)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),filename,strerror(errno));
		exit(EXIT_FAILURE);
	}
}

void load_excludecodes(const char *ExcludeCodes)
{
	FILE *fp_in;
	char data[80];
	int i;
	int Stored;
	long int MemSize;

	if (ExcludeCodes[0] == '\0')
		return;

	if ((fp_in=fopen(ExcludeCodes,"r"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),ExcludeCodes,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (fseek(fp_in, 0, SEEK_END)==-1) {
		debuga(__FILE__,__LINE__,_("Failed to move till the end of file \"%s\": %s\n"),ExcludeCodes,strerror(errno));
		exit(EXIT_FAILURE);
	}
	MemSize = ftell(fp_in);
	if (MemSize<0) {
		debuga(__FILE__,__LINE__,_("Cannot get the size of file \"%s\"\n"),ExcludeCodes);
		exit(EXIT_FAILURE);
	}
	if (fseek(fp_in, 0, SEEK_SET)==-1) {
		debuga(__FILE__,__LINE__,_("Failed to rewind file \"%s\": %s\n"),ExcludeCodes,strerror(errno));
		exit(EXIT_FAILURE);
	}

	MemSize+=1;
	if ((excludecode=(char *) malloc(MemSize))==NULL) {
		debuga(__FILE__,__LINE__,_("malloc error (%ld bytes required)\n"),MemSize);
		exit(EXIT_FAILURE);
	}
	memset(excludecode,0,MemSize);

	Stored=0;
	while(fgets(data,sizeof(data),fp_in)!=NULL) {
		if (data[0]=='#') continue;
		for (i=strlen(data)-1 ; i>=0 && (unsigned char)data[i]<=' ' ; i--) data[i]='\0';
		if (i<0) continue;
		if (Stored+i+2>=MemSize) {
			debuga(__FILE__,__LINE__,_("Too many codes to exclude in file \"%s\"\n"),ExcludeCodes);
			break;
		}
		strcat(excludecode,data);
		strcat(excludecode,";");
		Stored+=i+1;
	}

	if (fclose(fp_in)==EOF) {
		debuga(__FILE__,__LINE__,_("Read error in \"%s\": %s\n"),ExcludeCodes,strerror(errno));
		exit(EXIT_FAILURE);
	}
	return;
}

void free_excludecodes(void)
{
	if (excludecode) {
		free(excludecode);
		excludecode=NULL;
	}
}

int vercode(const char *code)
{
	char *cod;
	int clen;

	if (excludecode && excludecode[0]!='\0') {
		clen=strlen(code);
		cod=excludecode;
		while (cod) {
			if (strncmp(code,cod,clen)==0 && cod[clen]==';')
				return 1;
			cod=strchr(cod,';');
			if (cod) cod++;
		}
	}
	return 0;
}

void fixnone(char *str)
{
	int i;

	for (i=strlen(str)-1 ; i>=0 && (unsigned char)str[i]<=' ' ; i--);
	if (i==3 && strncmp(str,"none",4) == 0)
		str[0]='\0';

	return;
}

void fixendofline(char *str)
{
	int i;

	for (i=strlen(str)-1 ; i>=0 && (unsigned char)str[i]<=' ' ; i--) str[i]=0;
}

#ifdef LEGACY_TESTVALIDUSERCHAR
int testvaliduserchar(const char *user)
{
	int x=0;
	int y=0;

	for (y=0; y<strlen(UserInvalidChar); y++) {
		for (x=0; x<strlen(user); x++) {
			if (user[x] == UserInvalidChar[y])
				return 1;
		}
	}
	return 0;
}
#else
int testvaliduserchar(const char *user)
{
	char * p_UserInvalidChar = UserInvalidChar ;
	const char * p_user ;

	while( *p_UserInvalidChar ) {
		p_user = user ;
		while ( *p_user ) {
			if ( *p_UserInvalidChar == *p_user )
				return 1;
			p_user++ ;
		}
		p_UserInvalidChar++ ;
	}
	return 0;
}
#endif

int compar( const void *a, const void *b )
{
	if ( *(int *)a > *(int *)b ) return 1;
	if ( *(int *)a < *(int *)b ) return -1;
	return 0;
}

/*!
 * Store a range in a list.
 *
 * \param paramname Name of the configuration parameter providing the list.
 * \param list List where to store the numbers.
 * \param d0 Start range or -1 to store only one value.
 * \param d End range if d0>=0 or the single value to store.
 */
static void storenumlist(const char *paramname, int *list, int d0, int d)
{
	if (d0<0)
	{
		list[d]=1;
	}
	else
	{
		int i;

		if (d<d0)
		{
			debuga(__FILE__,__LINE__,_("Ending value %d is less than or equal to starting value %d in parameter \"%s\"\n"),d,d0,paramname);
			exit(EXIT_FAILURE);
		}
		for (i=d0 ; i<=d ; i++) list[i]=1;
	}
}

/*!
Get a comma separated list of numbers and split them into separate values taking into account
that no value may be greater than a maximum. If a value is a range, it is expended.

Any duplicate value is removed.

\param paramname Name of the configuration parameter providing the list.
\param buffer The string with the list of numbers.
\param list List where to store the numbers.
\param maxvalue The maximum value allowed in the list.

The function terminate the application with an error message if the list is invalid.
*/
void getnumlist(const char *paramname, const char *buffer, int *list, int maxvalue)
{
	int i, d, d0;
	int digitcount;
	int nvalues=0;

	// skip parameter name
	while (*buffer && *buffer!=' ' && *buffer!='\t') buffer++;
	if (!*buffer)
	{
		debuga(__FILE__,__LINE__,_("Missing values for parameter \"%s\"\n"),paramname);
		exit(EXIT_FAILURE);
	}

	// clear list
	for (i=0 ; i<maxvalue ; i++) list[i]=0;

	// get values
	d=0;
	d0=-1;
	digitcount=0;
	for ( ; *buffer ; buffer++)
	{
		if (isdigit(*buffer))
		{
			d=d*10+(*buffer-'0');
			if (d>=maxvalue)
			{
				debuga(__FILE__,__LINE__,_("Value too big found in parameter \"%s\" (max value is %d)\n"),paramname,maxvalue-1);
				exit(EXIT_FAILURE);
			}
			digitcount++;
		}
		else if (*buffer=='-')
		{
			if (!digitcount)
			{
				debuga(__FILE__,__LINE__,_("Missing start value before \"-\" in parameter \"%s\"\n"),paramname);
				exit(EXIT_FAILURE);
			}
			d0=d;
			d=0;
			digitcount=0;
		}
		else if (*buffer==',')
		{
			if (!digitcount)
			{
				debuga(__FILE__,__LINE__,_("Missing value before \",\" in parameter \"%s\"\n"),paramname);
				exit(EXIT_FAILURE);
			}
			storenumlist(paramname,list,d0,d);
			nvalues++;
			d0=-1;
			d=0;
			digitcount=0;
		}
		else if (*buffer=='\r' || *buffer=='\n')
		{
			break;
		}
		else if (*buffer!=' ' && *buffer!='\t')
		{
			debuga(__FILE__,__LINE__,_("Invalid character \"%c\" found in parameter \"%s\"\n"),*buffer,paramname);
			exit(EXIT_FAILURE);
		}
	}
	if (digitcount>0)
	{
		storenumlist(paramname,list,d0,d);
		nvalues++;
	}
	else if (d0>=0)
	{
		debuga(__FILE__,__LINE__,_("Missing ending value in range for parameter \"%s\"\n"),paramname);
		exit(EXIT_FAILURE);
	}
	if (!nvalues)
	{
		debuga(__FILE__,__LINE__,_("Parameter \"%s\" is empty\n"),paramname);
		exit(EXIT_FAILURE);
	}
}

/*!
 * Search if the \a list contains the \a value.
 *
 * \param list The list to search for a value.
 * \param maxvalue The maximum value of the list.
 * \param value The value to search for.
 *
 * \return \c True if the value is enabled in the list.
 */
bool numlistcontains(const int *list, int maxvalue, int value)
{
	if (value<0 || value>=maxvalue) return(false);
	return(list[value]!=0);
}

void show_info(FILE *fp_ou)
{
	char ftime[127];

	if (!ShowSargInfo) return;
	zdate(ftime, sizeof(ftime), df);
	fputs("<div class=\"info\">",fp_ou);
	fprintf(fp_ou,_("Generated by <a href=\"%s\">%s-%s</a> on %s"),URL,PGM,VERSION,ftime);
	fputs("</div>\n",fp_ou);
}

void show_sarg(FILE *fp_ou, int depth)
{
	int i;

	if (!ShowSargLogo) return;
	fputs("<div class=\"logo\"><a href=\"http://sarg.sourceforge.net\"><img src=\"",fp_ou);
	for (i=0 ; i<depth ; i++)
		fputs("../",fp_ou);
	fputs("images/sarg.png\" title=\"SARG, Squid Analysis Report Generator. Logo by Osamu Matsuzaki\" alt=\"Sarg\"></a>&nbsp;Squid Analysis Report Generator</div>\n",fp_ou);
}

void write_logo_image(FILE *fp_ou)
{
	if (LogoImage[0]!='\0')
		fprintf(fp_ou, "<div class=\"logo\"><img src=\"%s\" width=\"%s\" height=\"%s\" alt=\"Logo\">&nbsp;%s</div>\n",LogoImage,Width,Height,LogoText);
}

void write_html_head(FILE *fp_ou, int depth, const char *page_title,int javascript)
{
	int i;

	fputs("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n<html>\n",fp_ou);
	fprintf(fp_ou, "<head>\n  <meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\">\n",CharSet);
	if (page_title) fprintf(fp_ou,"<title>%s</title>\n",page_title);
	css(fp_ou);
	if ((javascript & HTML_JS_SORTTABLE)!=0 && SortTableJs[0]) {
		fputs("<script type=\"text/javascript\" src=\"",fp_ou);
		if (strncmp(SortTableJs,"../",3)==0) {
			for (i=0 ; i<depth ; i++) fputs("../",fp_ou);
		}
		fputs(SortTableJs,fp_ou);
		fputs("\"></script>\n",fp_ou);
	}
	fputs("</head>\n<body>\n",fp_ou);
}

void write_html_header(FILE *fp_ou, int depth, const char *page_title,int javascript)
{
	write_html_head(fp_ou,depth,page_title,javascript);
	write_logo_image(fp_ou);
	show_sarg(fp_ou, depth);
	fprintf(fp_ou,"<div class=\"title\"><table cellpadding=\"0\" cellspacing=\"0\">\n<tr><th class=\"title_c\">%s</th></tr>\n",Title);
}

void close_html_header(FILE *fp_ou)
{
	fputs("</table></div>\n",fp_ou);
}

void write_html_trailer(FILE *fp_ou)
{
	show_info(fp_ou);
	fputs("</body>\n</html>\n",fp_ou);
}

void output_html_string(FILE *fp_ou,const char *str,int maxlen)
{
	int i=0;

	while (*str && (maxlen<=0 || i<maxlen)) {
		switch (*str) {
			case '&':
				fputs("&amp;",fp_ou);
				break;
			case '<':
				fputs("&lt;",fp_ou);
				break;
			case '>':
				fputs("&gt;",fp_ou);
				break;
			case '"':
				fputs("&quot;",fp_ou);
				break;
			case '\'':
				fputs("&#39;",fp_ou);
				break;
			default:
				fputc(*str,fp_ou);
		}
		str++;
		i++;
	}
	if (maxlen>0 && i>=maxlen)
		fputs("&hellip;",fp_ou);
}

void output_html_url(FILE *fp_ou,const char *url)
{
	while (*url) {
		if (*url=='&')
			fputs("&amp;",fp_ou);
		else
			fputc(*url,fp_ou);
		url++;
	}
}

/*!
  Write a host name inside an A tag of a HTML file. If the host name starts
  with a star, it is assumed to be an alias that cannot be put inside a link
  so the A tag is not written around the host name.

  \param fp_ou The handle of the HTML file.
  \param url The host to display in the HTML file.
  \param maxlen The maximum number of characters to print into the host name.
 */
void output_html_link(FILE *fp_ou,const char *url,int maxlen)
{
	if (url[0]==ALIAS_PREFIX) {
		// this is an alias, no need for a A tag
		output_html_string(fp_ou,url+1,100);
	} else {
		if (skip_scheme(url)==url)
			fputs("<a href=\"http://",fp_ou);//no scheme in the url, assume http:// to make the link clickable
		else
			fputs("<a href=\"",fp_ou);//the scheme is in the url, no need to add one
		output_html_url(fp_ou,url);
		fputs("\">",fp_ou);
		output_html_string(fp_ou,url,100);
		fputs("</a>",fp_ou);
	}
}

void url_module(const char *url, char *w2)
{
	int x, y;
	char w[255];

	y=0;
	for (x=strlen(url)-1; x>=0; x--) {
		if (url[x] == '/' || y>=sizeof(w)-1) break;
		w[y++]=url[x];
	}
	if (x<0) {
		w2[0]='\0';
		return;
	}

	x=0;
	for (y=y-1; y>=0; y--) {
		w2[x++]=w[y];
	}
	w2[x]='\0';
}

/*!
Mangle an URL to produce a part that can be used as an anchor in
a html <a name=""> tag.

\param url The URL to mangle.
\param anchor The buffer to write the mangled URL.
\param size The size of the buffer.
*/
void url_to_anchor(const char *url,char *anchor,int size)
{
	int i,j;
	bool skip;

	// find url end
	for (i=0 ; url[i] && url[i]!='/' && url[i]!='?' ; i++);
	i--;
	if (i<=0) {
		anchor[0]='\0';
		return;
	}

	// only keep really safe characters
	skip=false;
	j=size-1;
	anchor[j]='\0';
	while (j>0 && i>=0)
	{
		if (isalnum(url[i]) || url[i]=='-' || url[i]=='_' || url[i]=='.') {
			anchor[--j]=url[i];
			skip=false;
		} else {
			if (!skip) anchor[--j]='_';
			skip=true;
		}
		i--;
	}
	if (j>0)
	{
		while ( anchor[j])
		{
			*anchor=anchor[j];
			anchor++;
		}
		*anchor='\0';
	}
}

void version(void)
{
	printf(_("SARG Version: %s\n"),VERSION);
#if defined(ENABLE_NLS) && defined(HAVE_LOCALE_H)
	if (debug) {
		printf(_("\nFor the translation to work, a valid message file should be copied to "
				 "\"%s/<Locale>/LC_MESSAGES/%s.mo\" where <Locale> is derived from the effective locale.\n"),LOCALEDIR,PACKAGE_NAME);
		if (CurrentLocale) {
			printf(_("Currently effective locale is \"%s\".\n"),CurrentLocale);
		} else {
			printf(_("Locale is not set in the environment variable.\n"));
		}
		// TRANSLATORS: You may change this message to tell the reader that the language is correctly supported.
		printf(_("If this message is in English, then your language is not supported or not correctly installed.\n"));
	}
#endif
	if (debug) {
#ifdef HAVE_GLOB_H
		printf(_("File globbing compiled in.\n"));
#else
		printf(_("File globbing NOT compiled in.\n"));
#endif
	}
	exit(EXIT_SUCCESS);
}

char *get_param_value(const char *param,char *line)
{
	int plen;

	while (*line==' ' || *line=='\t') line++;
	plen=strlen(param);
	if (strncasecmp(line,param,plen)) return(NULL);
	if (line[plen]!=' ' && line[plen]!='\t') return(NULL);
	line+=plen;
	while (*line==' ' || *line=='\t') line++;
	return(line);
}

void unlinkdir(const char *dir,bool contentonly)
{
	struct stat st;
	DIR *dirp;
	struct dirent *direntp;
	char dname[MAXLEN];
	int err;

	dirp=opendir(dir);
	if (!dirp) return;
	while ((direntp = readdir(dirp)) != NULL) {
		if (direntp->d_name[0] == '.' && (direntp->d_name[1] == '\0' ||
		    (direntp->d_name[1] == '.' && direntp->d_name[2] == '\0')))
			continue;
		if (snprintf(dname,sizeof(dname),"%s/%s",dir,direntp->d_name)>=sizeof(dname)) {
			debuga(__FILE__,__LINE__,_("Path too long: "));
			debuga_more("%s/%s\n",dir,direntp->d_name);
			exit(EXIT_FAILURE);
		}
#ifdef HAVE_LSTAT
		err=lstat(dname,&st);
#else
		err=stat(dname,&st);
#endif
		if (err) {
			debuga(__FILE__,__LINE__,_("Cannot stat \"%s\": %s\n"),dname,strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (S_ISREG(st.st_mode)) {
			if (unlink(dname)) {
				debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),dname,strerror(errno));
				exit(EXIT_FAILURE);
			}
		} else if (S_ISDIR(st.st_mode)) {
			unlinkdir(dname,0);
		} else {
			debuga(__FILE__,__LINE__,_("Don't know how to delete \"%s\" (not a regular file nor a directory)\n"),dname);
		}
	}
	closedir(dirp);

	if (!contentonly) {
		if (rmdir(dir)) {
			debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),dir,strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}

/*!
Delete every file from the temporary directory where sarg is told to store its
temporary files.

As any stray file left over by a previous run would be included in the report, we
must delete every file from the temporary directory before we start processing the logs.

But the temporary directory is given by the user either in the configuration file or
on the command line. We check that the user didn't give a wrong directory by looking
at the files stored in the directory. If a single file is not one of ours, we abort.

\param dir The temporary directory to purge.
*/
void emptytmpdir(const char *dir)
{
	struct stat st;
	DIR *dirp;
	struct dirent *direntp;
	int dlen;
	int elen;
	char dname[MAXLEN];
	int err;
	int i;
	static const char *TmpExt[]=
	{
		".int_unsort",
		".int_log",
		".day",
		"htmlrel.txt",
		".user_unsort",
		".user_log",
		".utmp",
		".ip",
		"lastlog1",
		"lastlog",
		"emailrep"
	};

	dirp=opendir(dir);
	if (!dirp) return;

	// make sure the temporary directory contains only our files
	while ((direntp = readdir(dirp)) != NULL) {
		if (direntp->d_name[0] == '.' && (direntp->d_name[1] == '\0' ||
		    (direntp->d_name[1] == '.' && direntp->d_name[2] == '\0')))
			continue;

		// is it one of our files
		dlen=strlen(direntp->d_name);
		for (i=sizeof(TmpExt)/sizeof(TmpExt[0])-1 ; i>=0 ; i--) {
			elen=strlen(TmpExt[i]);
			if (dlen>=elen && strcasecmp(direntp->d_name+dlen-elen,TmpExt[i])==0) break;
		}
		if (i<0) {
			debuga(__FILE__,__LINE__,_("Unknown file \"%s\" found in temporary directory \"%s\". It is not one of our files. "
			"Please check the temporary directory you gave to sarg. Adjust the path to a safe "
			"directory or manually delete the content of \"%s\"\n"),direntp->d_name,dir,dir);
			exit(EXIT_FAILURE);
		}

		if (snprintf(dname,sizeof(dname),"%s/%s",dir,direntp->d_name)>=sizeof(dname)) {
			debuga(__FILE__,__LINE__,_("Path too long: "));
			debuga_more("%s/%s\n",dir,direntp->d_name);
			exit(EXIT_FAILURE);
		}

#ifdef HAVE_LSTAT
		err=lstat(dname,&st);
#else
		err=stat(dname,&st);
#endif
		if (err) {
			debuga(__FILE__,__LINE__,_("Cannot stat \"%s\": %s\n"),dname,strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) {
			debuga(__FILE__,__LINE__,_("Unknown path type for \"%s\". Check temporary directory\n"),dname);
			exit(EXIT_FAILURE);
		}
	}
	rewinddir(dirp);

	// now delete our files
	while ((direntp = readdir(dirp)) != NULL) {
		if (direntp->d_name[0] == '.' && (direntp->d_name[1] == '\0' ||
		    (direntp->d_name[1] == '.' && direntp->d_name[2] == '\0')))
			continue;

		// is it one of our files
		dlen=strlen(direntp->d_name);
		for (i=sizeof(TmpExt)/sizeof(TmpExt[0])-1 ; i>=0 ; i--) {
			elen=strlen(TmpExt[i]);
			if (dlen>=elen && strcasecmp(direntp->d_name+dlen-elen,TmpExt[i])==0) break;
		}
		if (i<0) {
			debuga(__FILE__,__LINE__,_("Unknown file \"%s\" found in temporary directory \"%s\". It is not one of our files. "
			"Please check the temporary directory you gave to sarg. Adjust the path to a safe "
			"directory or manually delete the content of \"%s\"\n"),direntp->d_name,dir,dir);
			exit(EXIT_FAILURE);
		}

		if (snprintf(dname,sizeof(dname),"%s/%s",dir,direntp->d_name)>=sizeof(dname)) {
			debuga(__FILE__,__LINE__,_("Path too long: "));
			debuga_more("%s/%s\n",dir,direntp->d_name);
			exit(EXIT_FAILURE);
		}
#ifdef HAVE_LSTAT
		err=lstat(dname,&st);
#else
		err=stat(dname,&st);
#endif
		if (err) {
			debuga(__FILE__,__LINE__,_("Cannot stat \"%s\": %s\n"),dname,strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (S_ISDIR(st.st_mode)) {
			unlinkdir(dname,0);
		} else if (S_ISREG(st.st_mode)) {
			if (unlink(dname)) {
				debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),dname,strerror(errno));
				exit(EXIT_FAILURE);
			}
		} else {
			debuga(__FILE__,__LINE__,_("Don't know how to delete \"%s\" (not a regular file)\n"),dname);
		}
	}
	closedir(dirp);
}

/*!
  Extract an url, IPv4 or IPv6 from a buffer. The IP addresses may end with a
  prefix size.

  \param buf The buffer to parse.
  \param text A pointer to set to the beginning of the string pattern. No terminating zero is inserted.
              The pointer may be NULL.
  \param ipv4 A 4 bytes buffer to store the bytes of the IPv4 address.
  \param ipv6 A 8 short integers buffer to store the values of the IPv6 address.
  \param nbits The number of prefix bits for an IP address.
  \param next The content of the line after the extracted address.

  \retval 3 The pattern is a IPv6 address.
  \retval 2 The pattern is a IPv4 address.
  \retval 1 The patter is a string.
  \retval 0 Empty pattern.
 */
int extract_address_mask(const char *buf,const char **text,unsigned char *ipv4,unsigned short int *ipv6,int *nbits,const char **next)
{
	int i;
	int j;
	int ip_size;
	unsigned int value4, value6;
	unsigned short int addr[8];
	int addr_len;
	int nibble6_len;
	int mask, max_mask;
	int pad_pos;
	int pad_len;
	bool bracket=false;
	bool port=false;
	int port_num=0;

	// skip leading spaces and tabs
	while (*buf && (*buf==' ' || *buf=='\t')) buf++;

	// find out the nature of the pattern
	ip_size=0x60  | 0x04;
	if (*buf=='[') {
		bracket=true;
		ip_size=0x60;
		buf++;
	}
	value4=0U;
	value6=0U;
	addr_len=0;
	nibble6_len=0;
	pad_pos=-1;
	for (i=0 ; (unsigned char)buf[i]>' ' && buf[i]!='/' && buf[i]!='?' && (!bracket || buf[i]!=']') && ip_size ; i++) {
		if (ip_size & 0x04) {
			if (isdigit(buf[i])) {
				if (port) {
					port_num=port_num*10+(buf[i]-'0');
					if (port_num>65535) ip_size&=~0x04;
				} else {
					value4=value4*10+(buf[i]-'0');
					if (value4>0xFFU) ip_size&=~0x04;
				}
			} else if (buf[i]=='.' && addr_len<4) {
				addr[addr_len++]=(unsigned short)(value4 & 0xFFU);
				value4=0U;
			} else if (!port && buf[i]==':') {
				port=true;
			} else {
				ip_size&=~0x04;
			}
		}
		if (ip_size & 0x60) {
			if (isdigit(buf[i])) {
				value6=(value6<<4)+(buf[i]-'0');
				nibble6_len++;
				if (value6>0xFFFFU) ip_size&=~0x60;
			} else if (toupper(buf[i])>='A' && toupper(buf[i])<='F') {
				value6=(value6<<4)+(toupper(buf[i])-'A'+10);
				nibble6_len++;
				if (value6>0xFFFFU) ip_size&=~0x60;
			} else if (buf[i]==':' && addr_len<8) {
				if (nibble6_len>0) {
					addr[addr_len++]=(unsigned short)(value6 & 0xFFFFU);
					nibble6_len=0;
				}
				value6=0U;
				if (buf[i+1]==':') {
					pad_pos=addr_len;
					i++;
				}
			} else {
				ip_size&=~0x60;
			}
		}
	}
	if (i==0) return(0);
	if (ip_size & 0x04) {
		if (addr_len!=3)
			ip_size&=~0x04;
		else
			addr[addr_len++]=(unsigned short)(value4 & 0xFFU);
	}
	if (ip_size & 0x60) {
		if (pad_pos<0 && addr_len!=7) {
			ip_size&=~0x60;
		} else if (pad_pos>=0 && addr_len>=7)
			ip_size&=~0x60;
		else if (nibble6_len>0)
			addr[addr_len++]=(unsigned short)(value6 & 0xFFFFU);
	}
	if (!ip_size) {
		if (text) {
			*text=buf;
			if (bracket) (*text)--;
		}
		while ((unsigned char)buf[i]>' ') i++;
		if (next) *next=buf+i;
		return(1);
	}
	max_mask=(ip_size & 0x04) ? 4*8 : 8*16;
	if (buf[i]=='/') {
		i++;
		mask=atoi(buf+i);
		while (isdigit(buf[i])) i++;
		if (mask<0 || mask>max_mask) mask=max_mask;
	} else
		mask=max_mask;
	if (ip_size & 0x60 && bracket && buf[i]==']') i++;
	if (next) *next=buf+i;
	if (ip_size & 0x04) {
		if (nbits) *nbits=mask;
		for (i=0 ; i<addr_len ; i++)
			ipv4[i]=(unsigned char)addr[i];
		return(2);
	}

	// IPv6 address
	if (nbits) *nbits=mask;
	i=0;
	j=0;
	if (pad_pos>=0) {
		while (i<pad_pos)
			ipv6[j++]=(unsigned short int)addr[i++];
		pad_len=8-addr_len;
		while (j<pad_pos+pad_len)
			ipv6[j++]=0;
	}
	while (i<addr_len)
		ipv6[j++]=(unsigned short int)addr[i++];
	return(3);
}

int format_path(const char *file, int line, char *output_buffer, int buffer_size, const char *format,...)
{
	va_list ap;
	int output_length;

	va_start(ap, format);
	output_length = vsnprintf(output_buffer, buffer_size, format, ap);
	if (output_length >= buffer_size) {
		debuga(file, line, _("Path too long: "));
		vfprintf(stderr, format, ap);
		exit(EXIT_FAILURE);
	}
	va_end(ap);
	return output_length;
}

void append_to_path(char *base_path, int base_path_size, const char *append)
{
	int length = strlen(base_path);
	int append_length;

	if (append[0] == '/') append++;
	if (length > 0 && base_path[length-1] != '/') {
		if (length+1 >= base_path_size) {
			debuga(__FILE__, __LINE__, _("Path too long: "));
			fprintf(stderr, "%s/%s", base_path, append);
			exit(EXIT_FAILURE);
		}
		base_path[length++] = '/';
	}
	append_length = strlen(append);
	if (length+append_length >= base_path_size) {
		debuga(__FILE__, __LINE__, _("Path too long: "));
		base_path[length] = '\0';
		fprintf(stderr, "%s%s", base_path, append);
		exit(EXIT_FAILURE);
	}
	strcpy(base_path + length, append);
}
