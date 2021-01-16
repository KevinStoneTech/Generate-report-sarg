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

#ifdef HAVE_LSTAT
#define MY_LSTAT lstat
#else
#define MY_LSTAT stat
#endif


static void make_date_index(void);
static void make_file_index(void);
static void file_index_to_date_index(const char *entry);
static void date_index_to_file_index(const char *entry);

void make_index(void)
{
	DIR *dirp;
	struct dirent *direntp;
	char wdir[MAXLEN];

	if (LastLog > 0) mklastlog(outdir);

	if (Index == INDEX_NO) {
		if (snprintf(wdir,sizeof(wdir),"%s"INDEX_HTML_FILE,outdir)>=sizeof(wdir)) {
			debuga(__FILE__,__LINE__,_("Path too long: "));
			debuga_more("%s"INDEX_HTML_FILE,outdir);
			exit(EXIT_FAILURE);
		}
		if (access(wdir, R_OK) == 0) {
			if (unlink(wdir)) {
				debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),wdir,strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		return;
	}

	if (debug) {
		// TRANSLATORS: The %s is the name of the html index file (index.html).
		debuga(__FILE__,__LINE__,_("Making %s\n"),INDEX_HTML_FILE);
	}

	// convert any old report hierarchy
	if ((dirp = opendir(outdir)) == NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open directory \"%s\": %s\n"),outdir,strerror(errno));
		exit(EXIT_FAILURE);
	}
	while ((direntp = readdir( dirp )) != NULL) {
		if (isdigit(direntp->d_name[0]) && isdigit(direntp->d_name[1])) {
			if (IndexTree == INDEX_TREE_DATE)
				file_index_to_date_index(direntp->d_name);
			else
				date_index_to_file_index(direntp->d_name);
		}
	}
	closedir(dirp);

	if (IndexTree == INDEX_TREE_DATE) {
		make_date_index();
	} else {
		make_file_index();
	}
}

/*!
 * Get the effective size of a regular file or directory.
 *
 * \param statb The structure filled by lstat(2).
 *
 * \return The size occupied on the disk (more or less).
 *
 * The actual size occupied on disk by a file or a directory table is not a
 * trivial computation. It must take into account sparse files, compression,
 * deduplication and probably many more.
 *
 * Here, we assume the file takes a whole number of blocks (which is not the
 * case of ReiserFS); the block size is constant (which is not the case of
 * ZFS); every data block is stored in one individal block (no deduplication as
 * is done by btrfs); data are not compressed (unlike ReiserFS and ZFS).
 *
 * As we are dealing with directories containing mostly text and a few
 * compressed pictures, we don't worry about sparse files with lot of zeros
 * that would take less blocks than the actual file size.
 */
static long long int get_file_size(struct stat *statb)
{
#ifdef __linux__
	long long int blocks;

	//return(statb->st_size);//the size of the file content
	//return(statb->st_blocks*512);//what is the purpose of this size?
	if (statb->st_blksize==0) return(statb->st_size);
	blocks=(statb->st_size+statb->st_blksize-1)/statb->st_blksize;
	return(blocks*statb->st_blksize);//how many bytes occupied on disk
#else
	return(statb->st_size);
#endif
}

/*!
 * Get the size of a directory.
 *
 * The size is the size of the directory content excluding the directory table.
 * The "du" tool on Linux returns the content size including the directory
 * table.
 *
 * \param path The directory whose size is computed. This is a buffer that must be
 * big enough to contains the deepest path as directory entries are appended to
 * the string this buffer contains.
 * \param path_size The number of bytes available in the \a path buffer.
 *
 * \return The number of bytes occupied by the directory content.
 */
static long long int get_size(char *path,int path_size)
{
	int path_len;
	DIR *dirp;
	struct dirent *direntp;
	struct stat statb;
	int name_len;
	long long int total_size=0;
	char *dir_list=NULL;
	int dir_filled=0;
	int dir_allocated=0;

	path_len=strlen(path);
	if (path_len+2>=path_size) {
		debuga(__FILE__,__LINE__,_("Path too long: "));
		debuga_more("%s\n",path);
		exit(EXIT_FAILURE);
	}
	if ((dirp=opendir(path))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open directory \"%s\": %s\n"),path,strerror(errno));
		exit(EXIT_FAILURE);
	}
	path[path_len++]='/';
	while ((direntp=readdir(dirp))!=NULL) {
		if (direntp->d_name[0]=='.' && (direntp->d_name[1]=='\0' || (direntp->d_name[1]=='.' && direntp->d_name[2]=='\0'))) continue;
		name_len=strlen(direntp->d_name);
		if (path_len+name_len+1>=path_size) {
			debuga(__FILE__,__LINE__,_("Path too long: "));
			debuga_more("%s%s\n",path,direntp->d_name);
			exit(EXIT_FAILURE);
		}
		strcpy(path+path_len,direntp->d_name);
		if (MY_LSTAT(path,&statb) == -1) {
			debuga(__FILE__,__LINE__,_("Failed to get the statistics of file \"%s\": %s\n"),path,strerror(errno));
			continue;
		}
		if (S_ISDIR(statb.st_mode))
		{
			if (!dir_list || dir_filled+name_len>=dir_allocated)
			{
				int size=3*(name_len+1);//make room for three file names like this one
				if (size<256) size=256;
				dir_allocated+=size;
				dir_list=realloc(dir_list,dir_allocated);
				if (!dir_list) {
					debuga(__FILE__,__LINE__,_("Not enough memory to recurse into subdirectory \"%s\"\n"),path);
					exit(EXIT_FAILURE);
				}
			}
			strcpy(dir_list+dir_filled,direntp->d_name);
			dir_filled+=name_len+1;
			total_size+=get_file_size(&statb);
		}
		else if (S_ISREG(statb.st_mode))
		{
			total_size+=get_file_size(&statb);
		}
	}
	closedir(dirp);

	if (dir_list)
	{
		int start=0;

		while (start<dir_filled)
		{
			name_len=strlen(dir_list+start);
			strcpy(path+path_len,dir_list+start);
			total_size+=get_size(path,path_size);
			start+=name_len+1;
		}
		free(dir_list);
	}

	path[path_len-1]='\0';//restore original string
	return (total_size);
}

/*!
 * Rebuild the html index file for a day when the reports are grouped in a date tree.
 *
 * \param monthdir The buffer containing the path where the html index file must be rebuild.
 * The buffer must be big enough to contain the deepest path in that directory as the buffer is
 * used to concatenate the directory entries.
 * \param monthdir_size The size, in byte, of the \a monthdir buffer.
 * \param order A postive number to sort the index file in positive order. A negative value sort it
 * in decreasing order.
 * \param yearnum The string naming the year in the date tree.
 * \param monthnum The string naming the month in the date tree.
 *
 * \return The approximate size occupied by the directory.
 */
static long long int make_date_index_day(char *monthdir,int monthdir_size,int order,const char *yearnum,const char *monthnum)
{
	int monthdir_len;
	int ndays;
	DIR *dirp3;
	struct dirent *direntp;
	struct stat statb;
	int i;
	int daysort[31*31];
	int d1, d2, day;
	FILE *fp_ou;
	char title[80];
	char daynum[10];
	int d;
	long long int total_size=0;
	long long int sub_size;
	int name_len;

	ndays=0;
	if ((dirp3 = opendir(monthdir)) == NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open directory \"%s\": %s\n"),monthdir,strerror(errno));
		exit(EXIT_FAILURE);
	}
	monthdir_len=strlen(monthdir);
	if (monthdir_len+strlen(INDEX_HTML_FILE)+2>=monthdir_size) {
		debuga(__FILE__,__LINE__,_("Path too long: "));
		debuga_more("%s/%s\n",monthdir,INDEX_HTML_FILE);
		exit(EXIT_FAILURE);
	}
	monthdir[monthdir_len++]='/';
	while ((direntp = readdir( dirp3 )) != NULL) {
		if (direntp->d_name[0]=='.' && (direntp->d_name[1]=='\0' || (direntp->d_name[1]=='.' && direntp->d_name[2]=='\0'))) continue;
		name_len=strlen(direntp->d_name);
		if (monthdir_len+name_len+1>=monthdir_size) {
			debuga(__FILE__,__LINE__,_("Path too long: "));
			debuga_more("%s%s\n",monthdir,direntp->d_name);
			exit(EXIT_FAILURE);
		}
		strcpy(monthdir+monthdir_len,direntp->d_name);
		if (MY_LSTAT(monthdir,&statb) == -1) {
			debuga(__FILE__,__LINE__,_("Failed to get the statistics of file \"%s\": %s\n"),monthdir,strerror(errno));
			continue;
		}
		if (S_ISDIR(statb.st_mode))
		{
			if (!isdigit(direntp->d_name[0]) && !isdigit(direntp->d_name[1])) continue;
			i=-1;
			if (sscanf(direntp->d_name,"%d%n",&d1,&i)!=1 || d1<1 || d1>31 || i<0) continue;
			if (direntp->d_name[i]=='-') {
				if (sscanf(direntp->d_name+i+1,"%d",&d2)!=1 || d2<1 || d2>31) continue;
			} else if (direntp->d_name[i]!='\0') {
				continue;
			} else {
				d2=0;
			}
			if (ndays>=sizeof(daysort)/sizeof(daysort[0])) {
				debuga(__FILE__,__LINE__,_("Too many day directories in %s\nSupernumerary entries are ignored\n"),monthdir);
				break;
			}
			day=(d1 << 5) | d2;
			for (i=ndays ; i>0 &&  day<daysort[i-1] ; i--) {
				daysort[i]=daysort[i-1];
			}
			daysort[i]=day;
			ndays++;
			total_size+=get_file_size(&statb);
		}
		else if (S_ISREG(statb.st_mode))
		{
			total_size+=get_file_size(&statb);
		}
	}
	closedir(dirp3);

	strcpy(monthdir+monthdir_len,INDEX_HTML_FILE);
	if ((fp_ou=fopen(monthdir,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),monthdir,strerror(errno));
		exit(EXIT_FAILURE);
	}
	snprintf(title,sizeof(title),ngettext("SARG: report for %s/%s","SARG: reports for %s/%s",ndays),yearnum,monthnum);
	write_html_header(fp_ou,2,title,HTML_JS_NONE);
	close_html_header(fp_ou);
	fputs("<div class=\"index\"><table cellpadding=\"1\" cellspacing=\"2\">\n<tr><td></td><td></td></tr>\n",fp_ou);
	fprintf(fp_ou,"<tr><th class=\"header_l\">%s/%s/%s</th>",_("YEAR"),_("MONTH"),_("DAYS"));
	if (IndexFields & INDEXFIELDS_DIRSIZE)
		fprintf(fp_ou,"<th class=\"header_l\">%s</th>",_("SIZE"));
	fputs("</tr>\n",fp_ou);
	for (d=0 ; d<ndays ; d++) {
		if (order>0)
			day=daysort[d];
		else
			day=daysort[ndays-1-d];
		d1=(day >> 5) & 0x1F;
		if ((day & 0x1F) != 0) {
			d2=day & 0x1F;
			snprintf(daynum,sizeof(daynum),"%02d-%02d",d1,d2);
		} else {
			snprintf(daynum,sizeof(daynum),"%02d",d1);
		}
		strcpy(monthdir+monthdir_len,daynum);
		sub_size=get_size(monthdir,monthdir_size);

		fprintf(fp_ou,"<tr><td class=\"data2\"><a href=\"%s/%s\">%s %s %s</a></td>",daynum,INDEX_HTML_FILE,yearnum,monthnum,daynum);
		if (IndexFields & INDEXFIELDS_DIRSIZE)
		{
			char size_str[40];

			strncpy(size_str,fixnum(sub_size,1),sizeof(size_str)-1);
			size_str[sizeof(size_str)-1]='\0';
			fprintf(fp_ou,"<td class=\"data2\">%s</td>",size_str);
		}
		fputs("</tr>\n",fp_ou);
		total_size+=sub_size;
	}
	fputs("</table></div>\n",fp_ou);
	monthdir[monthdir_len-1]='\0';
	write_html_trailer(fp_ou);
	if (fclose(fp_ou)==EOF) {
		strcpy(monthdir+monthdir_len,INDEX_HTML_FILE);
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),monthdir,strerror(errno));
		exit(EXIT_FAILURE);
	}
	return(total_size);
}

/*!
 * Get the name of a month based on its number.
 *
 * \param month The month number starting from one.
 * \param month_name The buffer to store the month name.
 * \param month_size The size of the \a month_name buffer.
 */
static void name_month(int month,char *month_name,int month_size)
{
	const char *m[12]={N_("January"),N_("February"),N_("March"),N_("April"),N_("May"),N_("June"),N_("July"),
					   N_("August"),N_("September"),N_("October"),N_("November"),N_("December")};

	if (month<1 || month>12) {
		debuga(__FILE__,__LINE__,_("The internal list of month names is invalid. Please report this bug to the translator.\n"));
		exit(EXIT_FAILURE);
	}
	strncpy(month_name,_(m[month-1]),month_size-1);
	month_name[month_size-1]='\0';
}

/*!
 * Rebuild the html index file for a month when the reports are grouped in a date tree.
 *
 * \param yeardir The buffer containing the path where the html index file must be rebuild.
 * The buffer must be big enough to contain the deepest path in that directory as the buffer is
 * used to concatenate the directory entries.
 * \param yeardir_size The size, in byte, of the \a yeardir buffer.
 * \param order A postive number to sort the index file in positive order. A negative value sort it
 * in decreasing order.
 * \param yearnum The string naming the year in the date tree.
 *
 * \return The approximate size occupied by the directory.
 */
static long long int make_date_index_month(char *yeardir,int yeardir_size,int order,const char *yearnum)
{
	int yeardir_len;
	int nmonths;
	DIR *dirp2;
	struct dirent *direntp;
	struct stat statb;
	int i;
	int monthsort[144];
	int m1, m2, month;
	FILE *fp_ou;
	char title[80];
	char monthname1[9], monthname2[9];
	char nmonth[30];
	char monthnum[10];
	int m;
	long long int total_size=0;
	long long int sub_size;
	int name_len;

	nmonths=0;
	if ((dirp2 = opendir(yeardir)) == NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open directory \"%s\": %s\n"),yeardir,strerror(errno));
		exit(EXIT_FAILURE);
	}
	yeardir_len=strlen(yeardir);
	if (yeardir_len+strlen(INDEX_HTML_FILE)+2>=yeardir_size) {
		debuga(__FILE__,__LINE__,_("Path too long: "));
		debuga_more("%s/%s\n",yeardir,INDEX_HTML_FILE);
		exit(EXIT_FAILURE);
	}
	yeardir[yeardir_len++]='/';
	while ((direntp = readdir( dirp2 )) != NULL) {
		if (direntp->d_name[0]=='.' && (direntp->d_name[1]=='\0' || (direntp->d_name[1]=='.' && direntp->d_name[2]=='\0'))) continue;
		name_len=strlen(direntp->d_name);
		if (yeardir_len+name_len+1>=yeardir_size) {
			debuga(__FILE__,__LINE__,_("Path too long: "));
			debuga_more("%s%s\n",yeardir,direntp->d_name);
			exit(EXIT_FAILURE);
		}
		strcpy(yeardir+yeardir_len,direntp->d_name);
		if (MY_LSTAT(yeardir,&statb) == -1) {
			debuga(__FILE__,__LINE__,_("Failed to get the statistics of file \"%s\": %s\n"),yeardir,strerror(errno));
			continue;
		}
		if (S_ISDIR(statb.st_mode))
		{
			if (!isdigit(direntp->d_name[0]) || !isdigit(direntp->d_name[1])) continue;
			i=-1;
			if (sscanf(direntp->d_name,"%d%n",&m1,&i)!=1 || m1<1 || m1>12 || i<0) continue;
			if (direntp->d_name[i]=='-') {
				if (sscanf(direntp->d_name+i+1,"%d",&m2)!=1 || m2<1 || m2>12) continue;
			} else if (direntp->d_name[i]!='\0') {
				continue;
			} else {
				m2=0;
			}
			if (nmonths>=sizeof(monthsort)/sizeof(monthsort[0])) {
				debuga(__FILE__,__LINE__,_("Too many month directories in %s\nSupernumerary entries are ignored\n"),yeardir);
				break;
			}
			month=(m1<<4) | m2;
			for (i=nmonths ; i>0 &&  month<monthsort[i-1] ; i--) {
				monthsort[i]=monthsort[i-1];
			}
			monthsort[i]=month;
			nmonths++;
			total_size+=get_file_size(&statb);
		}
		else if (S_ISREG(statb.st_mode))
		{
			total_size+=get_file_size(&statb);
		}
	}
	closedir(dirp2);

	strcpy(yeardir+yeardir_len,INDEX_HTML_FILE);
	if ((fp_ou=fopen(yeardir,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),yeardir,strerror(errno));
		exit(EXIT_FAILURE);
	}
	snprintf(title,sizeof(title),ngettext("SARG: report for %s","SARG: reports for %s",nmonths),yearnum);
	write_html_header(fp_ou,1,title,HTML_JS_NONE);
	close_html_header(fp_ou);
	fputs("<div class=\"index\"><table cellpadding=\"1\" cellspacing=\"2\">\n<tr><td></td><td></td></tr>\n",fp_ou);
	fprintf(fp_ou,"<tr><th class=\"header_l\">%s/%s</th>",_("YEAR"),_("MONTH"));
	if (IndexFields & INDEXFIELDS_DIRSIZE)
		fprintf(fp_ou,"<th class=\"header_l\">%s</th>",_("SIZE"));
	fputs("</tr>\n",fp_ou);
	for (m=0 ; m<nmonths ; m++) {
		if (order>0)
			month=monthsort[m];
		else
			month=monthsort[nmonths-1-m];
		m1=(month >> 4) & 0x0F;
		if ((month & 0x0F) != 0) {
			m2=month & 0x0F;
			snprintf(monthnum,sizeof(monthnum),"%02d-%02d",m1,m2);
			name_month(m1,monthname1,sizeof(monthname1));
			name_month(m2,monthname2,sizeof(monthname2));
			snprintf(nmonth,sizeof(nmonth),"%s-%s",monthname1,monthname2);
		} else {
			snprintf(monthnum,sizeof(monthnum),"%02d",m1);
			name_month(m1,nmonth,sizeof(nmonth));
		}
		if (yeardir_len+strlen(monthnum)+1>=yeardir_size) {
			yeardir[yeardir_len]='\0';
			debuga(__FILE__,__LINE__,_("Path too long: "));
			debuga_more("%s%s\n",yeardir,monthnum);
			exit(EXIT_FAILURE);
		}
		strcpy(yeardir+yeardir_len,monthnum);
		sub_size=make_date_index_day(yeardir,yeardir_size,order,yearnum,nmonth);

		fprintf(fp_ou,"<tr><td class=\"data2\"><a href=\"%s/%s\">%s %s</a></td>",monthnum,INDEX_HTML_FILE,yearnum,nmonth);
		if (IndexFields & INDEXFIELDS_DIRSIZE)
		{
			char size_str[40];

			strncpy(size_str,fixnum(sub_size,1),sizeof(size_str)-1);
			size_str[sizeof(size_str)-1]='\0';
			fprintf(fp_ou,"<td class=\"data2\">%s</td>",size_str);
		}
		fputs("</tr>\n",fp_ou);
		total_size+=sub_size;
	}
	fputs("</table></div>\n",fp_ou);
	yeardir[yeardir_len-1]='\0';
	write_html_trailer(fp_ou);
	if (fclose(fp_ou)==EOF) {
		strcpy(yeardir+yeardir_len,INDEX_HTML_FILE);
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),yeardir,strerror(errno));
		exit(EXIT_FAILURE);
	}
	return(total_size);
}

/*!
 * Rebuild a date index tree in the output directory.
 */
static void make_date_index(void)
{
	FILE *fp_ou;
	DIR *dirp;
	struct dirent *direntp;
	char yearindex[MAXLEN];
	char yeardir[MAXLEN];
	char yearnum[10];
	int yearsort[150];
	int nyears;
	int year;
	int i, y;
	int order;
	int yeardirlen;
	long long int total_size;

	nyears=0;
	if ((dirp = opendir(outdir)) == NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open directory \"%s\": %s\n"),outdir,strerror(errno));
		exit(EXIT_FAILURE);
	}
	while ((direntp = readdir( dirp )) != NULL) {
		if (!isdigit(direntp->d_name[0]) || !isdigit(direntp->d_name[1]) ||
		   !isdigit(direntp->d_name[2]) || !isdigit(direntp->d_name[3])) continue;
		year=atoi(direntp->d_name) << 10;
		if (direntp->d_name[4]=='-')
		{
			if (!isdigit(direntp->d_name[5]) || !isdigit(direntp->d_name[6]) ||
			   !isdigit(direntp->d_name[7]) || !isdigit(direntp->d_name[8])) continue;
			if (direntp->d_name[9]) continue;
			year|=atoi(direntp->d_name+5);
		}
		else
		{
			if (direntp->d_name[4]) continue;
		}
		if (nyears>=sizeof(yearsort)/sizeof(yearsort[0])) {
			/*
			If too many years are listed in the directory, we ignore the earliest years. The yearsort array
			is big enough to accomodate the most ambitious use of sarg but this safety is added to prevent
			a crash should the directory be polluted by other entries.
			*/
			if (year>yearsort[0]) {
				for (i=1 ; i<nyears && year>yearsort[i] ; i++)
					yearsort[i-1]=yearsort[i];
				yearsort[i-1]=year;
			}
		} else {
			for (i=nyears ; i>0 &&  year<yearsort[i-1] ; i--) {
				yearsort[i]=yearsort[i-1];
			}
			yearsort[i]=year;
			nyears++;
		}
	}
	closedir( dirp );

	order=(strcmp(IndexSortOrder,"A") == 0) ? 1 : -1;

	if (snprintf(yearindex,sizeof(yearindex),"%s"INDEX_HTML_FILE,outdir)>=sizeof(yearindex)) {
		debuga(__FILE__,__LINE__,_("Resulting index file name too long. File name is \"%s/%s\""),outdir,INDEX_HTML_FILE);
		exit(EXIT_FAILURE);
	}
	if ((fp_ou=fopen(yearindex,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),yearindex,strerror(errno));
		exit(EXIT_FAILURE);
	}
	write_html_header(fp_ou,0,ngettext("SARG report","SARG reports",nyears),HTML_JS_NONE);
	close_html_header(fp_ou);
	fputs("<div class=\"index\"><table cellpadding=\"1\" cellspacing=\"2\">\n",fp_ou);
	fprintf(fp_ou,"<tr><th class=\"header_l\">%s</th>",_("YEAR"));
	if (IndexFields & INDEXFIELDS_DIRSIZE)
		fprintf(fp_ou,"<th class=\"header_l\">%s</th>",_("SIZE"));
	fputs("</tr>\n",fp_ou);

	yeardirlen=strlen(outdir);
	if (yeardirlen>=sizeof(yeardir)) {
		debuga(__FILE__,__LINE__,_("Path too long: "));
		debuga_more("%s",outdir);
		exit(EXIT_FAILURE);
	}
	strcpy(yeardir,outdir);

	for (y=0 ; y<nyears ; y++) {
		if (order>0)
			year=yearsort[y];
		else
			year=yearsort[nyears-1-y];
		if ((year & 0x3FF)==0)
			snprintf(yearnum,sizeof(yearnum),"%04d",year>>10);
		else
			snprintf(yearnum,sizeof(yearnum),"%04d-%04d",year>>10,year & 0x3FF);
		strcpy(yeardir+yeardirlen,yearnum);
		total_size=make_date_index_month(yeardir,sizeof(yeardir),order,yearnum);

		fprintf(fp_ou,"<tr><td class=\"data2\"><a href=\"%s/%s\">%s</a></td>",yearnum,INDEX_HTML_FILE,yearnum);
		if (IndexFields & INDEXFIELDS_DIRSIZE)
		{
			char size_str[40];

			strncpy(size_str,fixnum(total_size,1),sizeof(size_str)-1);
			size_str[sizeof(size_str)-1]='\0';
			fprintf(fp_ou,"<td class=\"data2\">%s</td>",size_str);
		}
		fputs("</tr>\n",fp_ou);
	}

	fputs("</table></div>\n",fp_ou);
	write_html_trailer(fp_ou);
	if (fclose(fp_ou)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),yearindex,strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static void make_file_index(void)
{
	#define MAX_CREATION_DATE 15
	FILE *fp_ou;
	DIR *dirp;
	struct dirent *direntp;
	char wdir[MAXLEN];
	char data[80];
	char ftime[9];
	char day[6], mon[8], year[40], hour[10];
	long long int tbytes;
	long long int media;
	int iyear, imonth, iday, ihour, iminute, isecond, idst;
	int nsort;
	int nallocated;
	int order;
	int i;
	int tuser;
	struct getwordstruct gwarea;
	struct sortstruct
	{
		int year, month, day, sortnum;
		char creationdate[MAX_CREATION_DATE];
		char *dirname;
		char date[60];
	} **sortlist, *item, **tempsort;

	if (snprintf(wdir,sizeof(wdir),"%s"INDEX_HTML_FILE,outdir)>=sizeof(wdir)) {
		debuga(__FILE__,__LINE__,_("Path too long: "));
		debuga_more("%s"INDEX_HTML_FILE,outdir);
		exit(EXIT_FAILURE);
	}

	order=(strcmp(IndexSortOrder,"A") == 0) ? 1 : -1;

	if ((dirp = opendir(outdir)) == NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open directory \"%s\": %s\n"),outdir,strerror(errno));
		exit(EXIT_FAILURE);
	}

	nsort=0;
	nallocated=0;
	sortlist=NULL;
	while ((direntp = readdir( dirp )) != NULL) {
		if (strchr(direntp->d_name,'-') == 0) continue;
		if (obtdate(outdir,direntp->d_name,data)<0) {
			debuga(__FILE__,__LINE__,_("The directory \"%s%s\" looks like a report directory but doesn't contain a sarg-date file. You should delete it\n"),outdir,direntp->d_name);
			continue;
		}
		item=malloc(sizeof(*item));
		if (!item) {
			debuga(__FILE__,__LINE__,_("not enough memory to sort the index\n"));
			exit(EXIT_FAILURE);
		}
		if (df=='u') {
			item->year=atoi(direntp->d_name);
			item->month=conv_month(direntp->d_name+4);
			item->day=atoi(direntp->d_name+7);
		} else {
			item->year=atoi(direntp->d_name+5);
			item->month=conv_month(direntp->d_name+2);
			item->day=atoi(direntp->d_name);
		}
		item->sortnum=(item->year*16+item->month)*32+item->day;
		if (sscanf(data,"%d-%d-%d %d:%d:%d %d",&iyear,&imonth,&iday,&ihour,&iminute,&isecond,&idst)==7) {
			formatdate(data,sizeof(data),iyear,imonth,iday,ihour,iminute,isecond,idst);
			snprintf(item->creationdate,sizeof(item->creationdate),"%04d%02d%02d%02d%02d%02d",iyear,imonth,iday,ihour,iminute,isecond);
		} else {
			/*
			Old code to parse a date stored by sarg before 2.2.6.1 in the sarg-date file of each report directory.
			*/
			getword_start(&gwarea,data);
			if (getword_skip(16,&gwarea,' ')<0) {
				debuga(__FILE__,__LINE__,_("Invalid date in file \"%s%s/sarg-date\"\n"),outdir,direntp->d_name);
				exit(EXIT_FAILURE);
			}
			if (getword_multisep(mon,sizeof(mon),&gwarea,' ')<0) {
				debuga(__FILE__,__LINE__,_("Invalid date in file \"%s%s/sarg-date\"\n"),outdir,direntp->d_name);
				exit(EXIT_FAILURE);
			}
			if (getword_multisep(day,sizeof(day),&gwarea,' ')<0) {
				debuga(__FILE__,__LINE__,_("Invalid date in file \"%s%s/sarg-date\"\n"),outdir,direntp->d_name);
				exit(EXIT_FAILURE);
			}
			if (getword_multisep(hour,sizeof(hour),&gwarea,' ')<0) {
				debuga(__FILE__,__LINE__,_("Invalid time in file \"%s%s/sarg-date\"\n"),outdir,direntp->d_name);
				exit(EXIT_FAILURE);
			}
			do {
				if (getword_multisep(year,sizeof(year),&gwarea,' ')<0) {
					debuga(__FILE__,__LINE__,_("Invalid date in file \"%s%s/sarg-date\"\n"),outdir,direntp->d_name);
					exit(EXIT_FAILURE);
				}
			} while (year[0] && !isdigit(year[0])); //skip time zone information with spaces until the year is found
			if (sscanf(hour,"%d:%d:%d",&ihour,&iminute,&isecond)!=3) {
				debuga(__FILE__,__LINE__,_("Invalid time in file \"%s%s/sarg-date\"\n"),outdir,direntp->d_name);
				exit(EXIT_FAILURE);
			}
			buildymd(day,mon,year,ftime,sizeof(ftime));
			snprintf(item->creationdate,sizeof(item->creationdate),"%s%02d%02d%02d",ftime, ihour, iminute, isecond);
		}
		item->dirname=strdup(direntp->d_name);
		if (!item->dirname) {
			debuga(__FILE__,__LINE__,_("Not enough memory to store the directory name \"%s\" in the index\n"),direntp->d_name);
			exit(EXIT_FAILURE);
		}
		safe_strcpy(item->date,data,sizeof(item->date));
		if (nsort+1>nallocated) {
			nallocated+=10;
			tempsort=realloc(sortlist,nallocated*sizeof(*item));
			if (!tempsort) {
				debuga(__FILE__,__LINE__,_("not enough memory to sort the index\n"));
				exit(EXIT_FAILURE);
			}
			sortlist=tempsort;
		}
		for (i=nsort ; i>0 ; i--) {
			if (item->sortnum>sortlist[i-1]->sortnum) break;
			if (item->sortnum==sortlist[i-1]->sortnum) {
				if (strcmp(item->creationdate,sortlist[i-1]->creationdate)>=0) break;
			}
			sortlist[i]=sortlist[i-1];
		}
		sortlist[i]=item;
		nsort++;
	}

	closedir( dirp );

	if ((fp_ou=fopen(wdir,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),wdir,strerror(errno));
		exit(EXIT_FAILURE);
	}
	write_html_header(fp_ou,0,ngettext("SARG report","SARG reports",nsort),HTML_JS_SORTTABLE);
	close_html_header(fp_ou);
	fputs("<div class=\"index\"><table cellpadding=\"1\" cellspacing=\"2\"",fp_ou);
	if (SortTableJs[0]) fputs(" class=\"sortable\"",fp_ou);
	fputs(">\n",fp_ou);
	fprintf(fp_ou,"<thead><tr><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th><th class=\"header_l\">%s</th></tr></thead>\n",
			_("FILE/PERIOD"),_("CREATION DATE"),_("USERS"),_("BYTES"),_("AVERAGE"));
	for (i=0 ; i<nsort ; i++) {
		if (order>0)
			item=sortlist[i];
		else
			item=sortlist[nsort-i-1];
		tuser=obtuser(outdir,item->dirname);
		obttotal(outdir,item->dirname,tuser,&tbytes,&media);
		fputs("<tr><td class=\"data2\"",fp_ou);
		if (SortTableJs[0]) fprintf(fp_ou," sorttable_customkey=\"%d\"",item->sortnum);
		fprintf(fp_ou,"><a href='%s/%s'>%s</a></td>",item->dirname,ReplaceIndex,item->dirname);
		fputs("<td class=\"data2\"",fp_ou);
		if (SortTableJs[0]) fprintf(fp_ou," sorttable_customkey=\"%s\"",item->creationdate);
		fprintf(fp_ou,">%s</td>",item->date);
		fprintf(fp_ou,"<td class=\"data\">%d</td>",tuser);
		fputs("<td class=\"data\"",fp_ou);
		if (SortTableJs[0]) fprintf(fp_ou," sorttable_customkey=\"%"PRId64"\"",(int64_t)tbytes);
		fprintf(fp_ou,">%s</td>",fixnum(tbytes,1));
		fputs("<td class=\"data\"",fp_ou);
		if (SortTableJs[0]) fprintf(fp_ou," sorttable_customkey=\"%"PRId64"\"",(int64_t)media);
		fprintf(fp_ou,">%s</td></tr>\n",fixnum(media,1));
	}
	fputs("</table></div>\n",fp_ou);
	write_html_trailer(fp_ou);
	if (fclose(fp_ou)==EOF)
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),wdir,strerror(errno));

	if (sortlist) {
		for (i=0 ; i<nsort ; i++) {
			free(sortlist[i]->dirname);
			free(sortlist[i]);
		}
		free(sortlist);
	}
}

static void file_index_to_date_index(const char *entry)
{
	int y1, y2, m1, m2, d1, d2;
	int i, j;
	int ndirlen;
	int monthlen;
	char sm1[8], sm2[8];
	char olddir[MAXLEN], newdir[MAXLEN];

	if (strlen(entry) < 19) return;

	y1=0;
	y2=0;
	memset(sm1,0,sizeof(sm1));
	memset(sm2,0,sizeof(sm2));
	d1=0;
	d2=0;
	i=0;
	if (df=='u') {
		for (j=0 ; entry[i] && isdigit(entry[i]) ; j++)
			y1=y1*10+(entry[i++]-'0');
		if (j!=4) return;
		for (j=0 ; j<sizeof(sm1)-1 && entry[i] && isalpha(entry[i]) ; j++)
			sm1[j]=entry[i++];
		if (j!=3) return;
		sm1[j]='\0';
		for (j=0 ; entry[i] && isdigit(entry[i]) ; j++)
			d1=d1*10+(entry[i++]-'0');
		if (j!=2) return;

		if (entry[i++]!='-') return;

		for (j=0 ; entry[i] && isdigit(entry[i]) ; j++)
			y2=y2*10+(entry[i++]-'0');
		if (j!=4) return;
		for (j=0 ; j<sizeof(sm2)-1 && entry[i] && isalpha(entry[i]) ; j++)
			sm2[j]=entry[i++];
		if (j!=3) return;
		sm2[j]='\0';
		for (j=0 ; entry[i] && isdigit(entry[i]) ; j++)
			d2=d2*10+(entry[i++]-'0');
		if (j!=2) return;
	} else if (df=='e') {
		for (j=0 ; entry[i] && isdigit(entry[i]) ; j++)
			d1=d1*10+(entry[i++]-'0');
		if (j!=2) return;
		for (j=0 ; j<sizeof(sm1)-1 && entry[i] && isalpha(entry[i]) ; j++)
			sm1[j]=entry[i++];
		if (j!=3) return;
		sm1[j]='\0';
		for (j=0 ; entry[i] && isdigit(entry[i]) ; j++)
			y1=y1*10+(entry[i++]-'0');
		if (j!=4) return;

		if (entry[i++]!='-') return;

		for (j=0 ; entry[i] && isdigit(entry[i]) ; j++)
			d2=d2*10+(entry[i++]-'0');
		if (j!=2) return;
		for (j=0 ; j<sizeof(sm2)-1 && entry[i] && isalpha(entry[i]) ; j++)
			sm2[j]=entry[i++];
		if (j!=3) return;
		sm2[j]='\0';
		for (j=0 ; entry[i] && isdigit(entry[i]) ; j++)
			y2=y2*10+(entry[i++]-'0');
		if (j!=4) return;
	} else
		return;

	m1=conv_month(sm1);
	m2=conv_month(sm2);
	ndirlen=snprintf(newdir,sizeof(newdir),"%s%04d",outdir,y1);
	if (ndirlen>=sizeof(newdir)) {
		debuga(__FILE__,__LINE__,_("Path too long: "));
		debuga_more("%s%04d",outdir,y1);
		exit(EXIT_FAILURE);
	}
	if (access(newdir, R_OK) != 0) {
		if (PortableMkDir(newdir,0755)) {
			debuga(__FILE__,__LINE__,_("Cannot create directory \"%s\": %s\n"),newdir,strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	if (m1 != m2) ndirlen+=snprintf(newdir+ndirlen,sizeof(newdir)-ndirlen,"/%02d-%02d",m1,m2);
	else ndirlen+=snprintf(newdir+ndirlen,sizeof(newdir)-ndirlen,"/%02d",m1);
	if (ndirlen>=sizeof(newdir)) {
		debuga(__FILE__,__LINE__,_("Path too long: "));
		debuga_more("%s",newdir);
		exit(EXIT_FAILURE);
	}
	if (access(newdir, R_OK) != 0) {
		if (PortableMkDir(newdir,0755)) {
			debuga(__FILE__,__LINE__,_("Cannot create directory \"%s\": %s\n"),newdir,strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	monthlen=ndirlen;
	if (d1!=d2) ndirlen+=snprintf(newdir+ndirlen,sizeof(newdir)-ndirlen,"/%02d-%02d",d1,d2);
	else ndirlen+=snprintf(newdir+ndirlen,sizeof(newdir)-ndirlen,"/%02d",d1);
	if (ndirlen>=sizeof(newdir)) {
		debuga(__FILE__,__LINE__,_("Path too long: "));
		debuga_more("%s",newdir);
		exit(EXIT_FAILURE);
	}

	if (snprintf(olddir,sizeof(olddir),"%s%s",outdir,entry)>=sizeof(olddir)) {
		debuga(__FILE__,__LINE__,_("Path too long: "));
		debuga_more("%s%s",outdir,entry);
		exit(EXIT_FAILURE);
	}
	if (rename(olddir,newdir)) {
		debuga(__FILE__,__LINE__,_("Error renaming \"%s\" to \"%s\": %s\n"),olddir,newdir,strerror(errno));
		exit(EXIT_FAILURE);
	}

	strcpy(newdir+monthlen,"/images");
	if (access(newdir, R_OK) != 0) {
#ifdef HAVE_SYMLINK
		char linkdir[MAXLEN];

		format_path(__FILE__, __LINE__, linkdir, sizeof(linkdir), "%simages", outdir);
		if (symlink(linkdir,newdir)) {
			debuga(__FILE__,__LINE__,_("Failed to create link \"%s\" to \"%s\": %s\n"),linkdir,newdir,strerror(errno));
			exit(EXIT_FAILURE);
		}
#else
		char cmd[MAXLEN];
		int cstatus;

		sprintf(cmd,"ln -s \"%simages\" \"%s/images\"",outdir,newdir);
		cstatus=system(cmd);
		if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
			debuga(__FILE__,__LINE__,_("command return status %d\n"),WEXITSTATUS(cstatus));
			debuga(__FILE__,__LINE__,_("command: %s\n"),cmd);
			exit(EXIT_FAILURE);
		}
#endif
	}
}

static void date_index_to_file_index(const char *entry)
{
	int y1, next;
	int m1, m2;
	int d1, d2;
	int val1len;
	int i, j;
	char val1[MAXLEN];
	const char *sm1, *sm2;
	char *str;
	char newdir[MAXLEN], olddir[MAXLEN];
	DIR *dirp2, *dirp3;
	struct dirent *direntp2;
	struct dirent *direntp3;

	if (strlen(entry) != 4) return;

	next=-1;
	if (sscanf(entry,"%d%n",&y1,&next)!=1 || next<0 || entry[next]) return;

	val1len=snprintf(val1,sizeof(val1),"%s%s",outdir,entry);
	dirp2 = opendir(val1);
	if (!dirp2) return;
	while ((direntp2 = readdir( dirp2 )) != NULL) {
		if (!isdigit(direntp2->d_name[0]) || !isdigit(direntp2->d_name[1])) continue;
		i=0;
		str=direntp2->d_name;
		m1=0;
		for (j=0 ; j<2 && str[i] && isdigit(str[i]) ; j++)
			m1=(m1*10)+(str[i++]-'0');
		if (j>=2) continue;
		sm1=conv_month_name(m1);
		if (str[i]=='-') {
			i++;
			m2=0;
			for (j=0 ; j<2 && str[i] && isdigit(str[i]) ; j++)
				m2=(m2*10)+(str[i++]-'0');
			if (j>=2) continue;
			sm2=conv_month_name(m2);
		} else if (!str[i]) {
			sm2=sm1;
		} else {
			continue;
		}

		sprintf(val1+val1len,"/%s",direntp2->d_name);
		dirp3 = opendir(val1);
		if (!dirp3) continue;
		while ((direntp3 = readdir( dirp3 )) != NULL) {
			if (!isdigit(direntp3->d_name[0]) || !isdigit(direntp3->d_name[1])) continue;
			i=0;
			str=direntp3->d_name;
			d1=0;
			for (j=0 ; str[i] && isdigit(str[i]) ; j++)
				d1=d1*10+(str[i++]-'0');
			if (j!=2) continue;
			if (str[i]=='-') {
				i++;
				d2=0;
				for (j=0 ; str[i] && isdigit(str[i]) ; j++)
					d2=d2*10+(str[i++]-'0');
				if (j!=2) continue;
			} else if (!str[i]) {
				d2=d1;
			} else {
				continue;
			}

			if (df=='u') {
				format_path(__FILE__, __LINE__, newdir, sizeof(newdir), "%s%04d%s%02d-%04d%s%02d", outdir, y1, sm1, d1, y1, sm2, d2);
			} else if (df=='e') {
				format_path(__FILE__, __LINE__, newdir, sizeof(newdir), "%s%02d%s%04d-%02d%s%04d", outdir, d1, sm1, y1, d2, sm2, y1);
			} else {
				continue;
			}
			format_path(__FILE__, __LINE__, olddir, sizeof(olddir), "%s%04d/%s/%s", outdir, y1, direntp2->d_name, direntp3->d_name);
			if (rename(olddir,newdir)) {
				debuga(__FILE__,__LINE__,_("Error renaming \"%s\" to \"%s\": %s\n"),olddir,newdir,strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		closedir(dirp3);
	}
	closedir(dirp2);

	/*!
	\bug The links to the images in the reports are broken after moving the directories
	as the the HTML files are not at the right level for the images any more.
	*/
}

