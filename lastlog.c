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

struct DirEntry
{
	struct DirEntry *Next;
	time_t Time;
	char *Name;
};

static void DeleteDirList(struct DirEntry *List)
{
	struct DirEntry *Next;

	while (List)
	{
		Next=List->Next;
		if (List->Name) free(List->Name);
		free(List);
		List=Next;
	}
}

static struct DirEntry *AppendDirEntry(struct DirEntry *List,time_t CreationTime,const char *Name,int NameLen)
{
	struct DirEntry *entry;
	struct DirEntry *prev;
	struct DirEntry *ptr;

	entry=malloc(sizeof(*entry));
	if (!entry) {
		debuga(__FILE__,__LINE__,_("Not enough memory to store a report to purge\n"));
		DeleteDirList(List);
		return(NULL);
	}
	entry->Name=malloc((NameLen+1)*sizeof(char));
	if (!entry->Name) {
		free(entry);
		debuga(__FILE__,__LINE__,_("Not enough memory to store a report to purge\n"));
		DeleteDirList(List);
		return(NULL);
	}
	entry->Time=CreationTime;
	strcpy(entry->Name,Name);

	// store most recent file first
	prev=NULL;
	for (ptr=List ; ptr ; ptr=ptr->Next)
	{
		if (ptr->Time>CreationTime) break;
		prev=ptr;
	}
	entry->Next=ptr;
	if (prev)
		prev->Next=entry;
	else
		List=entry;

	return(List);
}

static struct DirEntry *BuildDirDateList(struct DirEntry *List,char *Path,int PathSize,int RootPos,int Length,int Level)
{
	DIR *dirp;
	struct dirent *direntp;
	struct stat statb;
	int name_len;

	if ((dirp = opendir(Path)) == NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open directory \"%s\": %s\n"),Path,strerror(errno));
		exit(EXIT_FAILURE);
	}
	while ((direntp = readdir( dirp )) != NULL )
	{
		name_len=strlen(direntp->d_name);
		if (RootPos+name_len+1>=PathSize) {
			debuga(__FILE__,__LINE__,_("Directory entry \"%s%s\" too long to purge the old reports\n"),Path,direntp->d_name);
			exit(EXIT_FAILURE);
		}
		strcpy(Path+Length,direntp->d_name);
		if (stat(Path,&statb) == -1) {
			debuga(__FILE__,__LINE__,_("Failed to get the statistics of file \"%s\": %s\n"),Path,strerror(errno));
			continue;
		}
		if (!S_ISDIR(statb.st_mode)) continue;
		if (Level==0)
		{
			if (IsTreeMonthFileName(direntp->d_name))
			{
				Path[Length+name_len]='/';
				Path[Length+name_len+1]='\0';
				List=BuildDirDateList(List,Path,PathSize,RootPos,Length+name_len+1,1);
				if (!List)
				{
					debuga(__FILE__,__LINE__,_("Old reports deletion not undertaken due to previous error\n"));
					break;
				}
			}
		}
		else if (Level==1)
		{
			if (IsTreeDayFileName(direntp->d_name))
			{
				List=AppendDirEntry(List,statb.st_mtime,Path+RootPos,Length-RootPos+name_len);
				if (!List)
				{
					debuga(__FILE__,__LINE__,_("Old reports deletion not undertaken due to previous error\n"));
					break;
				}
			}
		}
	}

	closedir(dirp);
	return(List);
}

static struct DirEntry *BuildDirList(const char *Path)
{
	DIR *dirp;
	struct dirent *direntp;
	struct stat statb;
	char warea[MAXLEN];
	int name_pos;
	int name_len;
	struct DirEntry *List=NULL;

	name_pos=strlen(Path);
	if (name_pos>=sizeof(warea)) {
		debuga(__FILE__,__LINE__,_("The directory name \"%s\" containing the old reports to purge is too long\n"),Path);
		exit(EXIT_FAILURE);
	}
	strcpy(warea,Path);
	if ((dirp = opendir(outdir)) == NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open directory \"%s\": %s\n"),outdir,strerror(errno));
		exit(EXIT_FAILURE);
	}
	while ((direntp = readdir( dirp )) != NULL )
	{
		name_len=strlen(direntp->d_name);
		if (name_pos+name_len+1>=sizeof(warea)) {
			debuga(__FILE__,__LINE__,_("Directory entry \"%s%s\" too long to purge the old reports\n"),Path,direntp->d_name);
			exit(EXIT_FAILURE);
		}
		strcpy(warea+name_pos,direntp->d_name);
		if (stat(warea,&statb) == -1) {
			debuga(__FILE__,__LINE__,_("Failed to get the statistics of file \"%s\": %s\n"),warea,strerror(errno));
			continue;
		}
		if (!S_ISDIR(statb.st_mode)) continue;
		if (IsTreeFileDirName(direntp->d_name))
		{
			List=AppendDirEntry(List,statb.st_mtime,direntp->d_name,name_len);
			if (!List)
			{
				debuga(__FILE__,__LINE__,_("Old reports deletion not undertaken due to previous error\n"));
				break;
			}
		}
		else if (IsTreeYearFileName(direntp->d_name))
		{
			warea[name_pos+name_len]='/';
			warea[name_pos+name_len+1]='\0';
			List=BuildDirDateList(List,warea,sizeof(warea),name_pos,name_pos+name_len+1,0);
			if (!List)
			{
				debuga(__FILE__,__LINE__,_("Old reports deletion not undertaken due to previous error\n"));
				break;
			}
		}
	}

	closedir(dirp);
	return(List);
}

static void DeleteEmptyDirs(char *Path,int PathSize,int BasePos)
{
	char *Dir;
	DIR *dirp;
	struct dirent *direntp;
	bool index;

	while ((Dir=strrchr(Path,'/'))!=NULL)
	{
		if (Dir-Path<=BasePos) break;
		*Dir='\0';
		if ((dirp = opendir(Path)) == NULL) {
			debuga(__FILE__,__LINE__,_("Cannot open directory \"%s\": %s\n"),Path,strerror(errno));
			return;
		}
		index=false;
		while ((direntp = readdir( dirp )) != NULL )
		{
			if (direntp->d_name[0]=='.' && (direntp->d_name[1]=='\0' || (direntp->d_name[1]=='.' && direntp->d_name[2]=='\0'))) continue;
			if (!strcmp(direntp->d_name,INDEX_HTML_FILE))
			{
				index=true;
				continue;
			}
			break;
		}
		closedir(dirp);
		if (direntp!=NULL) {
			// at least one file exists in the directory, don't delete the directory
			break;
		}
		if (debug)
			debuga(__FILE__,__LINE__,_("Deleting empty directory \"%s\"\n"),Path);
		if (index) {
			if (strlen(Path)+strlen(INDEX_HTML_FILE)+2>=PathSize) {
				debuga(__FILE__,__LINE__,_("Buffer too small to delete index file \"%s/%s\""),Path,INDEX_HTML_FILE);
				exit(EXIT_FAILURE);
			}
			strcat(Path,"/"INDEX_HTML_FILE);
			if (unlink(Path)==-1) {
				debuga(__FILE__,__LINE__,_("Failed to delete \"%s\": %s\n"),Path,strerror(errno));
				exit(EXIT_FAILURE);
			}
			*Dir='\0';
		}
		if (rmdir(Path)) {
			debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),Path,strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	//! \todo Rebuild the surviving index file
}

void mklastlog(const char *outdir)
{
	char warea[MAXLEN];
	int name_pos;
	int  ftot=0;
	struct DirEntry *List;
	struct DirEntry *ptr;

	if (LastLog <= 0)
		return;

	List=BuildDirList(outdir);
	if (!List) return;

	for (ptr=List ; ptr ; ptr=ptr->Next) ftot++;
	if (debug)
		debuga(__FILE__,__LINE__,ngettext("%d report directory found\n","%d report directories found\n",ftot),ftot);

	if (ftot<=LastLog) {
		DeleteDirList(List);
		if (debug) {
			debuga(__FILE__,__LINE__,ngettext("No old reports to delete as only %d report currently exists\n",
						"No old reports to delete as only %d reports currently exist\n",ftot),ftot);
		}
		return;
	}

	ftot-=LastLog;
	if (debug)
		debuga(__FILE__,__LINE__,ngettext("%d old report to delete\n","%d old reports to delete\n",ftot),ftot);

	name_pos=strlen(outdir);
	if (name_pos>=sizeof(warea)) {
		DeleteDirList(List);
		debuga(__FILE__,__LINE__,_("The directory name \"%s\" containing the old reports to purge is too long\n"),outdir);
		exit(EXIT_FAILURE);
	}
	strcpy(warea,outdir);
	for (ptr=List ; ptr && ftot>0 ; ptr=ptr->Next)
	{
		if (debug)
			debuga(__FILE__,__LINE__,_("Removing old report file %s\n"),ptr->Name);
		if (name_pos+strlen(ptr->Name)+1>=sizeof(warea)) {
			DeleteDirList(List);
			debuga(__FILE__,__LINE__,_("Path too long: "));
			debuga_more("%s%s\n",outdir,ptr->Name);
			exit(EXIT_FAILURE);
		}
		strcpy(warea+name_pos,ptr->Name);
		unlinkdir(warea,0);
		DeleteEmptyDirs(warea,sizeof(warea),name_pos);
		ftot--;
	}

	DeleteDirList(List);
	return;
}
