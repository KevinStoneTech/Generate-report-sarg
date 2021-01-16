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
#include "include/stringbuffer.h"
#include "include/filelist.h"
#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

struct DirEntryStruct
{
	//! Next entry at the same level.
	struct DirEntryStruct *Sibbling;
	//! First child of this entry.
	struct DirEntryStruct *Child;
	//! Name of this entry.
	char *Name;
	//! \c True if it contains any wildcard.
	bool IsMask;
};

/*!
 * \brief List of files.
 *
 * The list may contain wildcards.
 */
struct FileListStruct
{
	//! Root of the tree.
	struct DirEntryStruct *First;
	//! Buffer containing the file name strings.
	StringBufferObject Buffer;
	//! Deepest level of the tree.
	int TreeDepth;
	//! \c True if the tree depth is correct.
	bool TreeDepthOk;
};

struct DirEntryIterator
{
	//! The current node at each level.
	struct DirEntryStruct *Dir;
	//! Length of the path up to that level.
	int PathLength;
};

/*!
 * \brief Iterator of the file list.
 */
struct _FileListIterator
{
	//! File list object from which we are iterating.
	FileListObject Parent;
	//! Current path being stored in the object.
	char *CurrentPath;
	//! Number of bytes allocated for the current path.
	int CurrentPathSize;
	//! Level known to be stored in the path.
	int CurrentPathLevel;
	//! Tree depth when the iteration started.
	int TreeDepth;
	//! Current level being iterated over.
	int Level;
	//! The current node at each level.
	struct DirEntryIterator *DirNodes;
#ifdef HAVE_GLOB_H
	//! Next globbed file to return
	int NextGlob;
	//! Buffer with the globbed files.
	glob_t Glob;
#endif
};


/*!
 * Create an object to store the files to process.
 *
 * \return The created object or NULL if it failed.
 * The object must be destroyed with a call to FileList_Destroy().
 */
FileListObject FileList_Create(void)
{
	FileListObject FObj;

	FObj=(FileListObject)calloc(1,sizeof(*FObj));
	if (!FObj)
		return(NULL);

	return(FObj);
}

/*!
 * Destroy the entries tree.
 */
static void FileList_DestroyEntry(struct DirEntryStruct *Entry)
{
	struct DirEntryStruct *Next;

	while (Entry)
	{
		if (Entry->Child)
			FileList_DestroyEntry(Entry->Child);
		Next=Entry->Sibbling;
		free(Entry);
		Entry=Next;
	}
}

/*!
 * Destroy the object created by FileList_Create().
 *
 * \param FPtr A pointer to the object to destroy. It is
 * reset to NULL before the function returns.
 */
void FileList_Destroy(FileListObject *FPtr)
{
	FileListObject FObj;

	if (!FPtr || !*FPtr) return;
	FObj=*FPtr;
	*FPtr=NULL;

	FileList_DestroyEntry(FObj->First);
	StringBuffer_Destroy(&FObj->Buffer);
	free(FObj);
}

/*!
 * Store an entry in the tree.
 *
 * \param FObj The file list object created by FileList_Create().
 * \param FileName Name of the file to store recursively.
 *
 * \return The branch created with all the entries in \c FileName.
 * The returned value is NULL if \c FileName could not be added.
 */
static struct DirEntryStruct *FileList_StoreEntry(FileListObject FObj,const char *FileName)
{
	struct DirEntryStruct *Entry;
	int i;
	bool IsMask=false;
	int LastDir=-1;
	int Next=-1;

	Entry=(struct DirEntryStruct *)calloc(1,sizeof(*Entry));
	if (!Entry) return(NULL);
	for (i=0 ; FileName[i] ; i++)
	{
		if (FileName[i]=='/')
		{
			if (IsMask)
			{
				/* The path contains a wildcard. There are no directories
				 * before this path or it would have been caught by the other
				 * break in this loop. We store it.
				 */
				Next=i;
				break;
			}
			LastDir=i;
		}
		else if (FileName[i]=='*' || FileName[i]=='?')
		{
			if (LastDir>=0)
			{
				/* Some directories without wildcards before this directory
				 * with wildcard. We store the previous directories in one
				 * entry and disregard, for now, the current path level.
				 */
				Next=LastDir;
				break;
			}
			IsMask=true;
		}
	}
	Entry->Name=StringBuffer_StoreLength(FObj->Buffer,FileName,(Next<0) ? i : Next);
	if (!Entry->Name)
	{
		free(Entry);
		return(NULL);
	}
	Entry->IsMask=IsMask;
	if (Next>0)
	{
		FObj->TreeDepthOk=false; //it will have to be recomputed
		Entry->Child=FileList_StoreEntry(FObj,FileName+Next+1);
		if (!Entry->Child)
		{
			free(Entry);
			return(NULL);
		}
	}
	return(Entry);
}

/*!
 * Store a file in the internal data structure.
 *
 * \param FObj The file list object created by FileList_Create().
 * \param EntryPtr Pointer to the tree node to add or create.
 * \param FileName The name of the file.
 *
 * \return \c True on success or \c false on failure.
 */
static bool FileList_AddFileRecursive(FileListObject FObj,struct DirEntryStruct **EntryPtr,const char *FileName)
{
	int i;
	struct DirEntryStruct *Entry;
	struct DirEntryStruct *Last;
	int LastDir;

	if (!*EntryPtr)
	{
		Entry=FileList_StoreEntry(FObj,FileName);
		if (!Entry) return(false);
		*EntryPtr=Entry;
		return(true);
	}

	// find where to store the file name in the existing tree
	Last=NULL;
	for (Entry=*EntryPtr ; Entry ; Entry=Entry->Sibbling)
	{
		LastDir=-1;
		for (i=0 ; Entry->Name[i] && FileName[i] && Entry->Name[i]==FileName[i] ; i++)
		{
			if (FileName[i]=='/')
				LastDir=i;
		}
		if (FileName[i]=='/' && Entry->Name[i]=='\0')
		{
			//root is matching, check sub level
			return(FileList_AddFileRecursive(FObj,&Entry->Child,FileName+i+1));
		}
		if (LastDir>0)
		{
			//paths begin with the same directory but diverges at LastDir
			struct DirEntryStruct *Split;

			Split=(struct DirEntryStruct *)calloc(1,sizeof(*Split));
			if (!Split) return(false);
			Split->Name=Entry->Name+LastDir+1;
			Split->Child=Entry->Child;
			Entry->Name[LastDir]='\0';
			Entry->Child=Split;
			return(FileList_AddFileRecursive(FObj,&Entry->Child,FileName+LastDir+1));
		}
		Last=Entry;
	}

	// add a new entry
	Entry=FileList_StoreEntry(FObj,FileName);
	if (!Entry) return(false);
	Last->Sibbling=Entry;

	return(true);
}

/*!
 * Add a file to the object.
 *
 * \param FObj The object created by FileList_Create().
 * \param FileName The file name to add to the list.
 *
 * \return \c True if the file was added or \c false if it
 * failed. The function may fail if a parameter is invalid.
 * It will also fail if the memory cannot be allocated.
 */
bool FileList_AddFile(FileListObject FObj,const char *FileName)
{
	if (!FObj || !FileName) return(false);

	if (!FObj->Buffer)
	{
		FObj->Buffer=StringBuffer_Create();
		if (!FObj->Buffer)
			return(false);
	}

	return(FileList_AddFileRecursive(FObj,&FObj->First,FileName));
}

/*!
 * \brief Is the file list empty?
 *
 * \param FObj The file list to check.
 *
 * \return \c True if the file list is empty or \c false if
 * there is at least one file in the list.
 */
bool FileList_IsEmpty(FileListObject FObj)
{
	if (!FObj) return(true);
	if (FObj->First==NULL) return(true);
	return(false);
}

/*!
 * Recursively measure the tree depth.
 *
 * \param FObj File list object created by FileList_Create().
 * \param Entry Node whose child are to be processed.
 * \param Level Current level.
 */
static void FileList_SetDepth(FileListObject FObj,struct DirEntryStruct *Entry,int Level)
{
	if (Level>FObj->TreeDepth) FObj->TreeDepth=Level;
	while (Entry)
	{
		if (Entry->Child)
			FileList_SetDepth(FObj,Entry->Child,Level+1);
		Entry=Entry->Sibbling;
	}
}

/*!
 * Start the iteration over the files in the list.
 *
 * \param FObj The object to iterate over.
 *
 * \return The iterator structure to pass ot FileListIter_Next()
 * to get the first file name or NULL if an error occured.
 */
FileListIterator FileListIter_Open(FileListObject FObj)
{
	struct _FileListIterator *FIter;
	struct DirEntryStruct *Dir;

	if (!FObj) return(NULL);
	FIter=(FileListIterator)calloc(1,sizeof(*FIter));
	if (!FIter) return(NULL);
	FIter->Parent=FObj;

	// compute the depth of the tree.
	/*
	 * The tree depth computation is not thread safe. A lock is necessary around
	 * the following code to make it thread safe.
	 */
	if (!FObj->TreeDepthOk)
	{
		FObj->TreeDepth=0;
		if (FObj->First) FileList_SetDepth(FObj,FObj->First,1);
		FObj->TreeDepthOk=true;
	}
	FIter->TreeDepth=FObj->TreeDepth;
	FIter->Level=-1;
	FIter->CurrentPathSize=0;
	FIter->CurrentPathLevel=0;
	if (FIter->TreeDepth>0)
	{
		FIter->DirNodes=(struct DirEntryIterator *)calloc(FIter->TreeDepth,sizeof(struct DirEntryIterator));
		if (!FIter->DirNodes)
		{
			FileListIter_Close(FIter);
			return(NULL);
		}
		for (Dir=FObj->First ; Dir ; Dir=Dir->Child)
		{
			FIter->DirNodes[++FIter->Level].Dir=Dir;
		}
	}

	return(FIter);
}

/*!
 * Get the next entry in the directory tree.
 */
static void FileListIter_GetNext(struct _FileListIterator *FIter)
{
	struct DirEntryStruct *Dir;

	FIter->CurrentPathLevel=0;
	while (FIter->Level>=0)
	{
		Dir=FIter->DirNodes[FIter->Level].Dir;
		if (Dir->Sibbling)
		{
			Dir=Dir->Sibbling;
			FIter->DirNodes[FIter->Level].Dir=Dir;
			FIter->CurrentPathLevel=FIter->Level;
			while (Dir->Child)
			{
				if (FIter->Level>=FIter->TreeDepth) break;
				Dir=Dir->Child;
				FIter->DirNodes[++FIter->Level].Dir=Dir;
			}
			break;
		}
		FIter->Level--;
	}
}

/*!
 * Get the next file in the list.
 *
 * \param FIter The iterator created by FileListIter_Open().
 *
 * \return The iterator function containing the next file name or NULL
 * if there are no more files.
 */
const char *FileListIter_Next(struct _FileListIterator *FIter)
{
	const char *Path;

#ifdef HAVE_GLOB_H
	if (FIter->NextGlob>0)
	{
		if (FIter->NextGlob<FIter->Glob.gl_pathc)
		{
			Path=FIter->Glob.gl_pathv[FIter->NextGlob++];
			return(Path);
		}
		globfree(&FIter->Glob);
		FIter->NextGlob=0;
	}
	Path=FileListIter_NextWithMask(FIter);
	if (Path!=NULL && (Path[0]!='-' || Path[1]!='\0'))
	{
		int ErrCode=glob(Path,GLOB_ERR | GLOB_NOSORT,NULL,&FIter->Glob);
		if (ErrCode!=0)
		{
			switch (ErrCode)
			{
			case GLOB_NOSPACE:
				debuga(__FILE__,__LINE__,_("Not enough memory to read the files matching \"%s\"\n"),Path);
				break;
			case GLOB_ABORTED:
				debuga(__FILE__,__LINE__,_("Read error while listing the files matching \"%s\"\n"),Path);
				break;
			case GLOB_NOMATCH:
				debuga(__FILE__,__LINE__,_("No files matching \"%s\"\n"),Path);
				break;
			default:
				debuga(__FILE__,__LINE__,_("Failed to glob file pattern \"%s\" with unspecified error code %d"),Path,ErrCode);
				break;
			}
			exit(EXIT_FAILURE);
		}
		Path=FIter->Glob.gl_pathv[0];
		FIter->NextGlob=1;
	}
#else
	/*
	 * Fall back to a simple enumeration. In that case, the user cannot use
	 * wildcards as they won't be expended.
	 */
	Path=FileListIter_NextWithMask(FIter);
#endif
	return(Path);
}

/*!
 * Get the next file entry in the list without expanding the
 * wildcards.
 *
 * \param FIter The iterator created by FileListIter_Open().
 *
 * \return The iterator function containing the next file name or NULL
 * if there are no more files.
 */
const char *FileListIter_NextWithMask(struct _FileListIterator *FIter)
{
	int Length;
	int Level;
	struct DirEntryIterator *DIter;

	if (!FIter) return(NULL);
	if (!FIter->DirNodes) return(NULL);
	if (FIter->Level<0 || FIter->Level>=FIter->TreeDepth) return(NULL);

	// how much space to store the path
	Length=FIter->DirNodes[FIter->CurrentPathLevel].PathLength;
	for (Level=FIter->CurrentPathLevel ; Level<=FIter->Level ; Level++)
	{
		DIter=FIter->DirNodes+Level;
		DIter->PathLength=Length;
		Length+=strlen(DIter->Dir->Name)+1;
	}

	// get the memory to store the path
	if (Length>FIter->CurrentPathSize)
	{
		char *temp=realloc(FIter->CurrentPath,Length);
		if (!temp) return(NULL);
		FIter->CurrentPath=temp;
		FIter->CurrentPathSize=Length;
	}

	for (Level=FIter->CurrentPathLevel ; Level<=FIter->Level ; Level++)
	{
		DIter=FIter->DirNodes+Level;
		if (Level>0) FIter->CurrentPath[DIter->PathLength-1]='/';
		strcpy(FIter->CurrentPath+DIter->PathLength,DIter->Dir->Name);
	}
	FIter->CurrentPathLevel=Level;

	FileListIter_GetNext(FIter);
	return(FIter->CurrentPath);
}

/*!
 * Destroy the iterator created by FileListIter_Open().
 */
void FileListIter_Close(struct _FileListIterator *FIter)
{
	if (FIter)
	{
#ifdef HAVE_GLOB_H
		if (FIter->NextGlob>0) globfree(&FIter->Glob);
#endif
		if (FIter->CurrentPath) free(FIter->CurrentPath);
		if (FIter->DirNodes) free(FIter->DirNodes);
		free(FIter);
	}
}
