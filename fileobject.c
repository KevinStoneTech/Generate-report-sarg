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
/*!\file
\brief Encapsulate a file object

The file can be a standard file of the C library or a gzip file or
a bzip file.
*/

#include "include/conf.h"
#include "include/stringbuffer.h"
#include "include/fileobject.h"

//! Message describing the last open error.
static char LastOpenErrorString[2048]="";
//! Message describing the last close error.
static char LastCloseErrorString[2048]="";

/*!
 * Read a file using the standard C api.
 *
 * \param Data The file object.
 * \param Buffer The boffer to store the data read.
 * \param Size How many bytes to read.
 *
 * \return The number of bytes read.
 */
static int Standard_Read(void *Data,void *Buffer,int Size)
{
	return(fread(Buffer,1,Size,(FILE *)Data));
}

/*!
 * Check if end of file is reached.
 *
 * \param Data The file object.
 *
 * \return \c True if end of file is reached.
 */
static int Standard_Eof(void *Data)
{
	return(feof((FILE *)Data));
}

/*!
 * Return to the beginnig of the file.
 *
 * \param Data The file object.
 */
static void Standard_Rewind(void *Data)
{
	rewind((FILE *)Data);
}

/*!
 * Close a file using the standard C api.
 *
 * \param Data File to close.
 *
 * \return EOF on error.
 */
static int Standard_Close(void *Data)
{
	int RetCode=0;

	if (fclose((FILE *)Data)==EOF)
	{
		FileObject_SetLastCloseError(strerror(errno));
		RetCode=-1;
	}
	return(RetCode);
}

/*!
 * Open a file for reading using the standard C api.
 *
 * \param FileName The file to open.
 *
 * \return The object to pass to other function in this module.
 */
FileObject *FileObject_Open(const char *FileName)
{
	FileObject *File;

	LastOpenErrorString[0]='\0';
	File=malloc(sizeof(*File));
	if (!File)
	{
		FileObject_SetLastOpenError(_("Not enough memory"));
		return(NULL);
	}
	File->Data=MY_FOPEN(FileName,"r");
	if (!File->Data)
	{
		free(File);
		FileObject_SetLastOpenError(strerror(errno));
		return(NULL);
	}
	File->Read=Standard_Read;
	File->Eof=Standard_Eof;
	File->Rewind=Standard_Rewind;
	File->Close=Standard_Close;
	return(File);
}

/*!
 * Open a file for reading using the standard C api.
 *
 * \param FileName The file to open.
 *
 * \return The object to pass to other function in this module.
 */
FileObject *FileObject_FdOpen(int fd)
{
	FileObject *File;

	LastOpenErrorString[0]='\0';
	File=malloc(sizeof(*File));
	if (!File)
	{
		FileObject_SetLastOpenError(_("Not enough memory"));
		return(NULL);
	}
	File->Data=fdopen(fd,"r");
	if (!File->Data)
	{
		free(File);
		FileObject_SetLastOpenError(strerror(errno));
		return(NULL);
	}
	File->Read=Standard_Read;
	File->Eof=Standard_Eof;
	File->Rewind=Standard_Rewind;
	File->Close=Standard_Close;
	return(File);
}

/*!
 * Read the content of the file using the function identified
 * by the file object.
 *
 * \param File The file object to read.
 * \param Buffer The buffer to write the data into.
 * \param Size The maximum number of bytes to read.
 *
 * \return The number of bytes read or -1.
 */
int FileObject_Read(FileObject *File,void *Buffer,int Size)
{
	return(File->Read(File->Data,Buffer,Size));
}

/*!
 * Check if the end of file is reached.
 *
 * \param File The file object.
 *
 * \return \c True if end of file is reached.
 */
int FileObject_Eof(FileObject *File)
{
	return(File->Eof(File->Data));
}

/*!
 * Return to the beginning of the file.
 *
 * \param File The file object.
 */
void FileObject_Rewind(FileObject *File)
{
	File->Rewind(File->Data);
}

/*!
 * Close the file opened. The memory is freed. The object
 * cannot be reused after this function returns.
 *
 * \param File The file object to close.
 *
 * \return Zero on success or -1 on failure.
 */
int FileObject_Close(FileObject *File)
{
	LastCloseErrorString[0]='\0';
	int RetCode=File->Close(File->Data);
	free(File);
	return(RetCode);
}

/*!
 * Set the message returned by the last open error.
 *
 * \param Message The message explaining what error occurred
 * when the file was opened.
 */
void FileObject_SetLastOpenError(const char *Message)
{
	if (Message)
	{
		strncpy(LastOpenErrorString,Message,sizeof(LastOpenErrorString)-1);
		LastOpenErrorString[sizeof(LastOpenErrorString)-1]='\0';
	}
	else
		LastOpenErrorString[0]='\0';
}

/*!
 * Get a message explaining the last open error.
 *
 * \return The string to display to the user.
 */
const char *FileObject_GetLastOpenError(void)
{
	return(LastOpenErrorString);
}

/*!
 * Set the message returned by the last close error.
 *
 * \param Message The message explaining what error occurred
 * when the file was closed.
 */
void FileObject_SetLastCloseError(const char *Message)
{
	if (Message)
	{
		strncpy(LastCloseErrorString,Message,sizeof(LastCloseErrorString)-1);
		LastCloseErrorString[sizeof(LastCloseErrorString)-1]='\0';
	}
	else
		LastCloseErrorString[0]='\0';
}

/*!
 * Get a message explaining the last close error.
 *
 * \return The string to display to the user.
 */
const char *FileObject_GetLastCloseError(void)
{
	return(LastCloseErrorString);
}
