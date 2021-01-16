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
#ifdef HAVE_ZLIB_H
#include "zlib.h"
#endif
#ifdef HAVE_BZLIB_H
#include "bzlib.h"
#endif
#ifdef HAVE_LZMA_H
#include "lzma.h"
#endif

#ifdef HAVE_ZLIB_H
/*!
 * Read from gzip file.
 *
 * \param Data The file object.
 * \param Buffer The boffer to store the data read.
 * \param Size How many bytes to read.
 *
 * \return The number of bytes read.
 */
static int Gzip_Read(void *Data,void *Buffer,int Size)
{
	return(gzread((gzFile)Data,Buffer,Size));
}

/*!
 * Check if end of file is reached.
 *
 * \param Data The file object.
 *
 * \return \c True if end of file is reached.
 */
static int Gzip_Eof(void *Data)
{
	return(gzeof((gzFile)Data));
}

/*!
 * Return to the beginnig of the file.
 *
 * \param Data The file object.
 */
static void Gzip_Rewind(void *Data)
{
	gzrewind((gzFile)Data);
}

/*!
 * Close the file.
 *
 * \param Data File to close.
 *
 * \return 0 on success or -1 on error.
 */
static int Gzip_Close(void *Data)
{
	int RetCode=-1;
	int Status;

	Status=gzclose((gzFile)Data);
	switch (Status)
	{
	case Z_OK:
		RetCode=0;
		break;
	case Z_STREAM_ERROR:
		FileObject_SetLastCloseError(_("Invalid gzip file"));
		break;
	case Z_ERRNO:
		FileObject_SetLastCloseError(_("File operation error"));
		break;
	case Z_MEM_ERROR:
		FileObject_SetLastCloseError(_("Not enough memory"));
		break;
	case Z_BUF_ERROR:
		FileObject_SetLastCloseError(_("Truncated gzip stream"));
		break;
	default:
		FileObject_SetLastCloseError(_("Unknown error returned by zlib"));
		break;
	}
	return(RetCode);
}

/*!
 * Open a file object to read from a gzip file.
 *
 * \return The object to pass to other function in this module.
 */
static FileObject *Gzip_Open(int fd)
{
	FileObject *File;

	FileObject_SetLastOpenError(NULL);
	File=calloc(1,sizeof(*File));
	if (!File)
	{
		FileObject_SetLastOpenError(_("Not enough memory"));
		return(NULL);
	}
	File->Data=gzdopen(fd,"rb");
	if (!File->Data)
	{
		free(File);
		FileObject_SetLastOpenError(_("Error opening gzip file"));
		return(NULL);
	}
	File->Read=Gzip_Read;
	File->Eof=Gzip_Eof;
	File->Rewind=Gzip_Rewind;
	File->Close=Gzip_Close;
	return(File);
}
#endif

#ifdef HAVE_BZLIB_H

struct BzlibInternalFile
{
	//! Bzlib object.
	BZFILE *BzFile;
	//! \c True if end of file is reached.
	bool Eof;
	//! Original file in case a rewind is necessary.
	FILE *File;
};

/*!
 * Read from bzip file.
 *
 * \param Data The file object.
 * \param Buffer The boffer to store the data read.
 * \param Size How many bytes to read.
 *
 * \return The number of bytes read.
 */
static int Bzip_Read(void *Data,void *Buffer,int Size)
{
	struct BzlibInternalFile *BData=(struct BzlibInternalFile *)Data;
	int nread;
	int bzerr=BZ_OK;

	if (BData->Eof) return(0);
	nread=BZ2_bzRead(&bzerr,BData->BzFile,Buffer,Size);
	if (bzerr==BZ_STREAM_END)
		BData->Eof=true;
	else if (bzerr!=BZ_OK)
		return(0);
	return(nread);
}

/*!
 * Check if end of file is reached.
 *
 * \param Data The file object.
 *
 * \return \c True if end of file is reached.
 */
static int Bzip_Eof(void *Data)
{
	struct BzlibInternalFile *BData=(struct BzlibInternalFile *)Data;
	return(BData->Eof);
}

/*!
 * Return to the beginnig of the file.
 *
 * \param Data The file object.
 */
static void Bzip_Rewind(void *Data)
{
	struct BzlibInternalFile *BData=(struct BzlibInternalFile *)Data;
	int bzerr=BZ_OK;

	BZ2_bzReadClose(&bzerr,BData->BzFile);
	rewind(BData->File);
	BData->BzFile=BZ2_bzReadOpen(&bzerr,BData->File,0,0,NULL,0);
	if (!BData->BzFile)
	{
		debuga(__FILE__,__LINE__,_("Cannot rewind bzip file\n"));
		exit(EXIT_FAILURE);
	}
	BData->Eof=false;
}

/*!
 * Close the file.
 *
 * \param Data File to close.
 *
 * \return 0 on success or -1 on error.
 */
static int Bzip_Close(void *Data)
{
	struct BzlibInternalFile *BData=(struct BzlibInternalFile *)Data;
	int bzerr=BZ_OK;

	BZ2_bzReadClose(&bzerr,BData->BzFile);
	fclose(BData->File);
	free(BData);
	return(0);
}

/*!
 * Open a file object to read from a bzip file.
 *
 * \return The object to pass to other function in this module.
 */
static FileObject *Bzip_Open(int fd)
{
	FileObject *File;
	struct BzlibInternalFile *BData;
	int bzerr=BZ_OK;

	FileObject_SetLastOpenError(NULL);
	File=calloc(1,sizeof(*File));
	if (!File)
	{
		FileObject_SetLastOpenError(_("Not enough memory"));
		return(NULL);
	}
	BData=calloc(1,sizeof(*BData));
	if (!BData)
	{
		free(File);
		FileObject_SetLastOpenError(_("Not enough memory"));
		return(NULL);
	}
	BData->File=fdopen(fd,"rb");
	if (BData->File==NULL)
	{
		free(BData);
		free(File);
		FileObject_SetLastOpenError(_("Error duplicating file descriptor"));
		return(NULL);
	}
	File->Data=BData;
	BData->BzFile=BZ2_bzReadOpen(&bzerr,BData->File,0,0,NULL,0);
	if (!BData->BzFile)
	{
		fclose(BData->File);
		free(BData);
		free(File);
		FileObject_SetLastOpenError(_("Error opening bzip file"));
		return(NULL);
	}
	File->Read=Bzip_Read;
	File->Eof=Bzip_Eof;
	File->Rewind=Bzip_Rewind;
	File->Close=Bzip_Close;
	return(File);
}
#endif

#ifdef HAVE_LZMA_H

struct LzmaInternalFile
{
	//! Lzma stream.
	lzma_stream Stream;
	//! \c True if end of file is reached.
	bool Eof;
	//! Original file in case a rewind is necessary.
	FILE *File;
	//! Input buffer to store data read from the log file.
	unsigned char InputBuffer[128*1024];
};

/*!
 * Read from xz file.
 *
 * \param Data The file object.
 * \param Buffer The boffer to store the data read.
 * \param Size How many bytes to read.
 *
 * \return The number of bytes read.
 */
static int Lzma_Read(void *Data,void *Buffer,int Size)
{
	struct LzmaInternalFile *BData=(struct LzmaInternalFile *)Data;
	lzma_ret zerr;

	BData->Stream.next_out=Buffer;
	BData->Stream.avail_out=Size;
	while (BData->Stream.avail_out>0 && !BData->Eof)
	{
		if (BData->Stream.avail_in==0 && !BData->Eof)
		{
			BData->Stream.next_in=BData->InputBuffer;
			BData->Stream.avail_in=fread(BData->InputBuffer,1,sizeof(BData->InputBuffer),BData->File);
			if (feof(BData->File))
				BData->Eof=true;
		}
		zerr=lzma_code(&BData->Stream,(BData->Eof) ? LZMA_FINISH : LZMA_RUN);
		if (zerr==LZMA_STREAM_END)
		{
			BData->Eof=true;
		}
		else if (zerr!=LZMA_OK)
		{
			debuga(__FILE__,__LINE__,_("Error decompressiong xz file (lzma library returned error %d)"),zerr);
			return(0);
		}
	}
	return(Size-BData->Stream.avail_out);
}

/*!
 * Check if end of file is reached.
 *
 * \param Data The file object.
 *
 * \return \c True if end of file is reached.
 */
static int Lzma_Eof(void *Data)
{
	struct LzmaInternalFile *BData=(struct LzmaInternalFile *)Data;
	return(BData->Eof);
}

/*!
 * Initialize the lzma decoding stream.
 *
 * \param Stream Lzma stream to initialize.
 *
 * \return 0 on success or -1 if the intialization failed. A suitable
 * error message is displayed in case of error.
 */
static int Lzma_InitDecoder(lzma_stream *Stream)
{
	lzma_ret zerr;

	zerr=lzma_stream_decoder(Stream,UINT64_MAX,LZMA_CONCATENATED);
	if (zerr!=LZMA_OK)
	{
		switch (zerr)
		{
			case LZMA_MEM_ERROR:
				FileObject_SetLastOpenError(_("Not enough memory to initialize LZMA decoder"));
				break;
			case LZMA_OPTIONS_ERROR:
				FileObject_SetLastOpenError(_("Failed to initialize LZMA decoder due to invalid option passed to the decoder"));
				break;
			default:
			{
				char ErrMsg[80];

				snprintf(ErrMsg,sizeof(ErrMsg),_("Failed to initialize LZMA decoder with unknown error %d"),zerr);
				FileObject_SetLastOpenError(ErrMsg);
				break;
			}
		}
		return(-1);
	}
	return(0);
}

/*!
 * Return to the beginnig of the file.
 *
 * \param Data The file object.
 */
static void Lzma_Rewind(void *Data)
{
	struct LzmaInternalFile *BData=(struct LzmaInternalFile *)Data;

	rewind(BData->File);
	BData->Eof=false;
	memset(&BData->Stream,0,sizeof(BData->Stream));
	if (Lzma_InitDecoder(&BData->Stream)<0)
	{
		debuga(__FILE__,__LINE__,_("Failed to rewind the xz file (see previous LZMA error)\n"));
		exit(EXIT_FAILURE);
	}
}

/*!
 * Close the file.
 *
 * \param Data File to close.
 *
 * \return 0 on success or -1 on error.
 */
static int Lzma_Close(void *Data)
{
	struct LzmaInternalFile *BData=(struct LzmaInternalFile *)Data;

	fclose(BData->File);
	lzma_end(&BData->Stream);
	free(BData);
	return(0);
}

/*!
 * Open a file object to read from a xz file.
 *
 * \return The object to pass to other function in this module.
 */
static FileObject *Lzma_Open(int fd)
{
	FileObject *File;
	struct LzmaInternalFile *BData;

	FileObject_SetLastOpenError(NULL);
	File=calloc(1,sizeof(*File));
	if (!File)
	{
		FileObject_SetLastOpenError(_("Not enough memory"));
		return(NULL);
	}
	BData=calloc(1,sizeof(*BData));
	if (!BData)
	{
		free(File);
		FileObject_SetLastOpenError(_("Not enough memory"));
		return(NULL);
	}
	BData->File=fdopen(fd,"rb");
	if (BData->File==NULL)
	{
		free(BData);
		free(File);
		FileObject_SetLastOpenError(_("Error duplicating file descriptor"));
		return(NULL);
	}
	if (Lzma_InitDecoder(&BData->Stream)<0)
	{
		fclose(BData->File);
		free(BData);
		free(File);
		return(NULL);
	}
	File->Data=BData;
	File->Read=Lzma_Read;
	File->Eof=Lzma_Eof;
	File->Rewind=Lzma_Rewind;
	File->Close=Lzma_Close;
	return(File);
}
#endif


/*!
Open the log file. If it is compressed, uncompress it with the proper library.

Log files compressed with gzip, bzip2 can be uncompressed if sarg is compiled with
the proper library.

If the log file does not exist, the process terminates with an error message.

\param arq The log file to process.
*/
FileObject *decomp(const char *arq)
{
	int fd;
	FileObject *fi;
	unsigned char buf[5];
	ssize_t nread;

	// guess file type
	fd=open(arq,O_RDONLY | O_LARGEFILE);
	if (fd==-1) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),arq,strerror(errno));
		exit(EXIT_FAILURE);
	}
	nread=read(fd,buf,sizeof(buf));
	if (nread==-1) {
		debuga(__FILE__,__LINE__,_("Error while reading \"%s\" to guess its type: %s\n"),arq,strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (nread<sizeof(buf)) {
		debuga(__FILE__,__LINE__,_("File \"%s\" is too small to guess its type\n"),arq);
		exit(EXIT_FAILURE);
	}
	if (lseek(fd,0,SEEK_SET)==-1) {
		debuga(__FILE__,__LINE__,_("Cannot return to the beginning of file \"%s\": %s"),arq,strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (buf[0]==0x1F && buf[1]==0x8B && buf[2]==0x08)//gzip file
	{
#ifdef HAVE_ZLIB_H
		fi=Gzip_Open(fd);
#else
		debuga(__FILE__,__LINE__,_("Sarg was not compiled with gzip support to read file \"%s\"\n"),arq);
		exit(EXIT_FAILURE);
#endif
	}
	else if (buf[0]==0x42 && buf[1]==0x5A && buf[2]==0x68)//bzip2 file
	{
#ifdef HAVE_BZLIB_H
		fi=Bzip_Open(fd);
#else
		debuga(__FILE__,__LINE__,_("Sarg was not compiled with bzip support to read file \"%s\"\n"),arq);
		exit(EXIT_FAILURE);
#endif
	}
	else if (buf[0]==0xFD && buf[1]=='7' && buf[2]=='z' && buf[3]=='X' && buf[4]=='Z')//xz file
	{
#ifdef HAVE_LZMA_H
		fi=Lzma_Open(fd);
#else
		debuga(__FILE__,__LINE__,_("Sarg was not compiled with xz support to read file \"%s\"\n"),arq);
		exit(EXIT_FAILURE);
#endif
	}
	else if (buf[0]==0x1F && (buf[1]==0x9D || buf[1]==0xA0))//LZW and LZH compressed file
	{
		debuga(__FILE__,__LINE__,_("Support for LZW and LZH compressed files was removed in sarg 2.4.\n"
								   "You can still read such a file with a command like this:\n"
								   "  zcat \"%s\" | sarg - [your usual options here]\n"
								   "If you think it is important for sarg to read those files, open a bug ticket at <http://sourceforge.net/p/sarg/bugs/>.\n"),
			   arq);
		exit(EXIT_FAILURE);
	}
	else //normal file
	{
		fi=FileObject_FdOpen(fd);
	}
	return(fi);
}
