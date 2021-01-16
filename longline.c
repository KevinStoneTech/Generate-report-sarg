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

//! The size, in bytes, to allocate from the start.
#define INITIAL_LINE_BUFFER_SIZE 32768
/*!
The amount by which the line buffer size is increased when it turns out to be too small to accomodate
the line to read.
*/
#define LINE_BUFFER_SIZE_INCREMENT 8192
/*!
Maximum size of the line buffer.

A text line read from the file must be smaller than this value or the functions fails
and aborts the program.

10MB should not be a problem as most of the line is filled with the URL and squid 3
limits the URL to 4096 bytes (see MAX_URL). Squid has reportedly been tested with
MAX_URL set up to 32KB so I'm not expecting URL much longer than that.

Other proxies might handle longer URLs but certainly not longer than 10MB.

Now, why put a limit? Sarg version 2.3 originaly had no limits until sarg 2.3.3. At
that point a user with a defective network mount point reported that sarg was eating
up 8GB of memory available on the server triggering the OOM killer. So the limit is
here to prevent sarg from choking on an invalid file.
*/
#define MAX_LINE_BUFFER_SIZE (10*1024*1024)

struct longlinestruct
{
	//! The buffer to store the data read from the log file.
	char *buffer;
	//! The size of the buffer.
	size_t size;
	//! The number of bytes stored in the buffer.
	size_t length;
	//! The position of the beginning of the current string.
	size_t start;
	//! The position of the end of the current string.
	size_t end;
};

longline longline_create(void)
{
	longline line;

	line=malloc(sizeof(*line));
	if (line==NULL) return(NULL);
	line->size=INITIAL_LINE_BUFFER_SIZE;
	line->buffer=malloc(line->size);
	if (line->buffer==NULL) {
		free(line);
		return(NULL);
	}
	line->start=0;
	line->end=0;
	line->length=0;
	return(line);
}

void longline_reset(longline line)
{
	if (line!=NULL) {
		line->start=0;
		line->end=0;
		line->length=0;
	}
}

char *longline_read(FileObject *fp_in,longline line)
{
	int i;
	char *newbuf;
	int nread;

	if (line==NULL || line->buffer==NULL) return(NULL);

	while (true) {
		for (i=line->end ; i<line->length && (line->buffer[i]=='\n' || line->buffer[i]=='\r') ; i++);
		if (i<line->length) {
			line->end=i;
			break;
		}
		nread=(FileObject_Eof(fp_in)!=0) ? 0 : FileObject_Read(fp_in,line->buffer,line->size);
		if (nread<=0) return(NULL);
		line->length=nread;
		line->end=0;
	}

	line->start=line->end;
	while (true) {
		for (i=line->end ; i<line->length ; i++) {
			if ((unsigned char)line->buffer[i]>=' ') continue;
			if (line->buffer[i]=='\n' || line->buffer[i]=='\r') break;
		}

		line->end=i;
		if (line->end<line->length) break;

		if (line->start>0) {
			for (i=line->start ; i<line->length ; i++) line->buffer[i-line->start]=line->buffer[i];
			line->length-=line->start;
			line->end-=line->start;
			line->start=0;
		}
		if (line->length>=line->size) {
			line->size+=LINE_BUFFER_SIZE_INCREMENT;
			if (line->size>=MAX_LINE_BUFFER_SIZE) {
				debuga(__FILE__,__LINE__,_("A text line is more than %d bytes long denoting a corrupted file\n"),MAX_LINE_BUFFER_SIZE);
				exit(EXIT_FAILURE);
			}
			newbuf=realloc(line->buffer,line->size);
			if (!newbuf) {
				debuga(__FILE__,__LINE__,_("Not enough memory to read one more line from the file\n"));
				exit(EXIT_FAILURE);
			}
			line->buffer=newbuf;
		}
		nread=(FileObject_Eof(fp_in)!=0) ? 0 : FileObject_Read(fp_in,line->buffer+line->length,line->size-line->length);
		if (nread<=0) {
			if (line->end<=line->start) return(NULL);
			if (line->end>=line->size) {
				line->end=line->size;
				line->size++;
				newbuf=realloc(line->buffer,line->size);
				if (!newbuf) {
					debuga(__FILE__,__LINE__,_("Not enough memory to read one more line from the file\n"));
					exit(EXIT_FAILURE);
				}
				line->buffer=newbuf;
			}
			line->buffer[line->end]='\0';
			return(line->buffer+line->start);
		}
		line->length+=nread;
	}
	line->buffer[line->end++]='\0';
	return(line->buffer+line->start);
}

void longline_destroy(longline *line_ptr)
{
	longline line;

	if (line_ptr==NULL || *line_ptr==NULL) return;
	line=*line_ptr;
	*line_ptr=NULL;
	if (line->buffer!=NULL) free(line->buffer);
	free(line);
}
