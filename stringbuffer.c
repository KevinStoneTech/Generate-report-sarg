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
\brief Efficient? strings storage

Store strings in a globaly allocated memory to avoid memory waste and
memory fragmentation.
*/

#include "include/conf.h"
#include "include/stringbuffer.h"

//! Default size of the string buffer (I hope it fits inside one memory page).
#define STRINGBUFFER_SIZE (4096-sizeof(struct StringBufferStruct))

/*!
 * \brief String storage data.
 *
 * Strings are concatenated in fixed size buffers. The buffers are linked
 * in a list. New buffers are added as the previous buffers are filled.
 */
struct StringBufferStruct
{
	//! Next buffer in the chained list.
	StringBufferObject Next;
	//! How many buffer bytes are left.
	int BytesLeft;
	//! Where the strings are stored.
	char *Buffer;
};

/*!
 * Create an object to store constant strings.
 *
 * \return The created object or NULL if it failed.
 */
StringBufferObject StringBuffer_Create(void)
{
	StringBufferObject SObj;

	SObj=(StringBufferObject)calloc(1,sizeof(*SObj));
	if (!SObj) return(NULL);
	return(SObj);
}

/*!
 * Destroy the object created by StringBuffer_Create().
 *
 * Any string pointer to the destroyed object becomes invalid.
 *
 * \param SPtr A pointer to the object created by StringBuffer_Create().
 * The pointer is reset to NULL before the functrion returns to prevent
 * subsequent use of the freed pointer.
 */
void StringBuffer_Destroy(StringBufferObject *SPtr)
{
	StringBufferObject SObj;
	StringBufferObject Next;

	if (!SPtr || !*SPtr) return;
	SObj=*SPtr;
	*SPtr=NULL;

	while (SObj)
	{
		Next=SObj->Next;
		if (SObj->Buffer) free(SObj->Buffer);
		free(SObj);
		SObj=Next;
	}
}

/*!
 * Store a string in an existing buffer.
 */
static char *StringBuffer_StoreInBuffer(StringBufferObject SObj,const char *String,int Length)
{
	int Start=0;

	if (SObj->Buffer)
	{
		Start=STRINGBUFFER_SIZE-SObj->BytesLeft;
	}
	else if (Length>=STRINGBUFFER_SIZE)
	{
		SObj->BytesLeft=Length+1;
		SObj->Buffer=malloc(SObj->BytesLeft);
	}
	else
	{
		SObj->BytesLeft=STRINGBUFFER_SIZE;
		SObj->Buffer=malloc(SObj->BytesLeft);
	}
	if (!SObj->Buffer) return(NULL);
	strncpy(SObj->Buffer+Start,String,Length);
	SObj->Buffer[Start+Length]='\0';
	SObj->BytesLeft-=Length+1;
	return(SObj->Buffer+Start);
}

/*!
 * Add a string to the buffer. Duplicate strings are not merged.
 * Each call to this function stores one copy of the string.
 *
 * \param SObj The string buffer object.
 * \param String The string to store.
 * \param Length The length of the string.
 *
 * \return The pointer to the stored string or NULL if the function
 * failed. The returned string may be altered or truncated but not
 * appended to.
 */
char *StringBuffer_StoreLength(StringBufferObject SObj,const char *String,int Length)
{
	StringBufferObject SLast;
	char *Ptr;

	if (!SObj) return(NULL);

	// find a suitable buffer
	SLast=NULL;
	while (SObj)
	{
		if (!SObj->Buffer || Length<SObj->BytesLeft)
		{
			return(StringBuffer_StoreInBuffer(SObj,String,Length));
		}
		SLast=SObj;
		SObj=SObj->Next;
	}

	// create a new buffer
	SObj=(StringBufferObject)calloc(1,sizeof(*SObj));
	if (!SObj) return(NULL);
	Ptr=StringBuffer_StoreInBuffer(SObj,String,Length);
	if (!Ptr)
	{
		free(SObj);
		return(NULL);
	}
	SLast->Next=SObj;
	return(Ptr);
}

/*!
 * Add a string to the buffer. Duplicate strings are not merged.
 * Each call to this function stores one copy of the string.
 *
 * \param SObj The string buffer object.
 * \param String The string to store.
 *
 * \return The pointer to the stored string or NULL if the function
 * failed. The returned string may be altered or truncated but not
 * appended to.
 */
char *StringBuffer_Store(StringBufferObject SObj,const char *String)
{
	return(StringBuffer_StoreLength(SObj,String,strlen(String)));
}
