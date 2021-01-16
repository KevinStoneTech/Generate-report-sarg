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
#include "include/dichotomic.h"

/*!
One key/value pair stored in the sorted list.
*/
struct DichotomicItemStruct
{
	//! The key.
	const char *Key;
	//! The value.
	const char *Value;
};

struct DichotomicStruct
{
	//! The array containing the sorted pairs.
	struct DichotomicItemStruct *Items;
	//! The number of pairs in the array.
	int NItems;
	//! The size of the array.
	int NAllocated;
};

/*!
Create an object to store key/value pairs and
retrieve them.

\return The object to pass to the functions in this module.
The returned pointer is NULL if there is not enough memory
to allocate the object. The object must be freed with a call
to Dichotomic_Destroy().
*/
DichotomicObject Dichotomic_Create(void)
{
	DichotomicObject Obj;

	Obj=malloc(sizeof(*Obj));
	if (!Obj)
	{
		return(NULL);
	}
	memset(Obj,0,sizeof(*Obj));
	return(Obj);
}

/*!
Destroy an object created by Dichotomic_Create().

\param ObjPtr The pointer to the variable containing
the object to destroy. The pointer is reset to NULL
by this function. It is safe to pass NULL or a NULL
pointer.
*/
void Dichotomic_Destroy(DichotomicObject *ObjPtr)
{
	DichotomicObject Obj;
	int i;

	if (!ObjPtr || !*ObjPtr) return;
	Obj=*ObjPtr;
	*ObjPtr=NULL;
	if (Obj->Items)
	{
		for (i=0 ; i<Obj->NItems ; i++)
		{
			free((void*)Obj->Items[i].Key);
			free((void*)Obj->Items[i].Value);
		}
		free(Obj->Items);
	}
	free(Obj);
}

static int Dichotomic_FindKeyPos(DichotomicObject Obj,const char *key,bool *Found)
{
	int down,up;
	int middle=0;
	int cmp=0;

	down=0;
	up=Obj->NItems-1;
	while (up>=down)
	{
		middle=(down+up)/2;
		cmp=strcasecmp(key,Obj->Items[middle].Key);
		if (!cmp)
		{
			*Found=true;
			return(middle);
		}
		if (cmp<0)
			up=middle-1;
		else
			down=middle+1;
	}
	*Found=false;
	if (cmp>0) middle++;
	return(middle);
}

/*!
Insert a key/value pair into the array.

\param Obj The object created by Dichotomic_Create().
\param key The key of the pair.
\param value The value of the pair.

\return \c True if the pair was inserted or \c false if
it failed.
*/
bool Dichotomic_Insert(DichotomicObject Obj,const char *key, const char *value)
{
	int Position;
	bool Found;
	int i;

	if (!Obj) return(false);
	if (Obj->Items)
	{
		Position=Dichotomic_FindKeyPos(Obj,key,&Found);
		if (Found) return(false);
	}
	else
		Position=0;

	if (Obj->NItems>=Obj->NAllocated)
	{
		struct DichotomicItemStruct *Items;
		Obj->NAllocated+=25;
		Items=realloc(Obj->Items,Obj->NAllocated*sizeof(*Items));
		if (!Items)
		{
			debuga(__FILE__,__LINE__,_("Not enough memory to store the key/value pair %s/%s\n"),key,value);
			exit(EXIT_FAILURE);
		}
		Obj->Items=Items;
	}

	for (i=Obj->NItems ; i>Position ; i--)
	{
		Obj->Items[i].Key=Obj->Items[i-1].Key;
		Obj->Items[i].Value=Obj->Items[i-1].Value;
	}
	Obj->Items[Position].Key=strdup(key);
	Obj->Items[Position].Value=strdup(value);
	if (!Obj->Items[Position].Key || !Obj->Items[Position].Value)
	{
		debuga(__FILE__,__LINE__,_("Not enough memory to store the key/value pair %s/%s\n"),key,value);
		exit(EXIT_FAILURE);
	}
	Obj->NItems++;

	return(true);
}

/*!
Search for the value of a key.

\param Obj The object created by Dichotomic_Create().
\param key The key to search for.

\return The value of the key or NULL if the key was not found.
*/
const char *Dichotomic_Search(DichotomicObject Obj,const char *key)
{
	int Position;
	bool Found;

	if (!Obj) return(NULL);
	if (Obj->NItems==0 || !Obj->Items) return(NULL);
	Position=Dichotomic_FindKeyPos(Obj,key,&Found);
	if (!Found) return(NULL);
	return(Obj->Items[Position].Value);
}
