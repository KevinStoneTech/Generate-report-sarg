#ifndef DICHOTOMIC_HEADER
#define DICHOTOMIC_HEADER

#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#else
typedef int bool;
#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif
#endif

//! The object to store key/value pairs
typedef struct DichotomicStruct *DichotomicObject;

DichotomicObject Dichotomic_Create(void);
void Dichotomic_Destroy(DichotomicObject *ObjPtr);

const char *Dichotomic_Search(DichotomicObject Obj,const char *key);
bool Dichotomic_Insert(DichotomicObject Obj,const char *key, const char *value);


#endif //DICHOTOMIC_HEADER
