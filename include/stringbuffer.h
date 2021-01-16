#ifndef STRINGBUFFER_HEADER
#define STRINGBUFFER_HEADER

//! Object created by the string buffer module.
typedef struct StringBufferStruct *StringBufferObject;

StringBufferObject StringBuffer_Create(void);
void StringBuffer_Destroy(StringBufferObject *SPtr);

char *StringBuffer_StoreLength(StringBufferObject SObj,const char *String,int Length);
char *StringBuffer_Store(StringBufferObject SObj,const char *String);

#endif //STRINGBUFFER_HEADER
