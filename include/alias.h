#ifndef ALIAS_HEADER
#define ALIAS_HEADER

//! Object to group items.
typedef struct AliasStruct *AliasObject;

AliasObject Alias_Create(void);
void Alias_Destroy(AliasObject *AliasPtr);

int Alias_Store(AliasObject AliasData,char *String);
void Alias_PrintList(struct AliasStruct *AliasData);
const char *Alias_Replace(struct AliasStruct *AliasData,const char *Name);

#endif // ALIAS_HEADER
