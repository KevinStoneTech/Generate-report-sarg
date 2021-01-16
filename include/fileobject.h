#ifndef FILEOBJECT_H
#define FILEOBJECT_H

typedef struct FileObjectStruct
{
	void *Data;
	int (*Read)(void *Data,void *Buffer,int Size);
	int (*Eof)(void *Data);
	void (*Rewind)(void *Data);
	int (*Close)(void *Data);
} FileObject;

FileObject *FileObject_Open(const char *FileName);
FileObject *FileObject_FdOpen(int fd);
int FileObject_Read(FileObject *File,void *Buffer,int Size);
int FileObject_Eof(FileObject *File);
void FileObject_Rewind(FileObject *File);
int FileObject_Close(FileObject *File);

void FileObject_SetLastOpenError(const char *Message);
const char *FileObject_GetLastOpenError(void);
void FileObject_SetLastCloseError(const char *Message);
const char *FileObject_GetLastCloseError(void);

#endif // FILEOBJECT_H
