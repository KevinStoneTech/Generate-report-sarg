#ifndef FILELIST_HEADER
#define FILELIST_HEADER

//! Store the files to read.
typedef struct FileListStruct *FileListObject;

//! Iterator over the file list.
typedef struct _FileListIterator *FileListIterator;

FileListObject FileList_Create(void);
void FileList_Destroy(FileListObject *FPtr);

bool FileList_AddFile(FileListObject FObj,const char *FileName);
bool FileList_IsEmpty(FileListObject FObj);

FileListIterator FileListIter_Open(FileListObject FObj);
const char *FileListIter_Next(FileListIterator FIter);
const char *FileListIter_NextWithMask(FileListIterator FIter);
void FileListIter_Close(FileListIterator FIter);

#endif //FILELIST_HEADER
