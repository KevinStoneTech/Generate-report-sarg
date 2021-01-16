#ifndef READLOG_HEADER
#define READLOG_HEADER

/*!
\brief Possible return codes for the functions parsing the input log.
*/
enum ReadLogReturnCodeEnum
{
	//! Line successfuly read.
	RLRC_NoError,
	//! Line is known and should be ignored.
	RLRC_Ignore,
	//! Unknown line format.
	RLRC_Unknown,
	//! Error encountered during the parsing of the file.
	RLRC_InternalError,

	RLRC_LastRetCode //!< last entry of the list.
};

/*!
\brief Data read from an input log file.
*/
struct ReadLogStruct
{
	//! The time corresponding to the entry.
	struct tm EntryTime;
	//! The IP address connecting to internet.
	const char *Ip;
	//! The user's name.
	const char *User;
	/*!
	The URL of the visited site.

	The pointer may be NULL if the URL doesn't exists in the log file.
	*/
	char *Url;
	//! Time necessary to process the user's request.
	long int ElapsedTime;
	//! Number of transfered bytes.
	long long int DataSize;
	//! HTTP code returned to the user for the entry.
	char *HttpCode;
	//! HTTP method or NULL if the information is not stored in the log.
	char *HttpMethod;
	//! Useragent string or NULL if it isn't available
	const char *UserAgent;
};

/*!
\brief Functions to read a log file.
*/
struct ReadLogProcessStruct
{
	//! The name of the log file processed by this object.
	const char *Name;
	//! Inform the module about the reading of a new file.
	void (*NewFile)(const char *FileName);
	//! Funtion to read one entry from the log.
	enum ReadLogReturnCodeEnum (*ReadEntry)(char *Line,struct ReadLogStruct *Entry);
};

/*!
 * \brief Persistant data to parse a log line.
 */
struct LogLineStruct
{
	const struct ReadLogProcessStruct *current_format;
	int current_format_idx;
	int successive_errors;
	int total_errors;
	const char *file_name;
};

//! Opaque object used to parse a log line.
typedef struct LogLineStruct *LogLineObject;

void LogLine_Init(struct LogLineStruct *log_line);
void LogLine_File(struct LogLineStruct *log_line,const char *file_name);
enum ReadLogReturnCodeEnum LogLine_Parse(struct LogLineStruct *log_line,struct ReadLogStruct *log_entry,char *linebuf);

#endif //READLOG_HEADER
