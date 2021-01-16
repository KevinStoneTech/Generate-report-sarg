#ifndef IP2NAME_HEADER
#define IP2NAME_HEADER

//! The possible return code of ip2name subfunctions.
enum ip2name_retcode
{
	//! Error encountered during the processing.
	INRC_Error=-1,
	//! No match found.
	INRC_NotFound,
	//! A match was found.
	INRC_Found,
};


//! Entry points of the ip2name modules
struct Ip2NameProcess
{
	//! The real name of the module.
	const char *Name;
	//! The link to the next module to try if this one fails.
	struct Ip2NameProcess *Next;
	//! The function to configure the module.
	void (*Configure)(const char *name,const char *param);
	//! Function to resolve an IP address into a name.
	enum ip2name_retcode (*Resolve)(char *ip,int ip_len);
};

#endif //IP2NAME_HEADER
