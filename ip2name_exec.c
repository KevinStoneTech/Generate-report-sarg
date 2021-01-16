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
#include "include/ip2name.h"

//! The buffer size to store the command.
#define CMD_BUFFER_SIZE 2048

static void ip2name_execconfig(const char *name,const char *param);
static enum ip2name_retcode ip2name_exec(char *ip,int ip_len);

//! The functions to resolve an IP address using an external executable.
struct Ip2NameProcess Ip2NameExec=
{
	"dns",
	NULL,//no next item yet
	ip2name_execconfig,
	ip2name_exec
};

static char ExecCmd[CMD_BUFFER_SIZE]="";

/*!
Configure the module to resolve an IP address using an external program.

\param name The name of the module as invoked by the user in the configuration
file.
\param param The parameters passed to the module.
*/
static void ip2name_execconfig(const char *name,const char *param)
{
	int len;

	len=strlen(param);
	if (len>=sizeof(ExecCmd)) {
		debuga(__FILE__,__LINE__,_("Command to execute to resolve the IP addresses is too long (maximum is %d bytes)\n"),(int)sizeof(ExecCmd));
		exit(EXIT_FAILURE);
	}
	strcpy(ExecCmd,param);
}

/*!
Run an external process to get the name of a computer.

\param ip The ip address.
\param ip_len The number of bytes in the IP address.

\return One of the ::ip2name_retcode value.
*/
static enum ip2name_retcode ip2name_exec(char *ip,int ip_len)
{
	char cmd[CMD_BUFFER_SIZE];
	int i;
	int j;
	int len;
	FILE *cmd_in;
	char buffer[512];
	size_t nread;

	if (ExecCmd[0]=='\0') {
		debuga(__FILE__,__LINE__,_("No command to run to resolve an IP address. Please configure it in sarg.conf\n"));
		exit(EXIT_FAILURE);
	}

	j=0;
	len=strlen(ip);
	for (i=0 ; i<sizeof(ExecCmd) && ExecCmd[i] ; i++) {
		if (ExecCmd[i]=='%' && strncmp(ExecCmd+i+1,"IP",2)==0) {
			if (j+len>=sizeof(cmd)) {
				debuga(__FILE__,__LINE__,_("IP address \"%s\" too long for the command to run\n"),ip);
				return(INRC_Error);
			}
			strcpy(cmd+j,ip);
			j+=len;
			i+=2;
		} else {
			if (j>=sizeof(cmd)) {
				debuga(__FILE__,__LINE__,_("IP address \"%s\" too long for the command to run\n"),ip);
				return(INRC_Error);
			}
			cmd[j++]=ExecCmd[i];
		}
	}
	cmd[j]='\0';

	cmd_in=popen(cmd,"r");
	if (!cmd_in) {
		debuga(__FILE__,__LINE__,_("Cannot run command %s\n"),cmd);
		exit(EXIT_FAILURE);
	}

	nread=fread(buffer,1,sizeof(buffer),cmd_in);

	if (pclose(cmd_in)==-1) {
		debuga(__FILE__,__LINE__,_("Command failed: %s\n"),cmd);
		exit(EXIT_FAILURE);
	}

	if (nread==0) return(INRC_NotFound);

	safe_strcpy(ip,buffer,ip_len);
	return(INRC_Found);
}
