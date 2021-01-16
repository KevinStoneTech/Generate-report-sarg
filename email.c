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

#ifdef ENABLE_DOUBLE_CHECK_DATA
extern struct globalstatstruct globstat;
#endif

//! Name of the file containing the e-mail to send.
static char EmailFileName[MAXLEN]="";

/*!
 * Generate a file name to write the e-mail and open the file.
 *
 * \param Module The module for which the e-mail is generated.
 *
 * \return The file to which the e-mail can be written.
 */
FILE *Email_OutputFile(const char *Module)
{
	FILE *fp;

	if (strcmp(email,"stdout") == 0) {
		EmailFileName[0]='\0';
		return(stdout);
	}

	format_path(__FILE__, __LINE__, EmailFileName, sizeof(EmailFileName), "%s/%s.int_unsort", tmp, Module);
	if ((fp=fopen(EmailFileName,"w"))==NULL) {
		debuga(__FILE__,__LINE__,_("Cannot open file \"%s\": %s\n"),EmailFileName,strerror(errno));
		exit(EXIT_FAILURE);
	}
	return(fp);
}

/*!
 * Send the e-mail.
 *
 * \param fp The file opened by Email_OutputFile().
 */
void Email_Send(FILE *fp,const char *Subject)
{
	char warea[MAXLEN];
	int cstatus;

	if (fp==stdout) return;//to stdout

	if (fclose(fp)==EOF) {
		debuga(__FILE__,__LINE__,_("Write error in \"%s\": %s\n"),EmailFileName,strerror(errno));
		exit(EXIT_FAILURE);
	}

	format_path(__FILE__, __LINE__, warea, sizeof(warea), "%s -s \"%s\" \"%s\" <\"%s\"", MailUtility, Subject, email, EmailFileName);
	if (debug)
		debuga(__FILE__,__LINE__,_("Sending mail with command: %s\n"),warea);
	cstatus=system(warea);
	if (!WIFEXITED(cstatus) || WEXITSTATUS(cstatus)) {
		debuga(__FILE__,__LINE__,_("command return status %d\n"),WEXITSTATUS(cstatus));
		debuga(__FILE__,__LINE__,_("command: %s\n"),warea);
		exit(EXIT_FAILURE);
	}
	if (!KeepTempLog && unlink(EmailFileName)) {
		debuga(__FILE__,__LINE__,_("Cannot delete \"%s\": %s\n"),EmailFileName,strerror(errno));
		exit(EXIT_FAILURE);
	}
}
