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

void usage(const char *prog)
{
	printf(_("Usage: %s [options...]\n"), prog);
	puts  (_("     -a NAME|IP     Create report for host name or IP address"));
	//puts  (_("     -b Useragent log"));
	puts  (_("     -c FILE        Exclude connected hosts from the report"));
	puts  (_("     --convert      Convert the access.log file to a legible date"));
	puts  (_("     --css          Output the internal CSS"));
	puts  (_("     -d DATE        Date range to include in the report: from-until dd/mm/yyyy-dd/mm/yyyy"));
	puts  (_("     -e MAIL        Email address to send reports to (stdout for console)"));
	printf(_("     -f FILE        Config file to read (default is %s/sarg.conf)\n"),SYSCONFDIR);
	puts  (_("     -g FMT         Date format [e=Europe -> dd/mm/yyyy, u=USA -> mm/dd/yyyy]"));
	puts  (_("     -h             This help"));
	puts  (_("     --help         This help"));
	puts  (_("     -i             Reports by user and IP address"));
	puts  (_("     --keeplogs     Keep every previously generated report"));
	puts  (_("     -l FILE        Input log"));
	puts  (_("     --lastlog      Set the number of previous reports to keep"));
	puts  (_("     -n             Resolve IP addresses using RDNS"));
	puts  (_("     -o DIR         Report output directory"));
	puts  (_("     -p             Use Ip Address instead of userid (reports)"));
	puts  (_("     -P PREFIX      Prepend a prefix to the splitted file names"));
	puts  (_("     -r             Produce real time report"));
	puts  (_("     -s SITE        Limit report to accessed site [eg. www.microsoft.com]"));
	puts  (_("     --split        Split the log file by date in -d parameter"));
	puts  (_("     --splitprefix PREFIX\n"
	         "                    Prepend a prefix to the splitted file names"));
	puts  (_("     --statistics   Print run time statistics"));
	puts  (_("     -t TIME        Limit report to time range [HH:MM or HH:MM-HH:MM]"));
	puts  (_("     -u USER        Report only that user's activity"));
	puts  (_("     --version      Print version information"));
	puts  (_("     -w DIR         Temporary directory"));
	puts  (_("     -x             Debug messages"));
	puts  (_("     -z             Process messages"));
	printf("\n\t%s-%s\n",PGM,VERSION);
	puts  ("\thttp://sarg.sourceforge.net");
	/*puts  (_("\n\tPlease donate to the sarg project:"));
	puts  ("\t\thttp://sarg.sourceforge.net/donations.php\n");*/

	return;
}
