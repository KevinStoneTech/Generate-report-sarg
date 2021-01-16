<?php

/*
 * AUTHOR: Pedro Lineu Orso                         pedro.orso@gmail.com
 *                                                            1998, 2006
 * SARG Squid Analysis Report Generator            http://sarg-squid.org
 *
 * SARG donations:
 *      please look at http://sarg.sourceforge.net/donations.php
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

require_once "config.php.inc";

if (!isset($_GET['url']))
{
	echo "<p>",gettext("No URL passed as argument"),"</p>\n";
	exit;
}
$url = $_GET['url'];
$url = $url."\n";

$ha = fopen($DefaultSquidBlock, 'a');
if ($ha == false) {
   printf(gettext("Could not open file: %s"),$DefaultSquidBlock);
   exit;
}
else {
   $written = fwrite($ha, $url);
   fclose($ha);
   if ($written != strlen($url)) {
      print (gettext ("Write error"));
      exit;
   }
   print (gettext ("Done!"));
   echo "<br><br>\n";
   printf(gettext("<a href=\"%s\">Return</a> to Sarg."),"javascript:history.go(-1)");
}
