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
require_once "url_validator.php.inc";

if (!isset($_GET['file']))
{
	echo "<p>",gettext("No file passed as argument"),"</p>\n";
	exit;
}
$file = $_GET['file'];
if (!isset($_GET['url']))
{
	echo "<p>",gettext("No url passed as argument"),"</p>\n";
	exit;
}
$url = $_GET['url'];
if (!check_url($url))
{
	echo "<p>",gettext("Invalid URL to block"),"</p>\n";
	exit;
}
$url = $url."\n";

putenv("LANG=$language");
if (!setlocale(LC_ALL, $language))
{
	echo "<p>";
	printf(gettext("Invalid locale %s"),$language);
	echo "</p>\n";
	exit;
}
$domain = 'messages';
bindtextdomain($domain, "./locale");
textdomain($domain);

function parse_config($line,$clave) {
	if (preg_match("/dbhome/i", $line)) {
		global $dbhome;
		$l = explode(' ', $line);
		list(, $dbhome) = $l;
		$dbhome=preg_replace('/\s+/','',$dbhome);
	}
}

global $dbhome;
$lines=file($squidGuardConf);
array_walk($lines,'parse_config');
$file=$dbhome.'/'.$file;

?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
<title><?php echo gettext("Sarg-SquidGuard - URL Blocking")?></title>
</head>
<body>
<?php

$ha = fopen($file, 'a');
if ($ha == false)
{
	echo "<p>";
	printf(gettext("Could not open file: %s"),$file);
	echo "</p>\n";
	exit;
}

$written = fwrite($ha, $url);
fclose($ha);
if ($written != strlen($url))
{
	echo "<p>";
	echo gettext("Write error");
	echo "</p>\n";
	exit;
}

echo "<p>",gettext("Done!"),"</p>\n<p>";
printf(gettext("<a href=\"%s\">Return</a> to Sarg."),"javascript:history.go(-2)");
echo "</p>\n";
?>
</body>
