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

global $SargConf;
global $dbhome;

putenv("LANG=$language");
if (!setlocale(LC_ALL, $language))
{
	echo "<p>";
	printf(gettext("Invalid locale: %s"),$language);
	echo "</p>\n";
	exit;
}
$domain = 'messages';
bindtextdomain($domain, "./locale");
textdomain($domain);
include_once("style.php");

if (!isset($_GET['url']))
{
	echo "<p>",gettext("No URL to block"),"</p>\n";
	exit;
}

$url = $_GET['url'];
if (!check_url($url))
{
	echo "<p>",gettext("Invalid URL to block"),"</p>\n";
	exit;
}

function parse_config($line,$clave) {
	if (preg_match("/dbhome/i", $line)) {
		global $dbhome;
		$l = explode(' ', $line);
		list(, $dbhome) = $l;
		$dbhome=preg_replace('/\s+/','',$dbhome);
	}
}

$lines=file($squidGuardConf);
array_walk($lines,'parse_config');

?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
<title><?php echo gettext("Sarg-SquidGuard - URL Blocking")?></title>
</head>
<body>
<center>
<table>
<tr><td class="title"><?php echo gettext("Sarg-SquidGuard - URL Blocking")?></td></tr>
<tr><td class="header2">
<?php printf(gettext("Choose the rule set where %s will be added"),"<a href=\"http://$url\">".htmlspecialchars($url)."</a>")?></td></tr>
</table>
<?php

if (!is_dir($dbhome))
{
	echo "<p>";
	printf(gettext("The path <tt>%s</tt> (which is supposed to be the squidGuard DB home) is not a directory"),$dbhome);
	echo "</p>\n";
}
else
{
	$ha1 = opendir($dbhome);
	if ($ha1)
	{
		$table=false;
		while (false !== ($file = readdir($ha1)))
		{
			if ($file == '.' || $file == '..') continue;
			$dir2 = $dbhome.'/'.$file;
			if (is_dir($dir2))
			{
				if ($ha2 = opendir($dir2))
				{
					$first=true;
					while (false !== ($file2 = readdir($ha2)))
					{
						if ($file2 == '.' || $file2 == '..') continue;
						if (!$table)
						{
							echo "<table>\n";
							$table=true;
						}
						if ($first)
						{
							echo "<tr><td class=\"header\">$file</td></tr>\n";
							$first=false;
						}
						echo "<tr><td class=\"data2\"><a href=\"sarg-squidguard-block2.php?file=",rawurlencode($file.'/'.$file2),"&url=$url\">$file2</a></td></tr>\n";
					}
				}
				closedir($ha2);
			}
		}
		closedir($ha1);
		if ($table)
		{
			echo "</table>\n";
		}
		else
		{
			echo "<p>";
			printf(gettext("No squidGuard rule found in <tt>%s</tt>"),$dbhome);
			echo "</p>\n";
		}
	}
	else
	{
		echo "<p>";
		printf(gettext("Cannot read squidGuard DB home directory %s"),$dbhome);
		echo "</p>\n";
	}
}
?>
</html>
</body>
