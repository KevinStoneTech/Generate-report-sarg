<?php

function check_url($url)
{
	/*
		Regex is @gruber as found at https://mathiasbynens.be/demo/url-regex

		Thanks Mathias for sharing those regex in a clear table.
	 */
	return(preg_match("#\b(([\w-]+://?|www[.])[^\s()<>]+(?:\([\w\d]+\)|([^[:punct:]\s]|/)))#i", $url)===1);
}
