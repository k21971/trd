<?php

include "config.php";

$dir = $CACHE_PATH."/";

@mkdir($dir);
@chmod($dir, 0777);
$starttime = time();

/* delete old cached ttyrecs */
$count = 0;
if ($handle = opendir($dir)) {
    while (false !== ($file = readdir($handle))) {
	if (preg_match($REGEX_EXT, $file)) {
	    if (filemtime($dir.$file) + $CACHE_TIME < $starttime) {
		if (unlink($dir.$file))
		    $count++;
	    }
	}
    }
    closedir($handle);
}
