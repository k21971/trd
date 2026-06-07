<?php

$MAX_FILESIZE = 20000000;
$CACHE_PATH = "/tmp/trd";
$CACHE_TIME = 3600;
/* curl: http(s) only, bounded time + (compressed) size; redirects are NOT
   followed (no -L) so a 3xx can't bounce us to an internal host. */
$CURL_PRG = "/usr/bin/curl -f -s --proto =http,https --max-time 30 --max-filesize ".$MAX_FILESIZE;
/* cap the (decompressed) stream while writing, so a decompression bomb can't
   fill the disk before the post-write size check rejects it. */
$HEAD_PRG = "/usr/bin/head -c ".($MAX_FILESIZE + 1);
$REGEX_EXT = "/\.ttyrec(\.(gz|bz2))?$/";
$UNPACK_PRG = [
               ".gz" => "/usr/bin/gunzip - ",
               ".bz2" => "/usr/bin/bunzip2 - ",
               ];

/* should contain public URLs to specific ttyrec files */
$RND_TTYRECS = $CACHE_PATH."/rnd_ttyrecs.txt";

function allowed_files($fname)
{
    /* Structural gate only: permit http(s) URLs that have a host. The actual
       SSRF defence (private-IP rejection + DNS pinning) happens in
       ssrf_resolve() at fetch time, so cache hits don't pay for a DNS lookup.
       To restrict to specific hosts as well, add a host check here, e.g.:
       //return (preg_match('/^https?:\/\/s3\.amazonaws\.com\/altorg\//', $fname) ||
       //        preg_match('/^https?:\/\/alt\.org\/nethack\//', $fname)); */
    $p = @parse_url($fname);
    if ($p === false || !isset($p['scheme']) || !isset($p['host']))
        return false;
    $scheme = strtolower($p['scheme']);
    return ($scheme === 'http' || $scheme === 'https');
}

/* Resolve the URL host and reject private/loopback/link-local/reserved
   addresses -- this blocks SSRF to internal services and the cloud-metadata
   endpoint (169.254.169.254). Returns a curl "--resolve host:port:ip" fragment
   pinned to a validated public IP so curl cannot re-resolve to an internal
   address (DNS rebinding), or false if the host is not a safe public target. */
function ssrf_resolve($fname)
{
    $p = @parse_url($fname);
    if ($p === false || !isset($p['scheme']) || !isset($p['host']))
        return false;
    $scheme = strtolower($p['scheme']);
    if ($scheme !== 'http' && $scheme !== 'https')
        return false;
    $host = trim($p['host'], "[]"); /* strip IPv6 literal brackets */
    $port = isset($p['port']) ? (int)$p['port'] : ($scheme === 'https' ? 443 : 80);

    $candidates = array();
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $candidates[] = $host;
    } else {
        $recs = @dns_get_record($host, DNS_A | DNS_AAAA);
        if (is_array($recs)) {
            foreach ($recs as $r) {
                if (isset($r['ip'])) $candidates[] = $r['ip'];
                if (isset($r['ipv6'])) $candidates[] = $r['ipv6'];
            }
        }
        if (empty($candidates)) {
            $ip = gethostbyname($host); /* A-record fallback */
            if ($ip && $ip !== $host) $candidates[] = $ip;
        }
    }

    foreach ($candidates as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP,
                       FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return "--resolve ".escapeshellarg($host.":".$port.":".$ip);
        }
    }
    return false;
}
