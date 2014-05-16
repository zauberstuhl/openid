#! /usr/bin/perl

use strict;
use CGI;

require "openid_config.pl";

my $cgi = new CGI;

print $cgi->header();
print <<EOT;
<html>
  <head>
    <title>$main::openid_site_name OpenID Service</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
    <meta http-equiv="Content-Language" content="en-US"/>
    <link rel="SHORTCUT ICON" href="/favicon.ico"/>
  </head>
  <body>
  <div>
    <img src="/images/open_id.png" style="width: 200px; height: 80px; border: none;" alt="OpenID" />
    <h1>$main::openid_site_name OpenID Service</h1>
    <p>This site provides OpenID authentication services.</p>
  </div>
  </body>
</html>
EOT
