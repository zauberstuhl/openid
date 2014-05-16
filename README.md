Introduction
============

This product is free open source software.  For license information, see
the file called license.txt.

**Forked from** [packetizer.com](http://www.packetizer.com/security/openid/)

Installation
============

## Database Connection Configuration

The lib directory contains a file called config.pl. Inside, you will see four global variables defined. They  
each need to be populated with the proper value so as to enable a connection to the MySQL database.  
The variables are:

* database_user_id - This is the user ID associated with the database connection.
* database_password - This is the password used to connect to the database. Since this file contains the password in plaintext form, the config.pl file should be stored in a location that is not directly accessible via a web browser.
* database_name - This is the name of the database that contains the database tables discussed in section 3.1
* database_server - This is the name of the database server, which is often localhost in smaller installations.

## OpenID Server Configuration

The lib directory contains a file called openid_config.pl which global variables used by the various  
scripts. Each of these values should be replaced with appropriate values.

## Configuring Apache

If you wish to use the 404.shtml document, add this to your Apache configuration:
> ErrorDocument 404 /404.shtml

You need to ensure that the Perl libraries are accessible. To do this, add these lines to your Apache configuration:
> SetEnv PERL5LIB /path/to/lib/

You might have noticed that there are two CGI scripts in htdocs, once called “user.cgi” and one called  
"xrds.cgi". Those may be located anywhere, but wherever you place them, you need to ensure that  
Apache performs the correct URL re-writing to access them. Assuming you leave these in the default  
location, the following configuration should be added to Apache:
> RewriteEngine On
> RewriteRule ^/([A-Za-z0-9]+)$              /user.cgi?username=$1 [L]
> RewriteRule ^/xrds/([A-Za-z0-9]+)$         /xrds.cgi?username=$1 [L]

If you use other re-writing rules, you may already have the re-write engine turned on and the first line  
may be unnecessary. You will notice that these rules assume that any name that contains the characters  
[A-Xa-z0-9] at the root of the OpenID directory is a possible OpenID user ID.  

## Create Users

The software does not contain web pages to create users. However, adding users to the system is trivial  
and you may add users by hand or you might right your own software to create users. The reasons we  
do not provide a means to add users to the database are that you probably already have software that  
creates user accounts in your network and this would be largely redundant. If you do not, then creating  
users by hand is sufficient.

To create a new OpenID user ID, simply add a row to the openid_users table. The only required fields  
are "serial" (which should be assigned automatically by MySQL if you use a value of 0), "username",  
"password", and "name". The field called "homepage" is optional and, if present, will be shown on the  
user's identity page.

The only field that warrants mention is the password field. We do not store passwords in the clear in  
the database. Rather, the password field contains the SHA-1 hash of the user's password. To create the  
password, you can use any SHA-1 tool (software available on Packetizer). The simplest way is from the

Linux command-line:
> echo –n user_password | sha1sum

## Database Management

The only management that needs to be done is removal of old nonce values and removal of old  
signatures and associations. There two scripts that you may execute periodically from cron to do that  
for you: bin/expire_associations and bin/nonce_expiration. Of course, you should also ensure that  
those scripts are executable.

When you run those scripts is entirely up to you. You could run the scripts every few minutes or daily.  
There should be no security concerns if the scripts are run only once each day, as the software should  
ensure that a nonce is not used more than once and it should ensure that associations are not validated  
more than once.

Changelog
=========

## 1.8 - 2011-01-06
> Modified the code so that Cookies will only be
> sent to the User Agent if both the secure and
> insecure cookie domain variables are defined.

## 1.7 - 2010-12-30
> Renamed the checkid directory and separated the
> global variables into a separate config file.

## 1.6 - 2010-05-14
> Corrected an error where the OpenID server would reject
> association requests over TLS.  In that case, the
> value dh_consumer_public is not required, but the
> server was requiring it.

## 1.5 - 2010-05-10
> Moved the OpenID password checking script to
> a new directory called openid_check.

## 1.4 - 2010-03-28
> Added support for checkid_immediate and cookies
> to allow one to automatically log into sites
> without being prompted for a password after
> successfully logging in.  This works only when the
> user selects the "remember this computer" option.

## 1.3 - 2010-03-26
> Some RPs do not establish associations before directing
> the user to the OpenID server.  In those cases,
> an association is created using defaults and returned
> in the response, should the RP wish to verify the
> signature.

## 1.2 - 2010-02-09
> The openid_sigs table was missing in the misc directory

## 1.1 - 2010-01-19
> Fixed a bug where the OpenID server was not properly
> responding to login requests where the RP set the
> identity value to "identifier_select".  Specifically,
> the GetIdentity function was returning the wrong
> indicator to the calling routine and there was also
> an error in the login form that was generated.
> The only changes were made to the file named
> htdocs/login/index.cgi.

## 1.0 - 2009-12-26
> Initial release
