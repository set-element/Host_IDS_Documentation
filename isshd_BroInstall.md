#Bro install and configuration
-----

At this point we can assume that you have a working iSSHD install and that data is being delivered to the same system as the analysis bro will be running on.  Optionally the bro system can mount the sshd logs if performance or security dictate separation.

The general overview will have us download bro, install one additional bif, then download and configure the files required for isshd and the core host framework.

### Download Bro

As per the usual, download a >= version 2.4 of bro.  In this case we will live dangerously and get it directly out of git.

```
[scottc@sdn-n scratch]$
[scottc@sdn-n scratch]$ git clone --recursive git://git.bro.org/bro.git
Initialized empty Git repository in /home/scottc/scratch/bro/.git/
remote: Counting objects: 74607, done.
remote: Compressing objects: 100% (22952/22952), done.
 (...)
Receiving objects: 100% (40/40), 3.06 MiB | 111 KiB/s, done.
Resolving deltas: 100% (12/12), done.
Submodule path 'src/3rdparty': checked out '6a429e79bbaf0fcc11eff5f639bfb9d1f62be6f2'
[scottc@sdn-n scratch]$
```

To add the raw_unescape_URI() function, go to the "src/analyzer/protocol/http" directory and edit the functions.bif file .  At the bottom of the file add the following:

```
function raw_unescape_URI%(URI: string%): string
        %{
        const u_char* line = URI->Bytes();
        const u_char* const line_end = line + URI->Len();

        byte_vec decoded_URI = new u_char[line_end - line + 1];
        byte_vec URI_p = decoded_URI;

        while ( line < line_end )
                {
                if ( *line == '%' )
                        {
                        ++line;

                        if ( line == line_end )
                                {
                                // How to deal with % at end of line?
                                break;
                                }
                        else if ( *line == '%' )
                                {
                                // Double '%' might be either due to
                                // software bug, or more likely, an
                                // evasion (e.g. used by Nimda).
                                --line; // ignore the first '%'
                                }
                        else if ( isxdigit(line[0]) && isxdigit(line[1]) )
                                {
                                *URI_p++ = (decode_hex(line[0]) << 4) +
                                           decode_hex(line[1]);
                                ++line; // place line at the last hex digit
                                }
                        else
                                {
                                *URI_p++ = '%'; // put back initial '%'
                                *URI_p++ = *line; // take char w/o interp.
                                }
                        }
                else
                        {
                        *URI_p++ = *line;
                        }

                ++line;
                }

        URI_p[0] = 0;

        StringVal* rsv = new StringVal( (int)(URI_p - decoded_URI), (const char*)decoded_URI);
       free(decoded_URI);

       return rsv;
       %}
```

This will create a function that you can call from a script that will return the full URI decoded bitstream from an encoded string.  The bitstream can contain hostile binary data so that data should be treated with extreme care regarding printing it to the operators terminal or logging.

Now you can just 'configure' and 'make install' as you might in any other install.

### Configure the isshd Side

For the first install, I will show how to configure a standalone (non-cluster) version of the analyzer.  The assumption here is that the install contains:

	Data Directory: /data/isshd_log
	Bro Install: /home/scottc/scratch/BROINSTALL

First go to the share/bro/site directory and download the policy files

```
[scottc@sdn-n BROINSTALL]$ cd share/bro/site/
[scottc@sdn-n site]$ git clone https://github.com/set-element/isshd_policy.git
Cloning into 'isshd_policy'...
remote: Counting objects: 120, done.
remote: Compressing objects: 100% (33/33), done.
remote: Total 120 (delta 12), reused 0 (delta 0), pack-reused 87
Receiving objects: 100% (120/120), 242.67 KiB | 0 bytes/s, done.
Resolving deltas: 100% (63/63), done.
Checking connectivity... done
[scottc@sdn-n site]$ git clone https://github.com/set-element/host_core.git
Cloning into 'host_core'...
remote: Counting objects: 37, done.
remote: Total 37 (delta 0), reused 0 (delta 0), pack-reused 37
Unpacking objects: 100% (37/37), done.
Checking connectivity... done
[scottc@sdn-n site]$
```

The isshd_policy contains all the policy related to the logging and analysis of the ssh keystroke and metadata stream.  The host_core is more of an infrastructure framework and is required for keeping track of a number of things.  It provides a nice agnostic place to plug the various sources (like isshd, syslog etc) so that information like user authentication has a nice place to live.

To load the 


#### iSSHD

