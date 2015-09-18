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

To load the policies on a standalone system, make the local.bro file into something like this:

```
@load host_core
@load isshd_policy

redef SSHD_IN_STREAM::data_file = "/data/sshd_logs/ssh_logging";
redef SSHD_IN_STREAM::DATANODE = T;
```

with the value expressed in SSHD_IN_STREAM::data_file being the location of the isshd data file.  This file will be read in a 'tail -f' manner


### iSSHD
The set of files used to run and configure this are as follows:

-----
Files:
```
        README.md                    you are here
        __load__.bro                 policy autoloader
        functions.bif.patch          patch for raw_unescape_URI() bif
        init_node.bro                if node is an isshd analyzer and this is a cluster

        sshd_const.bro               const values across the package
        sshd_input_stream.bro        reads text datastream and turns into events
        sshd_core_cluster.bro        log events
        sshd_policy_cluster.bro      apply local sec policy against events
        sshd_sftp3_cluster.bro       log sftp traffic

        sshd_cert_data.bro           list of known poor certs - not tremendous utility in running
        sshd_signatures.bro          list of suspicous and hostile actions

        sshd_input_stream_depricated.bro  DEPRICATED: input framework functions and defs for v1 and v2 events
        sshd_sftp_cluster.bro             DEPRICATED: sftp analyzer for older versions of isshd
        sshd_analyzer_cluster.bro         DEPRECATED: old isshd analyzer
```
The role of the core policy is to provide basic logging, the maintenance of session state and various bookeeping functions.  The sshd_policy describes the local site security configuration and is designed to be much more flexible .


From a configuration perspective the most interesting files to look at are sshd_signatures.bro which defines what is interesting to the policy, sshd_policy_cluster.bro which events should see notices, and host_core/notice_action.bro which tells bro where to route the notice type (log/email/page).

####  sshd_signatures.bro 
The sshd_signatures file contains sets of regular expressions that identify user behaviors that are considered hostile, suspicious or of interest to the analyzer operator.  In the event that a match needs to be added or removed, it is *highly* suggested that the original policy files not be changed.

For example if the signature "/SCOTTTEST_IN/" is, for whatever reason causing you grief, you can remove it by adding the following line in the local.bro :

	redef SSHD_POLICY::input_trouble_whitelist += /SCOTTTEST_IN/;

which will cause the string "SCOTTTEST_IN" to be ignored in the incoming text datastream.  It is entirely likely that the regular expression will also have to be added to the output set as well since there are discrete lists for incoming (client) and outgoing (server) directions.


#### sshd_policy_cluster.bro
The most significant configuration options (besides the regular expressions described above) in this file involve the treatment of notices.  The complete set of possible notices look like:

```
                SSHD_RemoteExecHostile,
                SSHD_Suspicous,
                SSHD_SuspicousThreshold,
                SSHD_Hostile,
                SSHD_BadKey,
                #
                SSHD_POL_InvalUser,
                SSHD_POL_AuthPassAtt,
                SSHD_POL_PassSkip,
                SSHD_POL_ChanPortOpen,
                SSHD_POL_ChanPortFwrd,
                SSHD_POL_ChanPostFwrd,
                SSHD_POL_ChanSetFwrd,
                SSHD_POL_Socks4,
                SSHD_POL_Socks5,
                SSHD_POL_SesInChanOpen,
                SSHD_POL_SesNew,
                SSHD_POL_DirTCPIP,
                SSHD_POL_TunInit,
                SSHD_POL_x11fwd, 
```
Each of these represents something happening on the isshd side - for example when ssh channel port forwarding is used by a client, a SSHD_POL_ChanPortFwrd notice will be triggered *if* it is configured to do so.  This allows a more granular control of what each site may find interesting.  The list of notice types is static and is mostly driven by the set of events that have been chosen from within the iOpenSSH code itself. 

The decision to trigger a notice is controlled by the variable with the same name as the event that triggers it.  For example the SSHD_POL_InvalUser notice is normally triggered as seen by:

	        global auth_invalid_user_notice = T &redef;

in the sshd_policy_cluster.bro file.  By adding the line:

		redef SSHD_POLICY::auth_invalid_user_notice = F;

the activation of various notices can be turned on and off.

In addition to the sets of hostile content (already described), there is also a set of behaviors that is described as "suspicious".  These represent unusual actions on the part of the user which by themselves are not cause for alarm, but if enough of them are seen it might be.  Both the list of  commands as well as the number/threshold can be set at run time if the default values are not satisfactory.

####  host_core/notice_action.bro
This file controls the action associated with the notice.  The options are log, email or page.  Say you have a problem with ssh tunneling.  The default behavior for this notice is (from notice_action.bro):

	n_act[SSHD_POLICY::SSHD_POL_TunInit]            = ACT_L;

which assigns the action log to the activation of this notice.  Adding the line:

	HOST_CORE_ACT::n_act[SSHD_POLICY::SSHD_POL_TunInit] = HOST_CORE_ACT::ACT_P;

will change the action to page (also adding by default log and email as well).


