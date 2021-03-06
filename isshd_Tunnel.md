#Tunnel and Analysis System Configuration

The most typical (and the only) example of moving the data from the iSSHD instance to the data analysis node is to use an stunnel.  In this case it will be from the local iSSHD system on localhost 799/tcp to the analysis system where it will be deposited into a text file.

-----

### Data Producer: Local system stunnel config

For the system running the iSSHD, a configuration file for stunnel should look something like:

```
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
cert = /etc/iSSHD/stunnel.pem
client=yes
debug = 2
pid=/var/run/syslog_c2.pid
foreground = no

[isshd-client]
accept = 127.0.0.1:799
connect = 10.10.10.10:799
```
which will take data from a 799/tcp socket on localhost and deposit it on to 10.10.10.10:799/tcp




### Data Consumer: Options for stunnel landing

On the receiving end, things are a bit more complex.  When dealing with multiple input streams consisting of structured data, it is necessisary to avoid mixing the various records during logging.  There are [several options](set-element/InstrumentedSSHD) for this, but I will use the ssllogmux.pl program as an example.

The ssllogmux program is a SSL socket listener that can take multiple connections and write the incoming data to a single log file. It is fairly simple and has run for years at NERSC.

Documentation is a little sparse, but the perldoc page looks like

```
         This script starts up an SSL listener on a configurable port, and takes
        any input from clients connecting to that port, serializes it and and
        outputs it to a file, or to stdout. Nonblocking I/O is used for efficiency.
         In addition, this script has an option to perform on the fly translation
        of bropipe input from the type=size,contents format to the type=contents
        format, with conversion to URL strings when it detects that a string contains
        non-alphanumeric characters.
         Originally based on the non-forking server from the Perl Cookbook, modified
        for SSL and bropipe translation.

         Options for the script:
         -p PORT the port to run the listener on, defaults to 1799
         -o FILE the filename where output should be sent
                 if you don't specify one, then stdout will
                 be used
         -P dir  directory for the pidfile, defaults to /var/run/
         -d      turn on debugging output
         -c FILE File containing the ssl cert for the server
                 defaults to certs/server-cert.pem
         -k FILE File containing the key for the cert used for SSL
                 defaults to certs/server-key.pem. You will be prompted to
                 enter the passphrase if it is encrypted.
         -t      turn on translation of old bropipe format to new urlstring
                 based format.
         -h      Print out help
         -e      Display parsing errors on bropipe translation.
         -f      Stay in foreground - do not become a background process

         If the process recieved a HUP signal, it will close the file it is
        writing to, and open it again.
```

The log file generated by ssllogmux should be consitered the point of truth in that any bro related logs are based on an interpretation of this file.  It is ideologically similar to a pcap trace.


-----
[Return to Index](Intro_Index.md)

