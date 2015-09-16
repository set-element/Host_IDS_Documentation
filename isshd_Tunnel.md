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














[Return to Index](Intro_Index.md)

