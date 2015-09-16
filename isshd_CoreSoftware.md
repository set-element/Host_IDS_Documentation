#Install of core iOpenSSHD code

From the original repo we have:

> A version of OpenSSH designed for high security installations where it 
> is desirable to audit user activity. To do this we modify the SSH daemon 
> to export information about user names, authentication, keystrokes, file 
> transfers, remote command execution and a variety of SSH related metadata 
> in as agnostic a way as possible. As an addition to this project, we provide 
> infrastructure via the Bro Intrusion Detection System. The most general
> idea here is that a site can generate local security policy in the Bro scripting 
> language and monitor in near real time user activity.
>
> Please note that this is in no way designed to act as a hidden backdoor. We have 
> made it noisy and easy to identify to help avoid this sort of issue. In addition, 
> this software is complicated and not designed for naive implementations. Finally,
> if you are not sure what your local site policy is regarding monitoring user activity
> with or without their notification please find out before anyone else uses it.
> Privacy is not something that we take lightly. Nor is irony I suppose. 

Since long ago when that was written there has been added complexity as well as a much better hashed out upgrade process.

Currently the code follows a series of forks:

	OpenSSH Currnet => rapier1/HPN => iSSHD Mods

which allows the code base for isshd keep track with the current OpenSSH and HPN changes.  Because of this, the isshd code is a branch of the rapier1 tree.

-----

### Download and Configuration

First download the code:

```
[scottc@green-m ~]$ git clone https://github.com/set-element/openssh-hpn-isshd.git
Initialized empty Git repository in /home/scottc/openssh-hpn-isshd/.git/
remote: Counting objects: 46144, done.
remote: Compressing objects: 100% (43/43), done.
remote: Total 46144 (delta 13), reused 6 (delta 6), pack-reused 46095
Receiving objects: 100% (46144/46144), 12.41 MiB | 4.09 MiB/s, done.
Resolving deltas: 100% (36209/36209), done.
[scottc@green-m ~]$
```

Then switch to the isshd repo:

```
[scottc@green-m ~]$ cd openssh-hpn-isshd/
[scottc@green-m openssh-hpn-isshd]$ git checkout isshd
Branch isshd set up to track remote branch isshd from origin.
Switched to a new branch 'isshd'
[scottc@green-m openssh-hpn-isshd]$
```

And run autoheader and autoconf to set up the configure and config.h.in files.

```
scottc@green-m openssh-hpn-isshd]$
[scottc@green-m openssh-hpn-isshd]$ autoheader
[scottc@green-m openssh-hpn-isshd]$ autoconf
[scottc@green-m openssh-hpn-isshd]$
```

For the next step, run configure with one or more of the following options:
```
  --with-nerscmod           Add sshd instrumentation

  --with-stunnelport=PORT   Set stunnel port if other than 799/tcp
  --with-stunnelhost=HOST   Set stunnel host if other than localhost.  Do not quote.
  --with-passwdrec          Record password data
```

The most common option is "--with-nerscmod" which will turn on all the auditing features.  The stunnel config options tells the isshd where to put the logging data (which is assumed to be a socket of some kind).  The "--with-passwdrec" option will enable the recording of passwords its use is *strongly* discouraged since they will be put into the general logs in cleartext.

At this point we will do a routine install on this system, setting up the base directory away from the usual /usr.  For example:

```
[scottc@green-m openssh-hpn-isshd]$ ./configure --with-nerscmod --prefix="/home/scottc/ISSHD_INSTALL"
checking for gcc... gcc
checking for C compiler default output file name... a.out
checking whether the C compiler works... yes
checking whether we are cross compiling... no
checking for suffix of executables...
checking for suffix of object files... o
checking whether we are using the GNU C compiler... yes
checking whether gcc accepts -g... yes

(snipping out huge volumes of config logs)

OpenSSH has been configured with the following options:
                     User binaries: /home/scottc/ISSHD_INSTALL/bin
                   System binaries: /home/scottc/ISSHD_INSTALL/sbin
               Configuration files: /home/scottc/ISSHD_INSTALL/etc
                   Askpass program: /home/scottc/ISSHD_INSTALL/libexec/ssh-askpass
                      Manual pages: /home/scottc/ISSHD_INSTALL/share/man/manX
                          PID file: /var/run
  Privilege separation chroot path: /var/empty
            sshd default user PATH: /usr/bin:/bin:/usr/sbin:/sbin:/home/scottc/ISSHD_INSTALL/bin
                    Manpage format: doc
                       PAM support: no
                   OSF SIA support: no
                 KerberosV support: no
                   SELinux support: no
                 Smartcard support:
                     S/KEY support: no
              MD5 password support: no
                   libedit support: no
  Solaris process contract support: no
           Solaris project support: no
       IP address in $DISPLAY hack: no
           Translate v4 in v6 hack: yes
                  BSD Auth support: no
              Random number source: OpenSSL internal ONLY
              NERSC Mods          : yes
              STUNNEL Host        : localhost
              STUNNEL Port        : 799
              Record Passwd Data  : no
             Privsep sandbox style: rlimit

              Host: x86_64-unknown-linux-gnu
          Compiler: gcc
    Compiler flags: -g -O2 -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wformat-security -Wno-pointer-sign -fno-strict-aliasing -D_FORTIFY_SOURCE=2 -ftrapv -fno-builtin-memset -fstack-protector-all -fPIE
Preprocessor flags:
      Linker flags:  -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -fstack-protector-all -pie
         Libraries: -lcrypto -lrt -ldl -lutil -lz -lnsl  -lcrypt -lresolv
```
Now just run 'make' and 'make install' and iSSHD will be installed.  Additional (normal) configuration can be done as per the usual OpenSSH software so I will skip that.

-----
[Return to Index](Intro_Index.md)
