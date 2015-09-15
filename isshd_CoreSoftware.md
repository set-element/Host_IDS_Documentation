#Install of core iOpenSSHD code

-----

From the original repo we have:

A version of OpenSSH designed for high security installations where it is desirable to audit user activity. To do this we modify the SSH daemon to export information about user names, authentication, keystrokes, file transfers, remote command execution and a variety of SSH related metadata in as agnostic a way as possible. As an addition to this project, we provide infrastructure via the Bro Intrusion Detection System. The most general idea here is that a site can generate local security policy in the Bro scripting language and monitor in near real time user activity.

Please note that this is in no way designed to act as a hidden backdoor. We have made it noisy and easy to identify to help avoid this sort of issue. In addition, this software is complicated and not designed for naive implementations. Finally, if you are not sure what your local site policy is regarding monitoring user activity with or without their notification please find out before anyone else uses it. Privacy is not something that we take lightly. Nor is irony I suppose. 

Since long ago when that was written there has been added complexity as well as a much better hashed out upgrade process.

Currently the code follows a series of forks:

	**OpenSSH Currnet => rapier1/HPN => iSSHD Mods**

which allows the code base for isshd keep track with the current OpenSSH and HPN changes.
