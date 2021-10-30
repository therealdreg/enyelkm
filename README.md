# enyelkm
LKM rootkit for Linux x86 with the 2.6 kernel. It inserts salts inside system_call and sysenter_entry.

Please, consider make a donation: https://github.com/sponsors/therealdreg

## EnyeLKM Overview 

Written by Jacob Williams - 2008, thx for your presentation!

###  What is EnyeLKM?

* EnyeLKM is a Linux rootkit that is used by an attacker to maintain persistence on compromised Linux machines running a 2.6 kernel.
* As indicated by its name, it is implemented as a loadable kernel module.
* It cannot be used by itself to compromise a Linux machine.  Once a machine is compromised, it is used to provide a persistent back door.
* Since the code is inserted into kernel space it does not show up in the process list and can impact ALL user mode programs running on the infected machine.
* By using the rootkit to maintain persistence on the infected machine, the attacker does not have to use an attack vector against the machine every time he needs access.  
* Using the rootkit is more advantageous than traditional methods of leaving a backdoor account or running a user mode network backdoor as these can be easily detected.

### What does it provide?

EnyeLKM offers the following features:

* Hiding directories
* Hiding files
* Hiding specific content within files
* Hiding processes
* Privilege escalation to root from a non-root login
* Reverse shell
* The EnyeLKM module itself is hidden from lsmod

### Hiding files and data

EnyeLKM hides files, directories and processes by inserting jumps  to trampoline functions in both the system_call() and sys_enter() instructions in the kernel.  All user space applications (read() , write(), etc) invoke kernel space functionality (system calls) through one of these two functions.
 
When EnyeLKM is compiled, a special hide string is defined in config.h as the variable SHIDE.  The default string is “OCULTAR”.  An English translation of the rootkit is also available that uses a default hide string of “HIDE^IT”.  Since many of your attackers are script kiddies that don't know how to code, it has been my experience that most of the kits found use one of these two strings (although others are certainly possible).

The SHIDE string is significant.  Any file or directory name containing this string will be hidden from view when performing a directory listing.  

The SHIDE string is also used to hide the kernel module itself on the filesystem.  It is installed in /etc/ by default but will usually not be visible because the module is hiding it.

A common reason to compromise Linux servers is to install a warez site, IRC server, or botnet.  In any of these cases it helps to have hidden directories that a system administrator cannot see.  This can be accomplished by including the SHIDE string in the directory name.  Of course many gigabytes of missing disk space (such as in the case of a warez site) may be noticed by a good system administrator.

Only the top level hidden directory needs to include the SHIDE string in its name.  All child directories and files can have normal names.  Since the directory name will only be known to those meant to access it, the child directories and files will not be found by any interlopers.

Two additional strings are defined in read.c as MOPEN and MCLOSE.  These are set to by default to “#<OCULTAR_8762>” and #</OCULTAR_8762>” respectively.  Any data inside a file between these two strings (including the strings themselves) will not be returned from a read call.

This is used to load the kernel module on boot.  By default the command to load the EnyeLKM module will be contained between these strings in /etc/rc.d/rc.sysinit.  Before the module is loaded (i.e. while the system is booting) these strings will be visible in the file.  As soon as the module is loaded, the strings will not be visible in the file.  For this reason, simply inspecting the /etc/rc.d/rc.sysinit file for the insmod command will not reveal the rootkit.

As a matter of course, simply because you think you know the location of a hidden directory or kernel module does not mean that you should probe it (list it, stat any files, etc) on a live system where the module may be running.  

While EnyeLKM does not employ any defensive technology some other rootkits do.  This could easily be added to EnyeLKM by a skilled programmer.  An example of defensive technology would be to monitor read attempts to a hidden directory by an unprivileged process (one without the magic gid).  If an unprivileged process tries to read from the hidden directory the rootkit may try to delete itself or write random data to the disk to obfuscate digital forensics.

While I have not seen any rootkits that try to destroy the system, I have seen several examples that will remove themselves from memory and delete from disk if probed.  Corrupting the whole system is a trivial matter from kernel space.

The bottom line is this: only probe hidden directories for data when you know it is safe.  How do you know when it is safe?  It is only safe when you are examining a disk image  (or the actual disk) of the compromised machine from a trusted computer.  You can't trust anything the compromised machine tells you.

### Hiding processes

If the attacker wishes to run an IRC server, warez site, or other malicious enterprise simply hiding data won't do.  The processes used for this activity would be obvious to an administrator just by running a simple 'ps' command.  EnyeLKM inspects a process's GID to determine whether or not to hide it from the processlist.  The GID of processes to hide is defined in config.h.  By default it is set to 0x489196ab.  

Just like the SHIDE string, the gid for hidden processes is rarely if ever changed by script kiddies when building the rootkit.  One way to detect the rootkit while running on the system is to run a specially crafted utility that runs in a tight loop and changes it's GID to the default EnyeLKM GID.  If the target process disappears from the process list, something is hiding the process.  EnyeLKM is likely installed on the system.

For those familiar with Linux operation, the process is hidden from tools such as ps by hiding the PID's directory from the /proc filesystem.  The directory is still there and can be changed into (if the PID is known) just not read in a directory listing.

A utility to find the EnyeLKM GID was written as part of the exploration of this rootkit.  Code can be downloaded from the link below. http://www.williamsworx.com/wiki/pub/Linux/EnyeLKM/findEnyeGID.c

### Hiding network connections

Hiding network connections is just as important as hiding processes on a system if the attacker is to outsmart a savvy system administrator.

EnyeLKM will hide network connections from processes that have the special GID from netstat and other tools that depend on reading the /proc filesystem.

There is a (laborious) way to find network connections from view by EnyeLKM that still works as of EnyeLKM 1.2 but may be corrected in a future version.  It involves counting network connections.  Even though EnyeLKM correctly hides the network connections, it does not correctly update the TCP and UDP stack statistics.

### Privilege Escalation

When an attacker is a legitimate user, he may need to escalate his privileges to perform additional malicious activity.  While the attacker needed root privileges to install the rootkit, the user may never have gained an interactive shell.  Another possibility is that the user gained root privileges but the known root password has been changed.

In either case, the user can gain root by executing a kill command.  Running the following command in a shell will grant that shell root privileges:
'kill -s 58 12345'

In this case '58' is the signal and 12345 is the process ID.  There need not be any process ID 12345 running on the system.  The kill system call is trapped by the kernel and the shell running the command is given root privileges.  

The signal and PID are default values and can be changed in kill.c.

Note that in this case, the shell is given root privileges by changing the UID to zero in the shell's kernel task_struct.  No changes are visible on the shell.  Confirmation that the UID has been changed can be achieved by trying something that ordinarily can't be done as the root user.

### Network Backdoor

Most often the attacker will need to connect to the compromised machine remotely.  A traditional method of providing backdoor access is to run a user mode program that opens a port for the attacker to connect to.  This is not especially stealthy since it can be seen in netstat output.  Even if the user mode program is being blocked from netstat output by the methods described earlier the open port still may be detected with active port scanning (such as an internal security team performing a nessus or nmap scan).

To solve this issue, EnyeLKM offers a method remote access commonly referred to as reverse shell by callback.  The attacker sends a specially crafted ICMP echo request packet to the machine with the rootkit installed.  Since the rootkit is installed in kernel space, it is able to examine all incoming network packets.  When it detects an ICMP echo request, it checks the ICMP payload to see if it includes the pre-shared key and connection parameters.  If the payload includes the key and connection parameters the rootkit machine calls back to the machine sending the ping on the specified port.  The connection will give the attacker a root shell.

The newest version of EnyeLKM also offers TCP connection triggering.

The shell returned will be hidden from netstat and the process list.

Connections established using the network backdoor are not encrypted.

The network backdoor in EnyeLKM has matured with the rootkit.

Versions 1.1.2 – 1.1.4 only offered ICMP triggering.  Since many hosts do not process ICMP messages (or they may be blocked by perimeter firewalls) a TCP available as an option in the 1.2 build.  When using the TCP option for triggering, a listening port on the target machine must be used.  Attempting to trigger a closed port will not work as the kernel level monitor is inserted in the TCP stack above where port multiplexing occurs.

Network Address Translation (NAT) is an issue that EnyeLKM's backdoor is not programmed to deal with.  There is no option to trigger a callback address in the connection program.  When the attacker and target are on different sides of a NAT device, the backdoor cannot be triggered.  When the target receives the trigger packet, the source address appears to be the internal address of the NAT device.  The target will call back to the internal address of the NAT device and will most likely receive a RST packet from the NAT device.

***** Don't take this to mean your machines are safe from this backdoor if they sit behind a NAT device.  I personally know a hacker who has programmed a patch to the rootkit and connection program that overcome the NAT problem by adding a callback address to the trigger packet.  The code modifications were actually quite trivial. *****

![ScreenShot](https://github.com/David-Reguera-Garcia-Dreg/enyelkm/blob/master/nat.png)

Why NAT poses a problem:

In this diagram, the blue lines represent the trigger and the red lines represent the callback.  The same problem occurs whether an ICMP or TCP trigger is used.  Assume in this case that a TCP trigger is used. The TCP SYN packet will make it through the NAT device.  The target reply (normal SYN/ACK) will be returned through the NAT device since there is a Port Address Translation (PAT) rule in place for this connection.

Encoded in the TCP packet is the port to call back to (default 8822).  The target now tries to establish a connection to that port on the source address.  The problem is that the target sees the source address as 192.168.0.1 instead of 172.16.0.5.  Since no PAT rule exists for this IP/Port combination the connection is actively refused by the NAT device.

A pre-shared key is used to offer some sort of authentication for the rootkit.  Without a configurable key, anyone with the connection program could connect to any machine with EnyeLKM installed.  The default key is rarely changed by script kiddies.  It is defined in config.h (ICMP_CLAVE) and is set by default “ENYELKMICMPKEY”.  It can only be changed at compile time, so it is considerably less flexible than standard password based authentication.  In EnyeLKM 1.2, the TCP shared key defaults to “ENYELKMTCPKEY”.  It is defined in config.h as TCP_CLAVE.

The client (attacker) side connection program is called “connectar”.  It must be run from the client machine as root since it requires raw socket access to craft the trigger packet.  

After the connectar program sends the trigger packet, it opens a TCP port on the sending machine and waits for the attacked machine to call back to the open port.  If no port is specified when the program is run, the callback will occur on TCP 8822.  Any NIDS in place should be configured to flag TCP 8822 connections for inspection.

Client Usage:
./connectar -icmp IP_address [callback port]
./connectar -tcp IP_address destination_port [callback port]

### Detection

Just using lsmod and looking for the module name is out since the module name contains the SHIDE string and will be filtered out on a call to read.  The module name could also have been changed to something normal before loading.  There does not appear to be a way to detect the module by name when it is loaded in memory.

Assuming the attacker has compiled the rootkit with all defaults, a file or directory created with a name containing the string “OCULTAR” (“HIDE^IT” for the English version) will be hidden.  As an investigator on a live system, you can create a file with the SHIDE string.  If the created file is hidden, EnyeLKM is installed on the system.  Just because the file is visible, this does not mean that EnyeLKM is not present on the system.  It may just have been compiled with options other than the default.

Hiding text in a file is somewhat more reliable since the MOPEN and MCLOSE defines are not found in config.h and can easily be overlooked.  Try creating a file that contains these tags and write some specific text between the tags.  Save the file and cat it from the command line.  To reiterate, just because this fails does not mean that the system is clean.

Hidden processes can be found by scanning the /proc filesystem for directories that are present but not being listed with the standard readdir() calls.  Proof of concept code can be found at the link below.  Once the process's directory in /proc is located, the command line and environment of the process can be determined.  This should offer some clue about what the attacker is doing with the compromised machine.

Obviously the same advice offered earlier about probing hidden directories still applies here.  Some safety exists with this method however.  Because the /proc filesystem is only present in memory access and modification times are unlikely to be tracked by the attacker's code.

If at all possible, it is best to first discover the magic GID and run the detection process with that GID.

http://www.williamsworx.com/wiki/pub/Linux/EnyeLKM/findHiddenProc.tgz

Hidden network connections are somewhat more difficult to find.  Connections are hidden from /proc (where netstat gets its output) but connection statistics are not updated.  Hidden network connections can be discovered by comparing the number of established connections in /proc/net/stat to the number of connections in netstat output.  While this does not expose what the network connections are doing, it does show that some are being hidden and warrants further investigation.

If libpcap and tcpdump are installed on the victim machine, these can be used to ferret out active network connections that are not being displayed in netstat.  It would be better on a non-switched network to run the sniffer from a non-suspect machine since tcpdump may be compromised as well.  The connections EnyeLKM hides from netstat are not hidden from tcpdump, even when running on the compromised machine.  Note that when using this method, traffic must be captured for at least the TCP timeout period for the machine you are investigating.  A hidden connection will only be revealed by tcpdump if traffic is sent over the connection while tcpdump is listening.  By capturing for longer than the TCP timeout period, traffic is guaranteed to be passed on the hidden connection

If a NIDS is installed on the network, all traffic with a source or destination port of 8822 should be flagged for inspection.  If the NIDS offers inspection of packet internals, ICMP and TCP payloads should be inspected for ENYELKMICMPKEY and ENYELKMTCPKEY.

The ICMP trigger uses an ICMP echo request.  Its payload is short and contains only the pre-shared key and the callback port in hexadecimal (stored in little endian order).

The TCP  trigger completes the normal TCP three way handshake on the chosen port.  It then sends a PSH packet containing the pre-shared key and the callback port in hexadecimal (again stored in little endian order).

Packet dumps of both triggering mechanisms can be found at the links below.  They are in pcap format and can be examined using Wireshark.

* http://www.williamsworx.com/wiki/pub/Linux/EnyeLKM/tcpTrigger.pcap
* http://www.williamsworx.com/wiki/pub/Linux/EnyeLKM/icmpTrigger.pcap
* http://www.williamsworx.com/wiki/pub/Linux/EnyeLKM/icmpTwoTriggers.pcap

If your system has /proc/kcore enabled (Fedora kernels usually do not) you can use gdb to disassemble the sysenter_entry.  A normal sysenter routine won't jump soon after it is called, but that's exactly what happens with EnyeLKM installed:

0xc0103ff5 <sysenter_past_esp+62>:      jne    0xc0104114 <syscall_trace_entry>
0xc0103ffb <sysenter_past_esp+68>:      push   0xd0ba32a4
0xc0104000 <sysenter_past_esp+73>:      ret    

Of course, as with any system compromised at the kernel level, the best thing you can do to ferret out the rootkit on the disk is to take the system offline, make a forensic disk image, and examine it on a clean system.

### Removal 

Removal of this rootkit in its default form is almost too easy.

The EnyeLKM rootkit insmod command is installed into /etc/rc.d/rc.sysinit or in a very limited distribution /etc/inittab.  The module itself is installed as /etc/.enyelkmOCULTAR.ko.  The insmod command will not be seen if you inspect /etc/inittab or /etc/rc.d/rc.sysinit since it is hidden between OCULTAR tags.  This hiding can be used to your advantage when removing the rootkit.  Simply cat both files out to /tmp and copy them over the originals.  The hidden text will be gone from the file (instead of simply hidden).  Unfortunately, the module itself cannot be unloaded so a reboot is needed to remove the module from the running kernel.

Note that this method will not work if the insmod command for the rootkit is placed in some other location (such as another startup script or binary).

Once the system reboots without installing rootkit module, a thorough investigation of running processes and network connections should be performed.  Hackers will often install more than one backdoor on a system to maintain persistence.

## Referenced by

* Design and Implementation of a Virtual Machine Introspection based Intrusion Detection System  - Thomas Kittel:  https://pdfs.semanticscholar.org/d48a/dbea94a5e2bc108b274f3176db9d5024af15.pdf
* Full Virtual Machine State Reconstruction for Security Applications - Christian A. Schneider: http://citeseerx.ist.psu.edu/viewdoc/download;jsessionid=DDA289985A5B66223310A012971CAD3E?doi=10.1.1.722.9243&rep=rep1&type=pdf
