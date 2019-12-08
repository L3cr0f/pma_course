# Lab 1 - Basic Analysis

The purpose of the labs is to give you an opportunity to practice the skills taught in the chapter. In order to simulate realistic malware analysis you will be given little or no information about the program you are analyzing. Like all of the labs throughout this book, the basic static analysis lab files have been given generic names to simulate unknown malware, which typically use meaningless or misleading names.
Each of the labs consists of a malicious file, a few questions, short answers to the questions, and a detailed analysis of the malware. The solutions to the labs are included in Appendix C.
The labs include two sections of answers. The first section consists of short answers, which should be used if you did the lab yourself and just want to check your work. The second section includes detailed explanations for you to follow along with our solution and learn how we found the answers to the questions posed in each lab.

## Lab 1-1

This lab uses the files Lab01-01.exe and Lab01-01.dll. Use the tools and techniques described in the chapter to gain information about the files and answer the questions below.


**1. Upload the files to http://www.VirusTotal.com/ and view the reports. Does either file match any existing antivirus signatures?**

First of all, I checked the SHA256 hashes of both files in VirusTotal before submit them. These are:

```
58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47 Lab01-01.exe
f50e42c8dfaab649bde0398867e930b86c2a599e8db83b8260393082268f2dba Lab01-01.dll
```

The results of VirusTotal are the following:

40/69 Antivirus detect the file _Lab01-01.exe_ as malicious.
32/69 Antivirus detect the file _Lab01-01.dll_ as malicious.

The descriptions of the Antivirus software are quite generic, many of them just say that are a _Trojan_.

**2. When were these files compiled?**

We can check this value with several tools, in my case I have used VirusTotal and PEviwe:

- Lab01-01.exe: 2010-12-19 16:16:19
- Lab01-01.dll: 2010-12-19 16:16:38

3. **Are there any indications that either of these files is packed or obfuscated? If so, what are these indicators?**

We can check it with PEview, by looking for the values of _Virtual Size_ and _Size of Raw Data_  of the _IMAGE SECTION HEADER .text_ header:

- Lab01-01.exe:
	- Virtual Size: 970
	- Size of Raw Data: 1000
- Lab01-01.dll:
	- Virtual Size: 39E
	- Size of Raw Data: 1000


4. Do any imports hint at what this malware does? If so, which imports are they?

The imports are one of the main indicator of what a malware does, so it is important to check them:

- Lab01-01.exe:

This file seems to perform same filesystem operations, since it loads several functions to do so. Some of these functions allow the program to search for files and create and copy files.

```
======================
KERNEL32.dll
======================
UnmapViewOfFile
MapViewOfFile
CreateFileMappingA
CreateFileA
FindClose
FindNextFileA
FindFirstFileA
CopyFileA
```

- Lab01-01.dll:

This file seems to perform several network and process operations, like creating a mutex or a new process, based on the imported functions.

```
======================
KERNEL32.dll
======================
Sleep
CreateProcessA
CreateMutexA
OpenMutexA
CloseHandle
======================
WS2_32.dll
======================
socket
WSAStartup
inet_addr
connect
send
shutdown
recv
closesocket
WSACleanup
htons
```

5. Are there any other files or host-based indicators that you could look for on infected systems?

We can look for strings and see if there is something interesting within them:

Lab01-01.exe:

```
strings Lab01-01.exe
...
kerne132.dll
kernel32.dll
.exe
C:\*
C:\windows\system32\kerne132.dll
Kernel32.
Lab01-01.dll
C:\Windows\System32\Kernel32.dll
WARNING_THIS_WILL_DESTROY_YOUR_MACHINE
```

This file seems to perform some operation with the file called _Lab01-01.dll_. Also it do something with the library _kernel32.dll_, probably modify it, since we can see another file called _kerne132.dll_, with the letter _L_ changed for the number _1_.

- Lab01-01.dll:

```
strings Lab01-01.dll
...
hello
127.26.152.13
SADFHUHF
...
```

We can see that an IP address is shown, an important network-based indicator. Also, the string _SADFHUHF_ could be the name of the mutex created by the malware.

6. What network-based indicators could be used to find this malware on infected machines?

With basic static analysis techniques we can only get one network-based indicator, the IP address _127.26.152.13_.

7. What would you guess is the purpose of these files?

After the initial analysis is performed, we can perform some hypotheses regarding the samples:

- Lab01-01.exe: this file seems to copy the file _Lab01-01.dll_ into _C:\windows\system32\\_ with the name _kerne132.dll_ (it changes the _L_ for a _1_).
- Lab01-01.dll: this file seems to execute some process and perform some network requests to the IP address _127.26.152.13_.

## Lab 1-2

Analyze the file Lab01-02.exe.

**Questions**

1. Upload the Lab01-02.exe file to http://www.VirusTotal.com/. Does it match any existing antivirus definitions?

First of all, I checked the SHA256 hashes of both files in VirusTotal before submit them. These are:

```
c876a332d7dd8da331cb8eee7ab7bf32752834d4b2b54eaa362674a2a48f64a6 Lab01-02.exe
```

The results of VirusTotal are the following:

44/69 Antivirus detect the file _Lab01-02.exe_ as malicious.

2. Are there any indications that this file is packed or obfuscated? If so, what are these indicators? If the file is packed, unpack it if possible.

The file seems to be obfuscated with UPX, based on the headers shown by PEview:

![UPX packed](../Pictures/Lab_01/lab_01-02_2.png)

Also if we analyze the binary with PE Detective we can also see that it is packed with UPX v3.0.

To unpack this binary, we simply use UPX program aso so:

```
upx -d Lab01-02.exe
```

To not overwrite the original file, we could execute the following command:

```
upx -d Lab01-02.exe -o Lab01-02_unpacked.exe
```

This gives us the unpacked binary:

```
8bcbe24949951d8aae6018b87b5ca799efe47aeb623e6e5d3665814c6d59aeae Lab01-02.exe
```

This new binary has the following VirusTotal results:

49/71 Antivirus detect the file _Lab01-02.exe_ as malicious.

3. Do any imports hint at this program’s functionality? If so, which imports are they and what do they tell you?

The file has some interesting imports like the following:

```
======================
KERNEL32.DLL
======================
SystemTimeToFileTime
GetModuleFileNameA
CreateWaitableTimerA
ExitProcess
OpenMutexA
SetWaitableTimer
WaitForSingleObject
CreateMutexA
CreateThread
======================
ADVAPI32.dll
======================
CreateServiceA
StartServiceCtrlDispatcherA
OpenSCManagerA
======================
WININET.dll
======================
InternetOpenUrlA
InternetOpenA
```

As we can see, it seems to perform some system operations like creating mutexes, also, it seems to have the ability to create a new service in the host, probably to gain persistence. Finally, it also can perform network operations through HTTP.

4. What host- or network-based indicators could be used to identify this malware on infected machines?

The strings of the binary shows some interesting IOCs, some of them are.

- Host-based: Malservice (the name of the service create by the binary) and HGL345 (probably the name of the mutex).
- Network-based: http://www.malwareanalysisbook[.]com.

## Lab 1-3

Analyze the file Lab01-03.exe. Questions

**Questions**

1. Upload the Lab01-03.exe file to http://www.VirusTotal.com/. Does it match any existing antivirus definitions?


2. Are there any indications that this file is packed or obfuscated? If so, what are these indicators? If the file is packed, unpack it if possible.

3. Do any imports hint at this program’s functionality? If so, which imports are they and what do they tell you?
4. What host- or network-based indicators could be used to identify this malware on infected machines?

## Lab 1-4

Analyze the file Lab01-04.exe.

**Questions**

1. Upload the Lab01-04.exe file to http://www.VirusTotal.com/. Does it match any existing antivirus definitions?
2. Are there any indications that this file is packed or obfuscated? If so, what are these indicators? If the file is packed, unpack it if possible.
3. When was this program compiled?
4. Do any imports hint at this program’s functionality? If so, which imports are they and what do they tell you?
5. What host- or network-based indicators could be used to identify this malware on infected machines?
6. This file has one resource in the resource section. Use Resource Hacker to examine that resource, and then use it to extract the resource. What can you learn from the resource?