# Lab 7 - Analyzing Malicious Windows Programs

## Lab 7-1

Analyze the malware found in the file Lab07-01.exe.

**1. How does this program ensure that it continues running (achieves per- sistence) when the computer is restarted?**
**2. Why does this program use a mutex?**
**3. What is a good host-based signature to use for detecting this program?**
**4. What is a good network-based signature for detecting this malware?**
**5. What is the purpose of this program?**
**6. When will this program finish executing?**

## Lab 7-2

Analyze the malware found in the file Lab07-02.exe.

**1. How does this program achieve persistence?**
**2. What is the purpose of this program?**
**3. When will this program finish executing?**

## Lab 7-3

For this lab, we obtained the malicious executable, Lab07-03.exe, and DLL, Lab07-03.dll, prior to executing. This is important to note because the malware might change once it runs. Both files were found in the same directory on the victim machine. If you run the program, you should ensure that both files are in the same directory on the analysis machine. A visible IP string beginning with 127 (a loopback address) connects to the local machine. (In the real version of this malware, this address connects to a remote machine, but we’ve set it to connect to localhost to protect you.)
This lab may cause considerable damage to your computer and may be difficult to remove once installed. Do not run this file without a virtual machine with a snapshot taken prior to execution.
This lab may be a bit more challenging than previous ones. You’ll need to use a combination of static and dynamic methods, and focus on the big picture in order to avoid getting bogged down by the details.

**1. How does this program achieve persistence to ensure that it continues running when the computer is restarted?**
**2. What are two good host-based signatures for this malware?**
**3. What is the purpose of this program?**
**4. How could you remove this malware once it is installed?**