# Lab 17 - Anti-Virtual Machine Techniques

## Lab 17-1
Analyze the malware found in Lab17-01.exe inside VMware. This is the same malware as Lab07-01.exe, with added anti-VMware techniques.
NOTE The anti-VM techniques found in this lab may not work in your environment.

**Questions**

1. What anti-VM techniques does this malware use?
2. If you have the commercial version of IDA Pro, run the IDA Python script from Listing 17-4 in Chapter 17 (provided here as findAntiVM.py). What does it find?
3. What happens when each anti-VM technique succeeds?
4. Which of these anti-VM techniques work against your virtual machine?
5. Why does each anti-VM technique work or fail?
6. How could you disable these anti-VM techniques and get the malware to run?

## Lab 17-2

Analyze the malware found in the file Lab17-02.dll inside VMware. After answering the first question in this lab, try to run the installation exports using rundll32.exe and monitor them with a tool like procmon. The following is an example command line for executing the DLL:
rundll32.exe Lab17-02.dll,InstallRT (or InstallSA/InstallSB)

**Questions**

1. What are the exports for this DLL?
2. What happens after the attempted installation using rundll32.exe?
3. Which files are created and what do they contain?
4. What method of anti-VM is in use?
5. How could you force the malware to install during runtime?
6. How could you permanently disable the anti-VM technique?
7. How does each installation export function work?

## Lab 17-3

Analyze the malware Lab17-03.exe inside VMware. This lab is similar to Lab12-02.exe, with added anti-VMware techniques.

**Questions**

1. What happens when you run this malware in a virtual machine?
2. How could you get this malware to run and drop its keylogger?
3. Which anti-VM techniques does this malware use?
4. What system changes could you make to permanently avoid the anti-VM techniques used by this malware?
5. How could you patch the binary in OllyDbg to force the anti-VM techniques to permanently fail?