# Lab 21 - 64-Bit Malware

You’ll need a 64-bit computer and a 64-bit virtual machine in order to run the malware for these labs, as well as the advanced version of IDA Pro in order to analyze the malware.

## Lab 21-1

Analyze the code in Lab21-01.exe. This lab is similar to Lab 9-2, but tweaked and compiled for a 64-bit system.

**1. What happens when you run this program without any parameters?**
**2. Depending on your version of IDA Pro, main may not be recognized automatically. How can you identify the call to the main function?**
**3. What is being stored on the stack in the instructions from 0x0000000140001150 to 0x0000000140001161?**
**4. How can you get this program to run its payload without changing the filename of the executable?**
**5. Which two strings are being compared by the call to strncmp at 0x0000000140001205?**
**6. Does the function at 0x00000001400013C8 take any parameters?**
**7. How many arguments are passed to the call to CreateProcess at 0x0000000140001093? How do you know?**

## Lab 21-2

Analyze the malware found in Lab21-02.exe on both x86 and x64 virtual machines. This malware is similar to Lab12-01.exe, with an added x64 component.

**1. What is interesting about the malware’s resource sections?**
**2. Is this malware compiled for x64 or x86?**
**3. How does the malware determine the type of environment in which it is running?**
**4. What does this malware do differently in an x64 environment versus an x86 environment?**
**5. Which files does the malware drop when running on an x86 machine? Where would you find the file or files?**
**6. Which files does the malware drop when running on an x64 machine? Where would you find the file or files?**
**7. What type of process does the malware launch when run on an x64 system?**
**8. What does the malware do?**