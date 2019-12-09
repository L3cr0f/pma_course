# Lab 20 - C++ Analysis

## Lab 20-1

The purpose of this first lab is to demonstrate the usage of the this pointer. Analyze the malware in Lab20-01.exe.

**1. Does the function at 0x401040 take any parameters?**
**2. Which URL is used in the call to URLDownloadToFile?**
**3. What does this program do?**

## Lab 20-2

The purpose of this second lab is to demonstrate virtual functions. Analyze the malware in Lab20-02.exe.

_NOTE This program is not dangerous to your computer, but it will try to upload possibly sensitive files from your machine._

**1. What can you learn from the interesting strings in this program?**
**2. What do the imports tell you about this program?**
**3. What is the purpose of the object created at 0x4011D9? Does it have any virtual functions?**
**4. Which functions could possibly be called by the call [edx] instruction at 0x401349?**
**5. How could you easily set up the server that this malware expects in order to fully analyze the malware without connecting it to the Internet?**
**6. What is the purpose of this program?**
**7. What is the purpose of implementing a virtual function call in this program?**

## Lab 20-3

This third lab is a longer and more realistic piece of malware. This lab comes with a configuration file named config.dat that must be in the same directory as the lab in order to execute properly. Analyze the malware in Lab20-03.exe.

**1. What can you learn from the interesting strings in this program?**
**2. What do the imports tell you about this program?**
**3. At 0x4036F0, there is a function call that takes the string Config error, followed a few instructions later by a call to CxxThrowException. Does the function take any parameters other than the string? Does the function return anything? What can you tell about this function from the context in which it’s used?**
**4. What do the six entries in the switch table at 0x4025C8 do?**
**5. What is the purpose of this program?**