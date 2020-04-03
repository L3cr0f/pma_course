# Lab 20 - C++ Analysis

## Lab 20-1

The purpose of this first lab is to demonstrate the usage of the _this_ pointer. Analyze the malware in Lab20-01.exe.

**1. Does the function at 0x401040 take any parameters?**

This function does not take any parameters, since any push instruction prior the _call_ instruction is executed. However, the function uses the _this_ pointer set before the function call is made.

![_IDA Pro_ _this_ pointer](../Pictures/Lab_20/lab_20-01_1_ida_pro_1.png)

**2. Which URL is used in the call to URLDownloadToFile?**

The sample will load the _URL_ _http://www.practicalmalwareanalysis.com/cpp.html_ into the address pointed by the _this_ pointer in the _WinMain_ function. Then, in the function at _0x00401040_, this address will be accessed by means of _this_ pointer. This process is better explained in the following picture:

![_IDA Pro_ _URL_](../Pictures/Lab_20/lab_20-01_2_ida_pro_1.png)

**3. What does this program do?**

The program will execute the function _URLDownloadToFileA_ to download the file _http://www.practicalmalwareanalysis.com/cpp.html_ and save it to ·"c:\tempdownload.exe".

## Lab 20-2

The purpose of this second lab is to demonstrate virtual functions. Analyze the malware in Lab20-02.exe.

_NOTE This program is not dangerous to your computer, but it will try to upload possibly sensitive files from your machine._

**1. What can you learn from the interesting strings in this program?**

To do so, first, we execute the _strings_ command:

```
C:\> strings Lab20-02.exe

...
.pdf
.doc
%s-%d.pdf
pdfs
ftp.practicalmalwarenalaysis.com
Home ftp client
%s-%d.doc
docs
C:\*
...
```

Mmmm... Interesting! It seems that this sample performs some actions regarding _FTP_ communication and documents (_PDF_ and _DOC_).

**2. What do the imports tell you about this program?**

To get the imports of the binary we use the _Python_ script "Scripts/General/get_file_imports.py" as follows:

```
C:\> python get_file_imports.py Lab20-02.exe

######################
IMPORTS
######################
======================
KERNEL32.dll
======================
FindNextFileA
FindClose
FindFirstFileA
FlushFileBuffers
GetStringTypeW
GetStringTypeA
LCMapStringW
LCMapStringA
MultiByteToWideChar
SetStdHandle
LoadLibraryA
GetProcAddress
HeapAlloc
GetModuleHandleA
GetStartupInfoA
GetCommandLineA
GetVersion
ExitProcess
HeapDestroy
HeapCreate
VirtualFree
HeapFree
VirtualAlloc
HeapReAlloc
TerminateProcess
GetCurrentProcess
UnhandledExceptionFilter
GetModuleFileNameA
FreeEnvironmentStringsA
FreeEnvironmentStringsW
WideCharToMultiByte
GetEnvironmentStrings
GetEnvironmentStringsW
SetHandleCount
GetStdHandle
GetFileType
RtlUnwind
WriteFile
GetLastError
SetFilePointer
GetCPInfo
GetACP
GetOEMCP
CloseHandle
======================
WININET.dll
======================
InternetCloseHandle
FtpPutFileA
InternetOpenA
InternetConnectA
FtpSetCurrentDirectoryA
======================
WS2_32.dll
======================
WSAStartup
gethostname
```

All these imports tells us several interesting things about the sample like:

- It performs some Internet connection.
- It performs some _FTP_ connection.
- It performs file operations.

**3. What is the purpose of the object created at 0x4011D9? Does it have any virtual functions?**

This object _var_15_ have a total of two virtual functions as we can see in the following picture:

![_IDA Pro_ virtual functions](../Pictures/Lab_20/lab_20-02_3_ida_pro_1.png)

This virtual functions point to two functions located at _0x00401370_ and _0x00401440_.

![_IDA Pro_ virtual functions pointers](../Pictures/Lab_20/lab_20-02_3_ida_pro_2.png)

Let's analyze them to see what it hides.

The first one, located at _0x00401370_, seems to be a

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
