# Lab 10 - Kernel Debugging with WinDBG

## Lab 10-1

This lab includes both a driver and an executable. You can run the executable from anywhere, but in order for the program to work properly, the driver must be placed in the C:\Windows\System32 directory where it was originally found on the victim computer. The executable is Lab10-01.exe, and the driver is Lab10-01.sys.

**Questions**

1. Does this program make any direct changes to the registry? (Use procmon to check.)
2. The user-space program calls the ControlService function. Can you set a breakpoint with WinDbg to see what is executed in the kernel as a result of the call to ControlService?
3. What does this program do?

## Lab 10-2

The file for this lab is Lab10-02.exe.

**Questions**

1. Does this program create any files? If so, what are they?
2. Does this program have a kernel component?
3. What does this program do?

## Lab 10-3

This lab includes a driver and an executable. You can run the executable from anywhere, but in order for the program to work properly, the driver must be placed in the C:\Windows\System32 directory where it was originally found on the victim computer. The executable is Lab10-03.exe, and the driver is Lab10-03.sys.

**Questions**

1. What does this program do?
2. Once this program is running, how do you stop it?
3. What does the kernel component do?