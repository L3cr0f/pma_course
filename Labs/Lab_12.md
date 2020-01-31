# Lab 12 - Covert Malware Launching

## Lab 12-1

Analyze the malware found in the file Lab12-01.exe and Lab12-01.dll. Make sure that these files are in the same directory when performing the analysis.

**1. What happens when you run the malware executable?**

Before running the sample, we are going to set up _Process Monitor_ so as to capture all traces of the malware execution, to do so, we create a new filter in which the process name will have to be the name of the malware.

![_Process Monitor_ adding filter 1](../Pictures/Lab_12/lab_12-01_1_process_monitor_1.png)

Now, we apply the changes and we are ready to run the sample.

When we run the sample, a pop up that says "Press OK to reboot" appears, this pop up will appears every minute or so, but adding one to X at the title of the window "Practical Malware Analysis X".

![Malware execution](../Pictures/Lab_12/lab_12-01_1_1.png)

This behaviour is quite anoying, so we save the _Process Monitor_ log file, reboot the machine and revert the snapshot.

Now, we can analyze the file.

![_Process Monitor_ malware execution](../Pictures/Lab_12/lab_12-01_1_process_monitor_2.png)

Mmmmm... It seems that _Process Monitor_ does not capture all the execution with this filter. So we add another filter, in this case if the name of the _DLL_ appears in the path column (notice we have disabled the other filter).

![_Process Monitor_ adding filter 2](../Pictures/Lab_12/lab_12-01_1_process_monitor_3.png)

Now, we can see that the malicious _DLL_ has been loaded by...

![_Process Monitor_ malware execution](../Pictures/Lab_12/lab_12-01_1_process_monitor_4.png)

_Explorer.exe_!!! This is clearly an indicator of the usage of a process injection technique!

**2. What process is being injected?**

As we have previously seen in the first exercise, the targeted process seems to be _explorer.exe_, but let's analyze the malware in _IDA Pro_ so as to verify it.

At the beginning of the executable we can see how it loads _EnumProcessModules_, _GetModuleBaseNameA_ and _EnumProcesses_, which are necessary to list processes.

![_IDA Pro_ load functions](../Pictures/Lab_12/lab_12-01_2_ida_pro_1.png)

After that, it calls the previously loaded _EnumProcesses_ function, which returns an array of the _PIDs_ of the processes of the system that we have called _processesPIDs_.

![_IDA Pro_ _EnumProcesses_ call](../Pictures/Lab_12/lab_12-01_2_ida_pro_2.png)

Then, this array is iterated so as to find the PID of _explorer.exe_. Here, we can see where this check is done, in a function we have called _checkExplorerPID_ (_0x00401000_).

![_IDA Pro_ _checkExplorerPID_ call](../Pictures/Lab_12/lab_12-01_2_ida_pro_3.png)

In this function we can see how the malware makes this check.

![_IDA Pro_ checking of _explorer.exe_ PID](../Pictures/Lab_12/lab_12-01_2_ida_pro_4.png)

After that, we can see how the malware performs the process injection using the _WINAPI_ functions _VirtualAllocEx_ to allocate memory in the remote process, _WriteProcessMemory_ to write the malicious _DLL_ into the process address space and _CreateRemoteThread_ to call _LoadLibraryA_ from the remote process to load the malicious _DLL_.

![_IDA Pro_ process injection](../Pictures/Lab_12/lab_12-01_2_ida_pro_5.png)

**3. How can you make the malware stop the pop-ups?**

**4. How does this malware operate?**

## Lab 12-2

Analyze the malware found in the file Lab12-02.exe.

**1. What is the purpose of this program?**

**2. How does the launcher program hide execution?**

**3. Where is the malicious payload stored?**

**4. How is the malicious payload protected?**

**5. How are strings protected?**

## Lab 12-3

Analyze the malware extracted during the analysis of Lab 12-2, or use the file Lab12-03.exe.

**1. What is the purpose of this malicious payload?**

**2. How does the malicious payload inject itself?**

**3. What filesystem residue does this program create?**

## Lab 12-4

Analyze the malware found in the file Lab12-04.exe.

**1. What does the code at 0x401000 accomplish?**

**2. Which process has code injected?**

**3. What DLL is loaded using LoadLibraryA?**

**4. What is the fourth argument passed to the CreateRemoteThread call?**

**5. What malware is dropped by the main executable?**

**6. What is the purpose of this and the dropped malware?**
