# Lab 16 - Anti-Debugging

## Lab 16-1

Analyze the malware found in Lab16-01.exe using a debugger. This is the same malware as Lab09-01.exe, with added anti-debugging techniques.

**1. Which anti-debugging techniques does this malware employ?**

The first thing we do is loading the binary in _IDA Pro_ and execute the script _ida_highlight.py_ to see if there is any _anti-debugging_ technique within the code.

```
Number of potential Anti-Debugging instructions: 0
```

Mmmm... Any anti-debugging technique has been detected, we have to check them manually.

The first anti-debugging technique we see is the one in which the malware checks the _BeingDebugged_ flag of the _PEB_. This is done by checking the second byte of the _PEB_ struct, which is accessed via instruction _fs:30h_.

![_IDA Pro_ _BeingDebugged_ flag of _PEB_](../Pictures/Lab_17/lab_16-01_1_ida_pro_1.png)

After that, the malware also checks the _ProcessHeap_ (_PEB_ + _0x18_) _ForceFlags_ (_ProcessHeap_ + _0x10_ -_Windows XP_-) value of the _PEB_, since this field is used to tell the kernel if the heap was created within a debugger.

![_IDA Pro_ _ProcessHeap_ flag of _PEB_](../Pictures/Lab_17/lab_16-01_1_ida_pro_2.png)

Then, the malware will check the field _0x68_ of the _PEB_, which points to the _NTGlobalFlag_. If this value of this flag is equal to _0x70_, the process will be running in a debugger.

![_IDA Pro_ _NTGlobalFlag_ flag of _PEB_](../Pictures/Lab_17/lab_16-01_1_ida_pro_3.png)

These techniques are used in many different locations within the code, so as to hindering the debugging process.

**2. What happens when each anti-debugging technique succeeds?**

When an anti-debugging technique succeeds, the malware auto-removes itself.

![_IDA Pro_ auto-removing](../Pictures/Lab_17/lab_16-01_2_ida_pro_1.png)

**3. How can you get around these anti-debugging techniques?**

Since the malware checks several times if the process is being debugged, it is easier for us to change the queried values of the _PEB_.

To do so, we set a breakpoint at _0x0040355A_, after the _PEB_ struct address was loaded in _EAX_. Then, we go to the _PEB_ struct address (stored in _EAX_) in the hexadecimal memory dump container and start modifying the values by means of _CTRL+E_ or _right-click -> Binary -> Edit_.

![_IDA Pro_ _PEB_ in memory](../Pictures/Lab_17/lab_16-01_3_immunity_1.png)

In the case of _ProcessHeap_, we go to the address _0x00140000_ and select the offset _+0x10_, which points to _ForceFlags_ value that has a value of _0x40000060_ in this case.

![_IDA Pro_ _ProcessHeap_ in memory](../Pictures/Lab_17/lab_16-01_3_immunity_2.png)

So, we modify _BeingDebugged_ to _0x0_, _ForceFlags_ to _0x00000000_ and _NTGlobalFlag_ to any other value than _0x0070_, _0x0000_ in our case.

After that, we can check how the malware executes as expected.

**4. How do you manually change the structures checked during runtime?**

Explained in the previous exercise.

**5. Which OllyDbg plug-in will protect you from the anti-debugging techniques used by this malware?**

We can execute the following command in _Immunity_ so as to prevent the _PEB_ anti-debugging techniques the malware applies:

```
!hidedebug peb
```

## Lab 16-2

Analyze the malware found in Lab16-02.exe using a debugger. The goal of this lab is to figure out the correct password. The malware does not drop a malicious payload.

**1. What happens when you run Lab16-02.exe from the command line?**

**2. What happens when you run Lab16-02.exe and guess the command-line parameter?**

**3. What is the command-line password?**

**4. Load Lab16-02.exe into IDA Pro. Where in the main function is strncmp found?**

**5. What happens when you load this malware into OllyDbg using the default settings?**

**6. What is unique about the PE structure of Lab16-02.exe?**

**7. Where is the callback located? (Hint: Use CTRL-E in IDA Pro.)**

**8. Which anti-debugging technique is the program using to terminate immediately in the debugger and how can you avoid this check?**

**9. What is the command-line password you see in the debugger after you disable the anti-debugging technique?**

**10. Does the password found in the debugger work on the command line?**

**11. Which anti-debugging techniques account for the different passwords in the debugger and on the command line, and how can you protect against them?**

## Lab 16-3

Analyze the malware in Lab16-03.exe using a debugger. This malware is similar to Lab09-02.exe, with certain modifications, including the introduction of anti-debugging techniques. If you get stuck, see Lab 9-2.

**1. Which strings do you see when using static analysis on the binary?**

**2. What happens when you run this binary?**

**3. How must you rename the sample in order for it to run properly?**

**4. Which anti-debugging techniques does this malware employ?**

**5. For each technique, what does the malware do if it determines it is running in a debugger?**

**6. Why are the anti-debugging techniques successful in this malware?**

**7. What domain name does this malware use?**
