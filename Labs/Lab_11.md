# Lab 11 - Malware Behaviour

## Lab 11-1

Analyze the malware found in Lab11-01.exe.

**1. What does the malware drop to disk?**

To do so we are going to use different tools such as _Resource Hacker_ or _IDA Pro_.

Te first thing we do is using _Resource Hacker_ so as to check if the malware contains any other binary in it.

![_Resource Hacker_ check inserted binary](../Pictures/Lab_10/lab_10-01_1_resource_hacker_1.png)

As we can see, there is some binary inserted in the malware called _TGAD_. Also, it is something we can check in _IDA Pro_ at function that we have called _loadAndDropResource_ at address _0x00401080_.

![_IDA Pro_ load resource 1](../Pictures/Lab_10/lab_10-01_1_ida_pro_1.png)

![_IDA Pro_ load resource 2](../Pictures/Lab_10/lab_10-01_1_ida_pro_2.png)

Also, this binary seems to be dropped to the filesystem as a _DLL_ called _msgina32.dll_ as we can check in the same routine in _IDA Pro_.

![_IDA Pro_ drop resource](../Pictures/Lab_10/lab_10-01_1_ida_pro_3.png)

We will need to research deeper in order to know what this module does.

**2. How does the malware achieve persistence?**

The malware creates a registry key called _GinaDLL_ within "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" with the value "\msgina32.dll" at function we have called _persistenceSetup_ at address _0x00401000_.

![_IDA Pro_ load resource 1](../Pictures/Lab_10/lab_10-01_2_ida_pro_1.png)

**3. How does the malware steal user credentials?**

To know how the malware does, first, we need to extract the _DLL_ that is stored in it. To do so we use _Resource Hacker_ and the option _Save as..._ when you right-click on the stored binary. Now, we can analyze the _DLL_ in _IDA Pro_.

At first sight, we can see a lot of different exports in the binary. Nevertheless, most of them, the _gina_x_ are the same, they just prints out the result of the _WINAPI_ function _GetProcAddress_ using the number _x_ as parameter. Also, the rest of the exports are pretty much the same but _WlxLoggedOutSAS_, _DLLRegister_ and _DLLUnregister_.

The _DLLRegister_ and _DLLUnregister_ are methods so as to enable or disable the persistence mechanism. However, the function _WlxLoggedOutSAS_ allows the malware to steal the credentials of the user by means of a program called _msutil32.sys_.

**4. What does the malware do with stolen credentials?**

**5. How can you use this malware to get user credentials from your test environment?**

# Lab 11-2

Analyze the malware found in Lab11-02.dll. Assume that a suspicious file named Lab11-02.ini was also found with this malware.

**1. What are the exports for this DLL malware?**

**2. What happens after you attempt to install this malware using rundll32.exe?**

**3. Where must Lab11-02.ini reside in order for the malware to install properly?**

**4. How is this malware installed for persistence?**

**5. What user-space rootkit technique does this malware employ?**

**6. What does the hooking code do?**

**7. Which process(es) does this malware attack and why?**

**8. What is the significance of the .ini file?**

**9. How can you dynamically capture this malware’s activity with Wireshark?**

## Lab 11-3

Analyze the malware found in Lab11-03.exe and Lab11-03.dll. Make sure that both files are in the same directory during analysis.

**1. What interesting analysis leads can you discover using basic static analysis?**

**2. What happens when you run this malware?**

**3. How does Lab11-03.exe persistently install Lab11-03.dll ?**

**4. Which Windows system file does the malware infect?**

**5. What does Lab11-03.dll do?**

**6. Where does the malware store the data it collects?**
