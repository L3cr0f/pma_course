# Lab 7 - Analyzing Malicious Windows Programs

## Lab 7-1

Analyze the malware found in the file Lab07-01.exe.

**1. How does this program ensure that it continues running (achieves persistence) when the computer is restarted?**

The malware creates a new service called _Malservice_ by means of the API call _CreateServiceA_ using the value 0x2 for the _dwStartType_ parameter, which means that the service will start at system startup.

**2. Why does this program use a mutex?**

The malware creates one mutex with the value _HGL345_ so as to check if there is already a malware instance running on the computer.

**3. What is a good host-based signature to use for detecting this program?**

The malware mutex name _HGL345_ is the best host-based IOC, but also the name of the service, _Malservice_.

**4. What is a good network-based signature for detecting this malware?**

We can find one network-based IOC like the URL used by this malware: _http://www.malwareanalysisbook.com/_.

**5. What is the purpose of this program?**

The malware first check if there is already a mutex called _HGL345_, if not, then it creates a service called _Malservice_ that allows this malware to start at system startup. Then, when the malware is running, it will wait until 1st of January of 2100.

![_IDA Pro_ wait until year 2100](../Pictures/Lab_07/lab_07-01_5_ida_pro_1.png)

After that, the malware create 20 new threads that will make unlimited requests to the URL _http://www.malwareanalysisbook.com/_. This makes us believe that the main purpose of the malware is making DoS attacks against that domain.

![_IDA Pro_ _CreateThread_ 20 times](../Pictures/Lab_07/lab_07-01_5_ida_pro_2.png)

![_IDA Pro_ send DoS attack](../Pictures/Lab_07/lab_07-01_5_ida_pro_3.png)

**6. When will this program finish executing?**

The malware never terminates if the computer is running, since the main thread will sleep forever.

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

