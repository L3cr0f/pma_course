# Lab 16 - Anti-Debugging

## Lab 16-1

Analyze the malware found in Lab16-01.exe using a debugger. This is the same malware as Lab09-01.exe, with added anti-debugging techniques.

**1. Which anti-debugging techniques does this malware employ?**
**2. What happens when each anti-debugging technique succeeds?**
**3. How can you get around these anti-debugging techniques?**
**4. How do you manually change the structures checked during runtime?**
**5. Which OllyDbg plug-in will protect you from the anti-debugging techniques used by this malware?**

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