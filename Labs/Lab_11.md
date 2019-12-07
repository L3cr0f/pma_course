# Lab 11 - Malware Behaviour

## Lab 11-1

Analyze the malware found in Lab11-01.exe.

**Questions**

1. What does the malware drop to disk?
2. How does the malware achieve persistence?
3. How does the malware steal user credentials?
4. What does the malware do with stolen credentials?
5. How can you use this malware to get user credentials from your test environment?

# Lab 11-2

Analyze the malware found in Lab11-02.dll. Assume that a suspicious file named Lab11-02.ini was also found with this malware.

**Questions**

1. What are the exports for this DLL malware?
2. What happens after you attempt to install this malware using rundll32.exe?
3. Where must Lab11-02.ini reside in order for the malware to install properly?
4. How is this malware installed for persistence?
5. What user-space rootkit technique does this malware employ?
6. What does the hooking code do?
7. Which process(es) does this malware attack and why?
8. What is the significance of the .ini file?
9. How can you dynamically capture this malware’s activity with Wireshark?

## Lab 11-3

Analyze the malware found in Lab11-03.exe and Lab11-03.dll. Make sure that both files are in the same directory during analysis.

**Questions**

1. What interesting analysis leads can you discover using basic static analysis?
2. What happens when you run this malware?
3. How does Lab11-03.exe persistently install Lab11-03.dll ?
4. Which Windows system file does the malware infect?
5. What does Lab11-03.dll do?
6. Where does the malware store the data it collects?