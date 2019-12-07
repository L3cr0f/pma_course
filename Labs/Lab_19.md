# Lab 19 - Shellcode Analysis

In these labs, we’ll use what we’ve covered in Chapter 19 to analyze samples inspired by real shellcode. Because a debugger cannot easily load and run shellcode directly, we’ll use a utility called shellcode_launcher.exe to dynamically analyze shellcode binaries. You’ll find instructions on how to use this utility in Chapter 19 and in the detailed analyses in Appendix C.

## Lab 19-1

Analyze the file Lab19-01.bin using shellcode_launcher.exe.

**Questions**

1. How is the shellcode encoded?
2. Which functions does the shellcode manually import?
3. What network host does the shellcode communicate with?
4. What filesystem residue does the shellcode leave?
5. What does the shellcode do?

## Lab 19-2

The file Lab19-02.exe contains a piece of shellcode that will be injected into another process and run. Analyze this file.

**Questions**

1. What process is injected with the shellcode?
2. Where is the shellcode located?
3. How is the shellcode encoded?
4. Which functions does the shellcode manually import?
5. What network hosts does the shellcode communicate with?
6. What does the shellcode do?

## Lab 19-3

Analyze the file Lab19-03.pdf. If you get stuck and can’t find the shellcode, just skip that part of the lab and analyze file Lab19-03_sc.bin using shellcode_launcher.exe.

**Questions**

1. What exploit is used in this PDF?
2. How is the shellcode encoded?
3. Which functions does the shellcode manually import?
4. What filesystem residue does the shellcode leave?
5. What does the shellcode do?