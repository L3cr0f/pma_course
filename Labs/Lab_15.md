# Lab 15 - Anti-Disassembly

## Lab 15-1

Analyze the sample found in the file Lab15-01.exe. This is a command-line program that takes an argument and prints “Good Job!” if the argument matches a secret code.

**1. What anti-disassembly technique is used in this binary?**

When we load the bianry in _IDA Pro_ we notice how _IDA_ cannot show us the graphic version, telling us that there is something strange within the code, let's dig into it.

To analyze the code better, we are going to set up _IDA Pro_ in order to show the _opcodes_ of each operation, this can be configured in "Options -> General -> Number of opcode bytes" and setting 7 bytes. This will be displayed as follows:

![_IDA Pro_ opcodes](../Pictures/Lab_15/lab_15-01_1_ida_pro_1.png)

Now, we can start analyzing the sample. As we can see in the following output, there are several _call_ instructions that their targets are nonsensical. Also, before every _call_ instruction, there is _jz_ (jump if zero) instruction which is always true, since before every _jz_ instruction, there is a _xor eax, eax_ instruction, which will always set the _ZERO FLAG_ to _true_.

![_IDA Pro_ nonsensical _call_ instructions](../Pictures/Lab_15/lab_15-01_1_ida_pro_2.png)

We have to notice that the _jump_ instructions, jumps to the _call_ instructions plus one byte. We are going to explain with the following example:

```
0040100C 33 C0                                xor     eax, eax
0040100E 74 01                                jz      short near ptr loc_401010+1	-> Jumps to the address of the call instruction plus 1

                      loc_401010:
00401010 E8 8B 45 0C 8B                       call    near ptr 8B4C55A0h			-> The jump will go to loc_401011, not to 00401010
```

This means that the _jump_ instruction will go to the opcode _8B 45 0C 8B_, and not to _E8 8B 45 0C 8B_. This means, that the malware will execute other instruction than _call_, to be precise, it will execute:

```
8B 45 0C mov    eax, DWORD PTR [ebp+0Ch]
```

Let's repair this piece of code in _IDA Pro_, to do so, we click on key 'D' to convert the instruction in _data_ and then, we select the bytes we want to convert back to code and click on key 'C'.

![_IDA Pro_ partially fixed code](../Pictures/Lab_15/lab_15-01_1_ida_pro_3.png)

We repeat all necessary times so as to fully fix the code.

![_IDA Pro_ fully fixed code](../Pictures/Lab_15/lab_15-01_1_ida_pro_4.png)


**2. What rogue opcode is the disassembly tricked into disassembling?**

As mentioned in the first exercise, the malware use the _call_ instruction opcode (_0xE8_) to trick the disassembler.

**3. How many times is this technique used?**

The malware use this technique a total of 5 times! Innitially, we thought there were only 4, but one of the tricks was hidden in the instructions and only could be discovered when we started fixing the code.

**4. What command-line argument will cause the program to print “Good Job!”?**

To print "Good Job!" we need to insert the letter "d" as argument.

## Lab 15-2

Analyze the malware found in the file Lab15-02.exe. Correct all anti-disassembly countermeasures before analyzing the binary in order to answer the questions.

**1. What URL is initially requested by the program?**
**2. How is the User-Agent generated?**
**3. What does the program look for in the page it initially requests?**
**4. What does the program do with the information it extracts from the page?**

## Lab 15-3

Analyze the malware found in the file Lab15-03.exe. At first glance, this binary appears to be a legitimate tool, but it actually contains more functionality than advertised.

**1. How is the malicious code initially called?**
**2. What does the malicious code do?**
**3. What URL does the malware use?**
**4. What filename does the malware use?**