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
00401010 E8 8B 45 0C 8B                       call    near ptr 8B4C55A0h		-> The jump will go to loc_401011, not to 00401010
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

To print "Good Job!" we need to introduce the key "pdq" as argument as we can see in the disassembled code.

![_IDA Pro_ analized code](../Pictures/Lab_15/lab_15-01_4_ida_pro_1.png)

To verify this key, we execute the program as follows:

![_IDA Pro_ "Good Job!" printed](../Pictures/Lab_15/lab_15-01_4_ida_pro_2.png)

## Lab 15-2

Analyze the malware found in the file Lab15-02.exe. Correct all anti-disassembly countermeasures before analyzing the binary in order to answer the questions.

**1. What URL is initially requested by the program?**

If we take a look at the strings, we do not see any _URL_ or _IP_ address.

```
...
not enough name
internet unable
Bamboo::
```

This possibly means that the _URL_ is obfuscated or disguised within the code.

When we start _IDA Pro_ we can see that the binary cannot be showed by means of graphical view, meaning that some kind of anti-disassembly method has been applied.

Firts, if we take a look to the _main_ function, we can see some callings to _WINAPI_ functions.

![_IDA Pro_ _Internet_ functions](../Pictures/Lab_15/lab_15-02_1_ida_pro_1.png)

However, as we move forward into the code, que starting to see some things that must be fixed to understand the code in a better way.

If we scroll down the _IDA View_ panel we will find the following piece of data that draw our attention:

![_IDA Pro_ code fixing 1](../Pictures/Lab_15/lab_15-02_1_ida_pro_2.png)

As we can see, there are one _jmp_ instruction that has no sense. Also, the previous jump points out to the nonsensical _jmp_ plus 1 byte.

```
.text:0040115C 75 01                                jnz     short near ptr loc_40115E+1
.text:0040115E
.text:0040115E                      loc_40115E:
.text:0040115E E9 6A 00 6A 00                       jmp     near ptr 0AA11CDh
```

So the expected opcode instruction would be "6A 00 6A 00" instead of "E9".

To fix this code we click on "D" key to convert to data and then "C" on to convert the bytes we want to code. This will result in the following piece of code:

![_IDA Pro_ code fixing 2](../Pictures/Lab_15/lab_15-02_1_ida_pro_3.png)

We also see the following block of code being mislabeled.

![_IDA Pro_ code fixing 3](../Pictures/Lab_15/lab_15-02_1_ida_pro_4.png)

So, for the first highlighted piece of code, we follow the previous approach to fix it, resulting in:

![_IDA Pro_ code fixing 4](../Pictures/Lab_15/lab_15-02_1_ida_pro_5.png)

In the case of the second highlighted code, we must follow other approach, since the instruction:

```
.text:00401215 EB FF                                jmp     short near ptr loc_401215+1
```

Will jump to itself plus one. So we need to convert to data and then to code, but also stating that the sample took a jump here.

![_IDA Pro_ code fixing 5](../Pictures/Lab_15/lab_15-02_1_ida_pro_6.png)

After that, we see another disassembly technique that derives in the previously mentioned _jmp address+1_ technique:

![_IDA Pro_ code fixing 6](../Pictures/Lab_15/lab_15-02_1_ida_pro_7.png)

In this case, we have two consecutive conditional jumps that together form an unconditional jump. After fixing the code we will see the following:

![_IDA Pro_ code fixing 7](../Pictures/Lab_15/lab_15-02_1_ida_pro_8.png)

Then, another disassembly trick is shown us as follows:

![_IDA Pro_ code fixing 8](../Pictures/Lab_15/lab_15-02_1_ida_pro_9.png)

We have another jump in the middle instruction, as previously did, we are going to fix the code, referencing that previously this piece of code was executed:

```
mov     ax, 5EBh
xor     eax, eax
jz      short near ptr loc_4012E6+2
```

![_IDA Pro_ code fixing 9](../Pictures/Lab_15/lab_15-02_1_ida_pro_10.png)

Let's stop here and see what _URL_ the malware uses, to do so, we need to go back where the function _InternetOpenUrlA_ is called.

![_IDA Pro_ _InternetOpenUrlA_ call](../Pictures/Lab_15/lab_15-02_1_ida_pro_11.png)

As we can see, the function _sub_401386_ is called before calling _InternetOpenUrlA_. If go to that function, we will see the following:

![_IDA Pro_ _get_URL_ function 1](../Pictures/Lab_15/lab_15-02_1_ida_pro_12.png)

![_IDA Pro_ _get_URL_ function 2](../Pictures/Lab_15/lab_15-02_1_ida_pro_13.png)

As we can see, the function will copy the URL _http://www.practicalmalwareanalysis.com/bamboo.html_ to the return value, so we can rename this function to _get_URL_.

**2. How is the User-Agent generated?**

The _User-Agent_ is set up by the malware when it calls to the _InternetOpenA_ _WINAPI_ function.

![_IDA Pro_ _InternetOpenA_ _User-Agent_ argument](../Pictures/Lab_15/lab_15-02_2_ida_pro_1.png)

As we can see, the _User-Agent_ is introduced as argument by means of the variable _EBP-100h_, so if we look for this variable, we will find where the malware set up the _User-Agent_.

If we go back in the sample, we see how at the beginning, the malware set up the _User-Agent_ by means of _gethostname_.

![_IDA Pro_ _gethostname_ set _User-Agent_ variable](../Pictures/Lab_15/lab_15-02_2_ida_pro_2.png)

**3. What does the program look for in the page it initially requests?**

Once the malware has performed the _HTTP_ request, it will read the file by means of _InternetReadFile_ and then it will look for the string "Bamboo::" and then it will search for the first occurrence of "::".

![_IDA Pro_ look for "Bamboo::"](../Pictures/Lab_15/lab_15-02_3_ida_pro_1.png)

**4. What does the program do with the information it extracts from the page?**

After extracting the interesting information, the malware will call the function _sub_40130F_, which will get the string "Accounts.Summary.xls.exe".

![_IDA Pro_ get "Accounts.Summary.xls.exe"](../Pictures/Lab_15/lab_15-02_4_ida_pro_1.png)

So we can rename this function to _get_backdoor_name_.

Then, the malware will make another requests to the known _URL_ using the extracted information as header.

![_IDA Pro_ second _HTTP_ request](../Pictures/Lab_15/lab_15-02_4_ida_pro_2.png)

Then, with the retrieved information, it will dump it into the file "Accounts.Summary.xls.exe".

![_IDA Pro_ write backdoor into disk](../Pictures/Lab_15/lab_15-02_4_ida_pro_3.png)


TODO -> REVISAR EJERCICIOS 2 Y 4

## Lab 15-3

Analyze the malware found in the file Lab15-03.exe. At first glance, this binary appears to be a legitimate tool, but it actually contains more functionality than advertised.

**1. How is the malicious code initially called?**

**2. What does the malicious code do?**

**3. What URL does the malware use?**

**4. What filename does the malware use?**
