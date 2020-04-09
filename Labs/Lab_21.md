# Lab 21 - 64-Bit Malware

You’ll need a 64-bit computer and a 64-bit virtual machine in order to run the malware for these labs, as well as the advanced version of IDA Pro in order to analyze the malware.

## Lab 21-1

Analyze the code in Lab21-01.exe. This lab is similar to Lab 9-2, but tweaked and compiled for a 64-bit system.

**1. What happens when you run this program without any parameters?**

Our lab machine is a _x86 Windows XP_, so we cannot execute the sample. However, we can analyze it by means of _IDA Pro_ and see what would happen.

In the _main_ function we can see the following piece of code at the beginning.

![_IDA Pro_ _main_ beginning](../Pictures/Lab_21/lab_21-01_1_ida_pro_1.png)

As we can see, some unknown data is included in an array called _encoded_data_, since we cannot determine its content. Also, we see the string "1qaz2wsx3edc" that is included in a string tht we have called _key_, since we already have "encoded" content. Then, it gets the filename "ocl.exe" (_expected_filename_) and the full path of the binary via _GetModuleFileNameA_, from which extracts the filename by means of _strrchr_.

Then, the binary will perform some modifications on the _expected_filename_ string as follows.

![_IDA Pro_ _main_ _expected_filename_ modifications](../Pictures/Lab_21/lab_21-01_1_ida_pro_2.png)

Let's analyze what this piece of code does:

```
.text:00000001400011B0 loc_1400011B0:
.text:00000001400011B0                 movzx   ecx, byte ptr [rbp+rdi+260h+expected_filename]		-> ECX = expected_filename[RDI] (RDI works as counter)
.text:00000001400011B8                 mov     eax, 4EC4EC4Fh			-> EAX = 0x4EC4EC4F
.text:00000001400011BD                 sub     cl, 61h ; 'a'			-> CL = CL - 0x61 = expected_filename[RDI] - 0x61
.text:00000001400011C0                 movsx   ecx, cl				-> ECX = expected_filename[RDI] - 0x61
.text:00000001400011C3                 imul    ecx, ecx				-> ECX = ECX * ECX
.text:00000001400011C6                 sub     ecx, 5				-> ECX = ECX - 0x5
.text:00000001400011C9                 imul    ecx				-> EDX|EAX = ECX * EAX = ECX * 0x4EC4EC4F
.text:00000001400011CB                 sar     edx, 3				-> EDX = EDX >> 3 (EDX = 0x5C in the first iteration)
.text:00000001400011CE                 mov     eax, edx				-> EAX = EDX
.text:00000001400011D0                 shr     eax, 1Fh				-> EAX = EAX >> 0x1F = EDX >> 0x1F
.text:00000001400011D3                 add     edx, eax				-> EDX = EDX + EAX = EDX + (EDX >> 0x1F)
.text:00000001400011D5                 imul    edx, 1Ah				-> EDX = EDX * 0x1A = (EDX + (EDX >> 0x1F)) * 0x1A
.text:00000001400011D8                 sub     ecx, edx				-> ECX = ECX - EDX
.text:00000001400011DA                 test    cl, cl				-> CL == 0 ? -> if CL < 0 -> SF = 1
.text:00000001400011DC                 jns     short loc_1400011E1			-> JUMP to loc_1400011E1 if not sign (SF)
.text:00000001400011DE                 add     cl, 1Ah				-> ECX = ECX + 0x1A
.text:00000001400011E1
.text:00000001400011E1 loc_1400011E1:
.text:00000001400011E1                 add     cl, 61h ; 'a'		-> ECX = ECX + 0x61
.text:00000001400011E4                 inc     rdi				-> RDI = RDI + 1 (counter incremented)
.text:00000001400011E7                 mov     [rbp+rdi+260h+var_181], cl		-> VAR_181 + RDI = expected_filename[RDI - 1] = CL
.text:00000001400011EE                 cmp     rdi, 3				-> RDI == 3
.text:00000001400011F2                 jl      short loc_1400011B0		-> If the counter is less than 3, it will jump to loc_1400011B0
```

So now we can translate this piece of code to a _Python_ script.

```
MAX_VALUE_1 = 0xFF
MAX_VALUE_2 = 0xFFFFFFFF

def sar_32(byte, width):
	sign = byte & 0x80000000
	byte &= 0x7FFFFFFF
	byte >>= width
	byte |= sign
	return byte

def decode_filename(filename):
	name = ""
	extension = filename[3:]

	for counter in range(3):
		character = ord(filename[counter])
		constant = 0x4EC4EC4F

		character = (character & MAX_VALUE_1) - 0x61
		character = (character * character) & MAX_VALUE_2
		character = character - 0x5
		value = ((character * constant) & 0xFFFFFFFF00000000) >> 0x20

		value = sar_32(value, 3)
		aux_value = (value >> 0x1F) & MAX_VALUE_2
		value = (value + aux_value) & MAX_VALUE_2
		value = (value * 0x1A) & MAX_VALUE_2
		character = character - value 

		if character < 0:
			character = (character & MAX_VALUE_1) + 0x1A
		character = (character & MAX_VALUE_1) + 0x61

		name = name + chr(character)

	expected_filename = name + extension
	return expected_filename

filename = "ocl.exe"
expected_filename = decode_filename(filename)

print("The expected filename is: " + expected_filename)
```

When we execute the script, we obtain the following result:

```
$ python3 Scripts/Labs/Lab_21/lab21_01_filename_decoding.py

The expected filename is: jzm.exe
```

Then, the sample will do a comparison between the decoded string and the filename of the binary (it removes the slash from the filename stored in _R11_), if they are different, it will terminate the execution.

![_IDA Pro_ _main_ _expected_filename_ comparison](../Pictures/Lab_21/lab_21-01_1_ida_pro_3.png)

So, if we execute this sample as it is, it will exit, since it has a different name from "jzm.exe".

**2. Depending on your version of IDA Pro, main may not be recognized automatically. How can you identify the call to the main function?**

If _IDA_ did not recognize the _main_ function, we can identify it as following:

- The _main_ function is executed after calling the _GetCommandLineA_ routine.
- The _main_ function receives 3 arguments (1 integer and 2 pointers): _argc_, _argv_ and _envp_.

**3. What is being stored on the stack in the instructions from 0x0000000140001150 to 0x0000000140001161?**

At this position, we have seen that the _ocl.exe_ is stored in the stack.

**4. How can you get this program to run its payload without changing the filename of the executable?**

We can modify the instruction at _0x000000014000120A_ `test eax, eax` with the instruction `xor eax, eax`, this will always result in executing the main payload. To do so, we put the cursor on the instruction and execute "Edit -> Patch program -> Assemble", then we change the original instruction for the one we have chosen.

![_IDA Pro_ path binary 1](../Pictures/Lab_21/lab_21-01_4_ida_pro_1.png)

![_IDA Pro_ path binary 2](../Pictures/Lab_21/lab_21-01_4_ida_pro_2.png)

![_IDA Pro_ path binary 3](../Pictures/Lab_21/lab_21-01_4_ida_pro_3.png)

![_IDA Pro_ path binary 4](../Pictures/Lab_21/lab_21-01_4_ida_pro_4.png)

![_IDA Pro_ path binary 5](../Pictures/Lab_21/lab_21-01_4_ida_pro_5.png)

**5. Which two strings are being compared by the call to strncmp at 0x0000000140001205?**

Explained in the exercise 1.

**6. Does the function at 0x00000001400013C8 take any parameters?**

It receives one parameter via the _RCX_ register. This parameter is a socket previously created in the _WSASocketA_ function call.

![_IDA Pro_ _WSASocketA_ socket creation](../Pictures/Lab_21/lab_21-01_6_ida_pro_1.png)

![_IDA Pro_ socket passed as parameter](../Pictures/Lab_21/lab_21-01_6_ida_pro_2.png)

This parameter is used by the function at _0x0000000140001000_ to attach the socket to _stdin_, _stdout_ and _stderror_ of the process to create, in this case "cmd", this will allow to create a reverse shell. This function is renamed to _create_reverse_shell_.

![_IDA Pro_ _create_reverse_shell_](../Pictures/Lab_21/lab_21-01_6_ida_pro_3.png)

**7. How many arguments are passed to the call to CreateProcess at 0x0000000140001093? How do you know?**

## Lab 21-2

Analyze the malware found in Lab21-02.exe on both x86 and x64 virtual machines. This malware is similar to Lab12-01.exe, with an added x64 component.

**1. What is interesting about the malware’s resource sections?**

**2. Is this malware compiled for x64 or x86?**

**3. How does the malware determine the type of environment in which it is running?**

**4. What does this malware do differently in an x64 environment versus an x86 environment?**

**5. Which files does the malware drop when running on an x86 machine? Where would you find the file or files?**

**6. Which files does the malware drop when running on an x64 machine? Where would you find the file or files?**

**7. What type of process does the malware launch when run on an x64 system?**

**8. What does the malware do?**