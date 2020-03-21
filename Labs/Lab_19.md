# Lab 19 - Shellcode Analysis

In these labs, we’ll use what we’ve covered in Chapter 19 to analyze samples inspired by real shellcode. Because a debugger cannot easily load and run shellcode directly, we’ll use a utility called shellcode_launcher.exe to dynamically analyze shellcode binaries. You’ll find instructions on how to use this utility in Chapter 19 and in the detailed analyses in Appendix C.

## Lab 19-1

Analyze the file Lab19-01.bin using shellcode_launcher.exe.

**1. How is the shellcode encoded?**

First we load the binary into _IDA Pro_ to see what it hides.

```
seg000:00000000                 inc     ecx
					...
seg000:000001FE                 inc     ecx
seg000:000001FF                 inc     ecx
seg000:00000200                 xor     ecx, ecx
seg000:00000202                 mov     cx, 18Dh			-> ECX = 8Dh
seg000:00000206                 jmp     short loc_21F
seg000:00000208
seg000:00000208 ; =============== S U B R O U T I N E =======================================
seg000:00000208
seg000:00000208
seg000:00000208 sub_208         proc near               ; CODE XREF: seg000:loc_21F↓p
seg000:00000208                 pop     esi
seg000:00000209                 push    esi
seg000:0000020A                 mov     edi, esi
seg000:0000020C
seg000:0000020C loc_20C:                                ; CODE XREF: sub_208+14↓j
seg000:0000020C                 lodsb
seg000:0000020D                 mov     dl, al
seg000:0000020F                 sub     dl, 41h ; 'A'
seg000:00000212                 shl     dl, 4
seg000:00000215                 lodsb
seg000:00000216                 sub     al, 41h ; 'A'
seg000:00000218                 add     al, dl
seg000:0000021A                 stosb
seg000:0000021B                 dec     ecx
seg000:0000021C                 jnz     short loc_20C
seg000:0000021E                 retn
seg000:0000021E sub_208         endp
seg000:0000021E
seg000:0000021F ; ---------------------------------------------------------------------------
seg000:0000021F
seg000:0000021F loc_21F:                                ; CODE XREF: seg000:00000206↑j
seg000:0000021F                 call    sub_208
seg000:00000224                 dec     ecx
```

As we can see, first we have a block of _0x200_ bytes of _inc ecx_ instructions, something that is useless since at _0x00000200_ the binary executes a _xor ecx, ecx_ instruction. So we can conclude that this block of code is just a _NOP sled_ but without using the _0x90_ opcode.

Then, the binary adds the value _0x8D_ to _ECX_ and jumps to the instruction located at _0x0000021F_, which will call to the function at _0x00000208_.

![_IDA Pro_ main function](../Pictures/Lab_19/lab_19-01_1_ida_pro_1.png)

This function is a loop that will execute the following instructions:

```
lodsb					-> AL = [SI] (ESI + 1)
mov     dl, al			-> DL = AL
sub     dl, 41h ; 'A'	-> DL = DL - 0x41
shl     dl, 4			-> DL = DL << 4
lodsb					-> AL = [SI] (ESI + 1)
sub     al, 41h ; 'A'	-> AL = AL - 0x41
add     al, dl			-> AL = AL + DL
stosb					-> [DI] = AL (EDI + 1)
dec     ecx				-> ECX = ECX - 1 (Initial ECX value is 0x8D = 141)
jnz     short loc_20C
```

Before that, we have to take in mind that the following instructions are executed:

```
pop     esi			-> ESI = ESP = return address = 0x00000224
push    esi
mov     edi, esi	-> EDI = ESI = ESP = 0x00000224
```

So now that we know the value of _ESI_ and _EDI_ is _ESP_ and _ESP_ point to the data after the call instruction, we can see that this routine seems to decode the next part of the binary, composed by 141 bytes.

So let's write a python decoder:

```
MAX_VALUE = 0xFF

def decrypt_file():
	decoded_bytes = bytearray()
	key = 0x41
	counter = 0x18D

	with open("Scripts/Others/Lab_19/lab19-01.bin", "rb") as encoded_file:
		encoded_file.seek(0x224)
		encoded_byte = encoded_file.read(1)

		while counter > 0:
			value_1 = (((int.from_bytes(encoded_byte, byteorder="big") - key) & MAX_VALUE) << 4) & MAX_VALUE
			encoded_byte = encoded_file.read(1)

			value_2 = (int.from_bytes(encoded_byte, byteorder="big") - key) & MAX_VALUE
			decoded_byte = (value_2 + value_1) & MAX_VALUE
			decoded_bytes.append(decoded_byte)

			counter = counter - 1
			encoded_byte = encoded_file.read(1)

	return decoded_bytes

def save_decrypted_file(decoded_bytes):
	decoded_file = open("Scripts/Others/Lab_19/lab19-01_stage_2.bin", "wb")
	decoded_file.write(decoded_bytes)

decoded_bytes = decrypt_file()
save_decrypted_file(decoded_bytes)
```

We execute it...

```
python3 Scripts/Others/Lab_19/lab19_01_decode_next_stage.py
```

Great! We have decoding the second stage!

![_IDA Pro_ main function](../Pictures/Lab_19/lab_19-01_1_ida_pro_2.png)

**2. Which functions does the shellcode manually import?**

**3. What network host does the shellcode communicate with?**

**4. What filesystem residue does the shellcode leave?**

**5. What does the shellcode do?**

## Lab 19-2

The file Lab19-02.exe contains a piece of shellcode that will be injected into another process and run. Analyze this file.

**1. What process is injected with the shellcode?**

**2. Where is the shellcode located?**

**3. How is the shellcode encoded?**

**4. Which functions does the shellcode manually import?**

**5. What network hosts does the shellcode communicate with?**

**6. What does the shellcode do?**

## Lab 19-3

Analyze the file Lab19-03.pdf. If you get stuck and can’t find the shellcode, just skip that part of the lab and analyze file Lab19-03_sc.bin using shellcode_launcher.exe.

**1. What exploit is used in this PDF?**

**2. How is the shellcode encoded?**

**3. Which functions does the shellcode manually import?**

**4. What filesystem residue does the shellcode leave?**

**5. What does the shellcode do?**
