# Lab 13 - Data Encoding

## Lab 13-1

Analyze the malware found in the file Lab13-01.exe.

**1. Compare the strings in the malware (from the output of the strings command) with the information available via dynamic analysis. Based on this comparison, which elements might be encoded?**

When we execute the _strings_ command we only can see a bunch of interesting strings:

```
C:\> strings Lab13-01.exe

...
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
...
GetStringTypeW
CloseHandle
7"@
Mozilla/4.0
http://%s/%s/
Could not load exe.
Could not locate dialog box.
Could not load dialog box.
Could not lock dialog box.
...
```

However, the sample seems to lack of strings, probably because of encoding. Let's see if we execute the sample, we can see more strings.

To do so, we execute the sample and then we check the strings by means of _Process Explorer_.

```
...
C:\Documents and Settings\PSEL\Escritorio\Binaries\Chapter_13L\Lab13-01.exe
abcdefghijklmnopqrstuvwxyz
ABCDEFGHIJKLMNOPQRSTUVWXYZ
www.practicalmalwareanalysis.com
...
```

As we can see, the malware has decoded some binaries in execution time.

**2. Use IDA Pro to look for potential encoding by searching for the string xor. What type of encoding do you find?**

After searching the string _XOR_ ([ALT]+[T]) we find out the following operation at function _0x00401190_:

```
xor     eax, 3Bh
```

This seems to be the encoding routine that we were looking for.

**3. What is the key used for encoding and what content does it encode?**

The key of the decryption routine is the hexadecimal value _0x3B_.

![_IDA Pro_ decryption routine](../Pictures/Lab_13/lab_13-01_2_ida_pro_1.png)

The encoded data is given by means of a resource file, which can be seen by means of _Resource Hacker_. This file contains the following data:

![_IDA Pro_ load resource file to decrypt](../Pictures/Lab_13/lab_13-01_2_ida_pro_2.png)

```
4C 4C 4C 15 4B 49 5A 58 4F 52 58 5A 57 56 5A 57 4C 5A 49 5E 5A 55 5A 57 42 48 52 48 15 58 54 56
```

If we decode this data using the _XOR_ key we already know, we will see the value of the encrypted data. To do so, we have developed the following _python_ script:

```
encrypted_string = bytearray([0x4C, 0x4C, 0x4C, 0x15, 0x4B, 0x49, 0x5A, 0x58, 0x4F, 0x52, 0x58, 0x5A, 0x57, 0x56, 0x5A, 0x57, 0x4C, 0x5A, 0x49, 0x5E, 0x5A, 0x55, 0x5A, 0x57, 0x42, 0x48, 0x52, 0x48, 0x15, 0x58, 0x54, 0x56])
decryption_key = 0x3B

decrypted_string = ""

for counter in range(len(encrypted_string)):
	encrypted_char = encrypted_string[counter]
	decrypted_string = decrypted_string + chr(decryption_key ^ encrypted_char)

print("The decrypted string is: " + decrypted_string)
```

This wil give us the following output:

```
$ python3 Scripts/Others/Lab_13/lab13_01_decryption_resource_file.py

The decrypted string is: www.practicalmalwareanalysis.com
```

**4. Use the static tools FindCrypt2, Krypto ANALyzer (KANAL), and the IDA Entropy Plugin to identify any other encoding mechanisms. What do you find?**

We try to download and use the suggested _IDA Pro_ plugins, but we couldn't find the way to do it. However, we successfully executed the _KANAL_ plugin of _PEid_.

![_PEid_ _KANAL_ 1](../Pictures/Lab_13/lab_13-01_4_peid_1.png)

![_PEid_ _KANAL_ 2](../Pictures/Lab_13/lab_13-01_4_peid_2.png)

As we can see, several references to _base64_ have been found.

After that, we tried to use the plugin _findcrypt-yara_ (https://github.com/polymorf/findcrypt-yara) in the full IDA Pro version. After installing the plugin, we could see the following output.

![_IDA Pro_ _findcrypt-yara_](../Pictures/Lab_13/lab_13-01_4_ida_pro_1.png)

It has detected one coincidence of _base64_ encoding, the same that _KANAL_ detected.

**5. What type of encoding is used for a portion of the network traffic sent by the malware?**

To know the encoding mechanism used by the malware, we need to take into account what the previously used plugins told us. That in the address _0x004050E8_ something related with _base64_ encoding was detected. If we go there, we will see a bunch of bytes that seems to be the alphabet of _base64_ encoding, but _IDA Pro_ has mislabeled, so let's fix it.

![_IDA Pro_ _base64_ alphabet 1](../Pictures/Lab_13/lab_13-01_5_ida_pro_1.png)

We click in the first letter (0x41) or in the variable _byte_4050E8_, and click on the key 'a'.

![_IDA Pro_ _base64_ alphabet 2](../Pictures/Lab_13/lab_13-01_5_ida_pro_2.png)

Now, we can see how this variable is referenced four times in the function at address _0x00401000_, we called _base64_encode_, which is referenced by the function located at _0x004010B1_, which is called just before the _InternetOpen_ _WINAPI_ function call. So we rename the function to _base64_encoding_.

**6. Where is the Base64 function in the disassembly?**

**7. What is the maximum length of the Base64 encoded data that is sent? What is encoded?**

**8. In this malware, would you ever see the padding characters (= or ==) in the Base64-encoded data?**

**9. What does this malware do?**

## Lab 13-2

Analyze the malware found in the file Lab13-02.exe.

**1. Using dynamic analysis, determine what this malware creates.**

**2. Use static techniques such as an xor search, FindCrypt2, KANAL, and the IDA Entropy Plugin to look for potential encoding. What do you find?**

**3. Based on your answer to question 1, which imported function would be a good prospect for finding the encoding functions?**

**4. Where is the encoding function in the disassembly?**

**5. Trace from the encoding function to the source of the encoded content. What is the content?**

**6. Can you find the algorithm used for encoding? If not, how can you decode the content?**

**7. Using instrumentation, can you recover the original source of one of the encoded files?**

## Lab 13-3

Analyze the malware found in the file Lab13-03.exe.

**1. Compare the output of strings with the information available via dynamic analysis. Based on this comparison, which elements might be encoded?**

**2. Use static analysis to look for potential encoding by searching for the string xor. What type of encoding do you find?**

**3. Use static tools like FindCrypt2, KANAL, and the IDA Entropy Plugin to identify any other encoding mechanisms. How do these findings compare with the XOR findings?**

**4. Which two encoding techniques are used in this malware?**

**5. For each encoding technique, what is the key?**

**6. For the cryptographic encryption algorithm, is the key sufficient? What else must be known?**

**7. What does this malware do?**

**8. Create code to decrypt some of the content produced during dynamic analysis. What is this content?**
