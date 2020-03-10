# Lab 14 - Malware-focused Network Signatures

This chapter’s labs focus on identifying the networking components of malware. To some degree, these labs build on Chapter 13, since when developing network signatures, you’ll often need to deal with encoded content.

## Lab 14-1

Analyze the malware found in file Lab14-01.exe. This program is not harmful to your system.

**1. Which networking libraries does the malware use, and what are their advantages?**

To get this information we are going to run the script "get_file_imports.py".

```
C:\> python get_file_imports.py Lab14-01.exe

======================
KERNEL32.dll
======================
Sleep
CreateProcessA
FlushFileBuffers
...
LCMapStringW
GetStringTypeA
CloseHandle
======================
ADVAPI32.dll
======================
GetCurrentHwProfileA
GetUserNameA
======================
urlmon.dll
======================
URLDownloadToCacheFileA
```

As we can see, the malware only uses the _URLDownloadToCacheFileA_ function from _urlmon.dll_ library. The main advantage of using this specific function is that uses the _COM_ interface, so most of the content of its HTTP requests comes from within _Windows_ itself, and therefore cannot be effectively targeted using network signatures.

**2. What source elements are used to construct the networking beacon, and what conditions would cause the beacon to change?**

The first thing the malware does is getting some information from the machine, the _GUID_ (Global Unique IDentifier) and the username.

![_IDA Pro_ GUID and username](../Pictures/Lab_14/lab_14-01_1_ida_pro_1.png)

As we can see, the malware only gets the last 12 characters of the _GUID_ (notice that a the returned value could be something like this `{12340001-4980-1920-6788-123456789012}`).

The information retrieved is concatenated in the following format: "[partial GUID]-[username]". For example, if we have a computer with the _GUID_ `{12340001-4980-1920-6788-123456789012}` and the username `jones`, the final string would be: `123456789012-jones`. This string is then passed as argument to the function _get_http_path_ (the value obtained in this function is then used as path of the _URL_ that the malware requests information) located at _0x004010BB_.

![_IDA Pro_ _get_http_path_ calling](../Pictures/Lab_14/lab_14-01_1_ida_pro_2.png)

If we take a look to the function we will see that it is quite familiar...

![_IDA Pro_ known function 1](../Pictures/Lab_14/lab_14-01_1_ida_pro_3.png)

There is also another function being called, which is located at _0x00401000_.

![_IDA Pro_ known function 2](../Pictures/Lab_14/lab_14-01_1_ida_pro_4.png)

Mmmmm... We expected something different... Wait! Let's see what _byte_4050C0_ contains.

![_IDA Pro_ _byte_4050C0_ value](../Pictures/Lab_14/lab_14-01_1_ida_pro_5.png)

Great! The _base64_ alphabet, just what we were expecting! We convert this to a string (key "A") and rename it.

![_IDA Pro_ _base64_ alphabet](../Pictures/Lab_14/lab_14-01_1_ida_pro_6.png)

Ok! But there is something more, let's take a look to the function located at _0x00401000_, where the _base64_ encoding letter is chosen (some variables have been renamed to clearify).

![_IDA Pro_ _base64_ encoding letter](../Pictures/Lab_14/lab_14-01_1_ida_pro_7.png)

As we can see, this _base64_ implementation substitutes the padding character "=" with the letter "a".

So now, we know what the function _get_http_path_ does, converts the string "[partial GUID]-[username]" to base64, so our example would be:

```
$ echo -n 123456789012-jones | base64
MTIzNDU2Nzg5MDEyLWpvbmVz
```

If our username would be different, for example "eaglemath", the _base64_ of the string "[partial GUID]-[username]" would be (notice the replacing of "="):

```
$ echo -n 123456789012-eaglemath | base64 | tr '=' 'a'
MTIzNDU2Nzg5MDEyLWVhZ2xlbWF0aAaa
```

Now, we see that this value is being passed as argument to the next function called, _cnc_communicaton_ (_0x004011A3_).

![_IDA Pro_ _cnc_communicaton_ calling](../Pictures/Lab_14/lab_14-01_1_ida_pro_8.png)

This function will make a _HTTP_ request to the C&C _URL_ by means of _URLDownloadToCacheFileA_, using an _URL_ composed by the previously calculated _base64_ value as path and the last character of such path as name of the requested file plus the extension _PNG_.

![_IDA Pro_ _URLDownloadToCacheFileA_ request](../Pictures/Lab_14/lab_14-01_1_ida_pro_9.png)

Based on our example, the _URL_ would be:

```
http://www.practicalmalwareanalysis.com/MTIzNDU2Nzg5MDEyLWpvbmVz/z.png
```

**3. Why might the information embedded in the networking beacon be of interest to the attacker?**

The information encoded in the path could be interesting to the attacker for counting purposes, since the _GUID_ of one computer is unique.

**4. Does the malware use standard Base64 encoding? If not, how is the encoding unusual?**

The _base64_ is standard but the padding character, which is "a" instead of "=", as explained in exercise 1.

**5. What is the overall purpose of this malware?**

Once the malware has performed the _HTTP_ request by means of _URLDownloadToCacheFileA_, it will execute the downloaded file, which is not a _PNG_ file like the extension suggests, using _CreateProcessA_.

![_IDA Pro_ _CreateProcessA_](../Pictures/Lab_14/lab_14-01_5_ida_pro_1.png)

If the execution fails, it will sleep for one minute and then try it again (including the _HTTP_ request).

**6. What elements of the malware’s communication may be effectively detected using a network signature?**

**7. What mistakes might analysts make in trying to develop a signature for this malware?**

**8. What set of signatures would detect this malware (and future variants)?**

## Lab 14-2

Analyze the malware found in file Lab14-02.exe. This malware has been configured to beacon to a hardcoded loopback address in order to prevent it from harming your system, but imagine that it is a hardcoded external address.

**1. What are the advantages or disadvantages of coding malware to use direct IP addresses?**

**2. Which networking libraries does this malware use? What are the advantages or disadvantages of using these libraries?**

**3. What is the source of the URL that the malware uses for beaconing? What advantages does this source offer?**

**4. Which aspect of the HTTP protocol does the malware leverage to achieve its objectives?**

**5. What kind of information is communicated in the malware’s initial beacon?**

**6. What are some disadvantages in the design of this malware’s communication channels?**

**7. Is the malware’s encoding scheme standard?**

**8. How is communication terminated?**

**9. What is the purpose of this malware, and what role might it play in the attacker’s arsenal?**

## Lab 14-3

This lab builds on Lab 14-1. Imagine that this malware is an attempt by the attacker to improve his techniques. Analyze the malware found in file Lab14-03.exe.

**1. What hard-coded elements are used in the initial beacon? What elements, if any, would make a good signature?**

**2. What elements of the initial beacon may not be conducive to a longlasting signature?**

**3. How does the malware obtain commands? What example from the chapter used a similar methodology? What are the advantages of this technique?**

**4. When the malware receives input, what checks are performed on the input to determine whether it is a valid command? How does the attacker hide the list of commands the malware is searching for?**

**5. What type of encoding is used for command arguments? How is it different from Base64, and what advantages or disadvantages does it offer?**

**6. What commands are available to this malware?**

**7. What is the purpose of this malware?**

**8. This chapter introduced the idea of targeting different areas of code with independent signatures (where possible) in order to add resiliency to network indicators. What are some distinct areas of code or configuration data that can be targeted by network signatures?**

**9. What set of signatures should be used for this malware?**
