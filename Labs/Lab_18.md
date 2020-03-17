# Lab 18 - Packers and Unpacking

Your goal for the labs in this chapter is simply to unpack the code for further analysis. For each lab, you should try to unpack the code so that other static analysis techniques can be used. While you may be able to find an automated unpacker that will work with some of these labs, automated unpackers won’t help you learn the skills you need when you encounter custom packers. Also, once you master unpacking, you may be able to manually unpack a file in less time than it takes to find, download, and use an automated unpacker.

Each lab is a packed version of a lab from a previous chapter. Your task in each case is to unpack the lab and identify the chapter in which it appeared. The files are Lab18-01.exe through Lab18-05.exe.

## Lab 18-1

The first we do is loading the sample in a tool such as _PEView_ and see what it cointains.

![_PEView_ sample 1](../Pictures/Lab_18/lab_18-01_1_peview_1.png)

At first sight we can see that the sample seems to be packed with _UPX_. Let's verify it with _PEiD_.

![_PEiD_ sample 1](../Pictures/Lab_18/lab_18-01_1_peid_1.png)

Great! It is packed with _UPX_. We can follow two approaches, the first and easiest one is running the following command:

```
C:\> upx -d Lab18-01.exe -o Lab18-01_unpacked.exe

upx: Lab18-01.exe: NotPackedException: not packed by UPX
```

Mmmm... Interesting, the file has not been packed with _UPX_ or at least with the regular one, we will have to dig in it to unpack it, something we had done in the second approach.

We load the binary in _IDA Pro_ and start looking for the last _jump_ instruction, which is located at _0x00409F43_.

![_IDA Pro_ _UPX_ unpacking 1](../Pictures/Lab_18/lab_18-01_1_ida_pro_1.png)

Now, we load the sample into _OllyDBG_ and set a breakpoint at this memory location

![_OllyDBG_ _UPX_ unpacking 1](../Pictures/Lab_18/lab_18-01_1_ollydbg_1.png)

We run the sample until there (F9) and then we press either _Step into_ (F7) or _Step over_ (F8).

![_OllyDBG_ _UPX_ unpacking 2](../Pictures/Lab_18/lab_18-01_1_ollydbg_2.png)

Great! We are now into the unpacked code of the sample! 

So now, click on "Plugins -> OllyDump -> Dump debugged process

![_OllyDBG_ _UPX_ unpacking 3](../Pictures/Lab_18/lab_18-01_1_ollydbg_3.png)

After that, click ok and _Olly_ will do the rest (_OllyDBG_ will get the current _EIP_ as entry point).

![_OllyDBG_ _UPX_ unpacking 4](../Pictures/Lab_18/lab_18-01_1_ollydbg_4.png)

Let's see if the dumped process has been successfully unpacked.

![_IDA Pro_ _UPX_ unpacked 1](../Pictures/Lab_18/lab_18-01_1_ida_pro_2.png)

![_IDA Pro_ _UPX_ unpacked 2](../Pictures/Lab_18/lab_18-01_1_ida_pro_3.png)

![_IDA Pro_ _UPX_ unpacked 3](../Pictures/Lab_18/lab_18-01_1_ida_pro_4.png)

As we can see, the malware has been successfully unpacked! Now, we need to identify which sample is.

The first thing we see that draw our attention is the string `http://www.practicalmalwareanalysis.com/%s/%c.png`, which was seen in a the sample _Lab14-1.exe_.

## Lab 18-2

## Lab 18-3

## Lab 18-4

## Lab 18-5