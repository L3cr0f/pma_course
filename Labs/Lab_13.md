# Lab 13 - Data Encoding

## Lab 13-1

Analyze the malware found in the file Lab13-01.exe.

**1. Compare the strings in the malware (from the output of the strings command) with the information available via dynamic analysis. Based on this comparison, which elements might be encoded?**
**2. Use IDA Pro to look for potential encoding by searching for the string xor. What type of encoding do you find?**
**3. What is the key used for encoding and what content does it encode?**
**4. Use the static tools FindCrypt2, Krypto ANALyzer (KANAL), and the IDA Entropy Plugin to identify any other encoding mechanisms. What do you find?**
**5. What type of encoding is used for a portion of the network traffic sent by the malware?**
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