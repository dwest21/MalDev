# Disclaimer

This repo is purely for education purposes. While AMSI patching has been a known issue for a couple of years, any misuse of any code provided is _illegal_ without proper consent. For related security issues, please open an issue on this repo with a description of the misuse.

# Preliminary Notes

Recently, I've taken up a little security research project and looked into the AntiMalwareScanInterface (AMSI) that is implemented within the Windows operating system. AMSI was implemented with the release of Windows 10, and it served as a way for applications and services to scan for malware. This becomes important when thinking about Endpoint Detection and Response/Antivirus (EDR/AV). The workflow for AMSI has been provided by Microsoft, and you can see it acts as an intermediary for security providers and applications: 

<img width="725" height="320" alt="image" src="https://github.com/user-attachments/assets/21def793-1872-4975-89e5-95f2952e3c6d" />

This workflow makes it especially desirable for attackers to pursue because if you can remove the middleman, the security providers' buffer scanning capability is handicapped. That being said, there are many techniques for AMSI patching out there, but I'll be focusing on intercepting the CAmsiAntimalware object and patching the scanning functions for each provider held within that object. 

It is necessary to point out that I will be utilizing AmsiInitialize() in this PoC because it returns the AmsiContext which I will be able to get the objects and arrays that I need. Most of the research for this comes from a Black Hat 2022 Asia conference (linked [here](https://i.blackhat.com/Asia-22/Friday-Materials/AS-22-Korkos-AMSI-and-Bypass.pdf?_gl=1*1c4zhid*_gcl_au*MTgyMDgxMjc1OC4xNzUzNzM2MDIx*_ga*NTY5ODg5ODIxLjE3NTM3MzYwMjE.*_ga_K4JK67TFYV*czE3NTM4ODM5MzYkbzIkZzAkdDE3NTM4ODM5MzYkajYwJGwwJGgw&_ga=2.226094554.1561298366.1753883936-569889821.1753736021)). The general outline of this process goes like this:

1. Use AmsiIntialize() to get the Amsi context necessary for the rest of the technique

2. Retrieve the CAmsiAntimalware object

   2a. This object is found at an offset of 16 bytes from the base address of the Amsi context for 64-bit architectures, or an offset of 8 bytes for 32-bit architectures.

3. Retrieve the list of Antimalware providers

   3a. This list is located at an offset of 64 bytes from the CAmsiAntimalware object for 64-bit architectures, or an offset of 36 bytes for 32-bit architectures.

4. Retrieve each provider's Virtual Table (Vtable) to be able to grab the function we are looking for

   4a. A VTable is an implementation of virtual functions that are called at runtime. This is how object-oriented languages like C++ can achieve polymorphism.

   4b. The Vtable reference can be found within each Antimalware provider's base address

5. Retrieve the scanning function from the Vtable

   5a.  This function is found at an offset of 24 bytes from the VTable base address for 64-bit architectures, or an offset of 12 bytes for 32-bit architectures

6. Patch the functions as necessary

So with all of that out of the way, let's move onto the code. 

## Proof-of-Concept

First, in order to get around any detections caused by hooks or otherwise, I'll begin by dynamically grabbing the functions I need with an early declaration of the Win32 API functions "LoadLibrary" and "GetProcAddress" (this can be done without either of those two, but for the purposes of this I just went the easy route). 

<img width="699" height="219" alt="image" src="https://github.com/user-attachments/assets/44c6e07d-83c3-40d7-825e-b386170692a5" />

Next, I'm going to be using delegates for indirect method invocation; this can help prevent PowerShell from writing the code to disk. Before I start declaring delegates, however, I need to define the function signature, so I'll be using Get-DelegateType. Unfortunately, this cmdlet is picked up by a large amount of security software, but I found that it's just looking for the actual name of the cmdlet, so I changed the name to "Get-NewType" to prevent this. 

<img width="1291" height="475" alt="image" src="https://github.com/user-attachments/assets/dd69e610-6126-429d-beb9-acb04b13669f" />

I'll then add the previous assembly to the PowerShell instance that I'm in using Add-Type, and begin allocation the variables that I'm going to need for this (such as creating the aforementioned delegates). An important distinction here is that the shellcode I'll be patching into the functions is the 0x2d, 0x10, and 0xc3 instructions. They are the INT 2D, LEA, and RET assembly instructions, respectively. This can be used as an anti-debugging technique, however, in this method it's just being used as a way to return from the scanning function to prevent any other instructions from being executed. 

<img width="1084" height="303" alt="image" src="https://github.com/user-attachments/assets/fcd05756-2fe8-47f6-9506-b1a6c3548a83" />

After some error checking to make sure AmsiInitialize() executed correctly, we can begin grabbing the necessary objects and offsets. 

<img width="959" height="201" alt="image" src="https://github.com/user-attachments/assets/f53a396a-e8ac-4b01-989d-b6e3af4d8362" />

We want to cover every single provider based on the fact that multiple AV/EDR could exist, so we have to iterate through them. While iterating through them, we grab each function from the VTable and change the page protections to 0x80, or PAGE_EXECUTE_WRITECOPY, which allows me to write into that portion of memory. These permissions also allow for a copy to be made of the page and mapped to the calling process. This will not disable the entire AV/EDR, but will disable it from scanning the code within this single PowerShell instance. We also do error checking for that function to prevent any unexpected errors. 

<img width="1014" height="250" alt="image" src="https://github.com/user-attachments/assets/84a9dfd9-2345-440e-b35c-4119b3417b81" />

After the permissions have been changed, we want to write our shellcode into that memory page and verify that those are the same bytes that we intended for it to have. We then change the permissions back to what they were before to not raise any flags for the AV/EDR, and grab the next provider in the list. After this, the AMSI provider scanning function should be fully patched and this is where threat actors would likely thrive. 

<img width="1158" height="497" alt="image" src="https://github.com/user-attachments/assets/b5cf199d-8309-40bb-8947-28d701dff132" />

### EDR Test pre-AMSI patch

Before running the AMSI patching script, using the cmdlet "Invoke-Mimikatz" would cause that PowerShell instance to be caught and killed by the EDR. 

<img width="841" height="188" alt="image" src="https://github.com/user-attachments/assets/7a7469a4-bc5f-4026-9618-7fd738ae6ace" />
<img width="372" height="298" alt="image" src="https://github.com/user-attachments/assets/383b4db2-0580-49f6-ba4a-227330180c4e" />

### EDR Test post-AMSI patch

After running the script, the output was successful and running the malicious script, the PowerShell instance was NOT detected or killed. In fact, running the in-memory version of Mimikatz doesn't raise any alarms within this PowerShell instance.

<img width="827" height="371" alt="image" src="https://github.com/user-attachments/assets/0b631b3d-6b7c-4ef3-94ec-fb53456c9307" />
