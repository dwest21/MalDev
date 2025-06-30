A small note: Some of the screenshots I used in my explanation come from different articles and papers. I will include references at the end to make sure I give credit to the all pages. 

# Defense Evasion 101: Direct and Indirect Syscalls

In an ideal world, there wouldn’t be the need for cybersecurity because there would be no criminals. Unfortunately, human nature prevents us from living in an ideal world, which is why as technology advances, it becomes more and more apparent that there is a strong need to keep ahead of the curve if we want to secure our online technological environments. For those people that don’t want to deal with securing their own environments, numerous companies have created their own security software that can be used to maintain a strong security posture without much maintenance; this software is nowhere near perfect, and threat actors are constantly trying to find ways to evade detection. The process of actively trying to avoid security detection is commonly referred to as “Defense Evasion” and it can be very useful for Security Operations Centers (SOCs) to keep up to date on the most recent Defense Evasion techniques, so they don’t get blindsided. In this writeup, we’ll explore one of the more interesting (in my opinion) methods for getting around security measures that utilize the inner workings of Windows and Protection Rings. 

## Protection Rings

![image](https://github.com/user-attachments/assets/27aab444-c7da-4450-96d2-522bba77846b)

Protection Rings are a system of protection that CPUs implement to prevent users from executing privileged commands. The 2 levels that we'll focus on are colloquially referred to as “User mode” and “Kernel mode”, which appropriately names the levels based on who operates within them; the “Kernel” ring should have the highest privileges, which makes it the most desirable to threat actors. “Kernel mode” grants the ability to execute privileged assembly instructions in the CPU. “User mode” contains everything that would operate underneath a user within the machine, which even includes security software. While modern Anti-virus (AV) and Endpoint Detection and Response (EDR) software primarily operates in “User mode”, they do provide kernel-level monitoring to broaden the scope of which they’re able to contextualize and alert upon. This is concept is important to learn why this attack even came about in the first place.

## Windows API Workflow

![image](https://github.com/user-attachments/assets/58f8772d-b39e-4c3d-8ddc-aff5d3582950)

The CPUs implementing the principle of least privilege isn’t the only security measure taken, the Windows Operating system also has a layer of obfuscation for its developers. Microsoft provides APIs for developers to interact with the operating system to create new apps, however, Microsoft doesn’t want just any developer to interact with the kernel, because as mentioned previously, that would be a security flaw. Instead, Microsoft provides a wrapper for what’s known online as the “Windows native APIs”; the native APIs are almost officially undocumented within the Microsoft Developer docs (MSDN), the wrappers, however, are provided within the “Windows.h” header file for C/C#/C++ and can be used for a variety of things, however, those APIs within the header file are not the functions that interact with the kernel. This is a nice obfuscation technique to prevent threat actors from manipulating the “syscall” assembly instruction, which interacts with the kernel, as it doesn’t provide the function that contains the “syscall”. In fact, there are only two DLLs within the entire Windows system that have syscalls within them: Win32u.dll and Ntdll.dll. All other functions that need syscalls are basically just wrappers for these two DLLs.

A quick interlude for the syscall instruction: each syscall instruction is accompanied by a “system service number” (SSN) which is a numeric identifier to determine what privileged assembly instruction is to be executed by the CPU. These numbers are important for the theory of the attack mentioned later because we need to know the SSN to have a successful syscall, otherwise a privileged instruction won’t be executed. 

This was quickly found out by security researchers, and security solutions found a way to prevent threat actors from taking advantage of these APIs: API hooks.  These API hooks were a way for security companies to monitor the code before the syscalls to ensure that malicious code isn’t messing with the kernel. In order to do that, they modified the instructions before the syscall and put in a “jmp” instruction that sends the user code to the EDR’s own DLL that would analyze it and decide whether to let it run or not. Now with the hooks in place, if any code were to be executed that wanted to interact with the kernel, it gets executed under heavy scrutiny, all while allowing the EDR to run underneath the User mode ring.  

![image](https://github.com/user-attachments/assets/ba14595f-9c72-46c0-8057-63671f049afa)
![image](https://github.com/user-attachments/assets/ba74c5ef-c756-414d-bf34-1156a806d542)

## API Hook Exploit

Now, this presents a problem for malware developers because how can you abuse the kernel if your code gets scanned every time? Well, in comes direct syscalls. 

### Direct Syscalls

As mentioned previously, an SSN is needed for the syscall to work correctly. Luckily (depending on your perspective, this might be the wrong word), we can find out the SSN with relative ease. While the native API functions are not heavily documented, there are several sites that provide minor documentation on them, or there are methods to find implementations of them using debuggers. Regardless, in the Ntdll function definition you can see an assembly instruction “mov eax,18h”. This instruction moves the SSN into the eax register, meaning that we can store the value in that register into a variable and just call the syscall instruction ourselves. This is easily done by adding our own definition of any Ntdll function that we want to run in a separate assembly file and telling the compiler to include that assembly file to look for definitions. For process injection, we would need NtOpenProcess, NtAllocateVirtualMemory, NtWriteProcessMemory, NtCreateThreadEx, and NtWaitForSingleObject.

![image](https://github.com/user-attachments/assets/db9fc777-ac5b-499d-a74e-7edf6369ecb3)

Using this assembly file with the Ntdll function definitions, we can now bypass the EDR hook and run whatever code we want without being impeded. Fortunately, this method provides some big Indicators of Compromise (IoCs) that any security solution can see as soon as the program runs. When our malware runs and the syscall gets invoked from our assembly file, that syscall gets called in the virtual address space of our malware, which is a giant waving red flag for security solutions. Within the Windows environment, the syscall instruction is only allowed to run within two distinct address spaces: Ntdll.dll and Win32u.dll. The other IoC that a security solution would pick up is the “ret” instruction after the syscall is located within our malware’s address space as well.

### Indirect Syscalls

The clear next step for developing this is to figure out how to get the syscall and ret instructions to execute within the address space of Ntdll, while also skipping the API hook set by the EDRs. Well, indirect syscalls provide a nice steppingstone for our journey into defense evasion, which is detailed very nicely in the following diagram.

![image](https://github.com/user-attachments/assets/59541630-7fe2-4f1e-8f8d-c119a3c39595)

This would allow us to skirt the detection for the syscall address, while also completely evading the EDR code scanning DLL. Instead of the previous technique where we invoked the syscall instruction ourselves, we’re going to need an address to jump to so we can execute within the address space of Ntdll.

![image](https://github.com/user-attachments/assets/c3e1bdfc-be96-401a-a436-0baf6c999871)

Looking at the addresses of the two instructions boxed in red, there’s an offset of 0x12h, so finding the base address of the function and adding 0x12h would give us the syscall. Once again, we are going to have to create our own definitions for the Ntdll functions in an assembly file, however, this time, instead of using the syscall and ret instructions ourselves, we are going to jump to the address we have found above.

![image](https://github.com/user-attachments/assets/4a5fd5e1-f5d1-484e-aaac-3a80e4da2d35)

Upon execution of this code, you will see that the syscall gets executed and within the address space of Ntdll as intended. This technique, while clever upon its discovery, will also get flagged by most EDRs today because of something called “kernel-level” monitoring. There are also several other detections that could detect this attack; however, this was mainly done as proof-of-concept.

For ease of readability, I have included screenshots of the program running at the end to show that the proof-of-concept works. The following screenshots are of the “indirect syscall” method to show that the syscall does execute within the address space of where it’s expected. 

![image](https://github.com/user-attachments/assets/97f4d26b-0f3f-46cf-b8db-94a3021512c2)

Pre-execution, we can see an instance of mspaint.exe running, as well as some other instances of the coding environment I am using.

![image](https://github.com/user-attachments/assets/fefd45e3-3032-445a-9cbf-caa9f15d453f)

In Label 1, you can see the new definition for the assembly file that leads to the suspected address of the syscall within the library Ntdll, so we can evade the EDR hook, as well as just call the syscall instruction right off the bat. In label 2, you can see the current execution context of the process, which shows that we are in our own definitions of “NtOpenProcess” at the top of the stack. In label 3, you can see the SSN being stored in the rax (64-bit version of eax) register, so here we are calling SSN 0x26h.

![image](https://github.com/user-attachments/assets/6bdf7978-8d79-4010-a7ec-b9ba17617fd0)

In label 1, the yellow arrow shows the current value of the instruction pointer (the current instruction to be executed). After the jump, we went directly to the syscall instruction to execute it at the address on the left. There are two label 2 boxes because they both show the same thing: there is a new context that we are executing and that’s inside of Ntdll, which is expected because we were supposed to jump inside of that library’s address.

![image](https://github.com/user-attachments/assets/ce835550-efc5-453a-b21c-3cf0dca77a5a)

Finally, post-execution shows that a new instance of notepad has spawned, which the program output showing a successful tracing of where the program is at.

## References

•	https://alice.climent-pommeret.red/posts/a-syscall-journey-in-the-windows-kernel/
•	https://www.crow.rip/crows-nest/mal/dev/inject/syscalls/direct-syscalls
•	https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls
•	https://www.giac.org/paper/grem/2593/ioc-indicators-compromise-malware-forensics/125039 (Pages 15-17, specifically)
