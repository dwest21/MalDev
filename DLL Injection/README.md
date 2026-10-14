# DLL Injection

During my journey to understand malware and how complex it gets, I've started MalDev Academy to be able to learn from people more proficient in the topic than I am. The modules themselves have introduced a plethora of cool topics and helped me understand some basic concepts so far that I will need to know before creating malware (such as PE sections, how and where to place payloads within those sections, obfuscation of payloads, and much more). To demonstrate my understanding so far in the course, I've created a small sample for DLL injection. I'll do a breakdown of how it works and how to show that the proof-of-concept works. 

## Remote Process Injection

In Windows, you have to use a different set of APIs to inject into remote processes; these APIs are typically suffixed by "Ex," but you can easily find these functions in the Microsoft documentation (learn.microsoft.com). The general principal of injection attacks goes like this:

1. Allocate memory space in the process
2. Modify page permissions as needed to the newly allocated memory space
3. Write to the memory pages
4. Create a remote thread to execute in that address space

Security vendors have known this for a long time, so those win32 APIs are monitored pretty heavily and any suspicious allocations/write actions are alerted on. I haven't provided an example of that in this module, however, you can use dynamically loaded APIs to prevent static scans from catching their use, or you can also use API hashing. There are more methods to prevent detection, but that will come in future proof-of-concepts to demonstrate my understanding. 

## Payload DLL

The DLL that we are going to inject is a simple DLL (code provided in this repository). Upon being loaded, it pops a Windows message box; there is an exported function that also pops a Windows message box, however, it has a different name to distinguish itself. That is the sole purpose of this DLL. 

## Running The Malware

The executable is setup to read the DLL path and the process name in from the command line parameters. Passing those in and you get met with a series of prompts to prevent the script from running too fast (and to allow for debugging). 

![image](https://github.com/user-attachments/assets/a2633150-6164-4888-b02f-bb14c0cc361b)

You can see that from x64Dbg's output, we have successfully allocated space within the target process. The memory space does not have any content within it yet because we have decided to place a breakpoint after allocation, again, to allow for debugging and proving that the code does what we want it to do. 

![image](https://github.com/user-attachments/assets/7a4eb816-0b58-4029-b998-937b57f8acf3)

After writing to the memory space, x64Dbg correctly shows the path of the DLL that we are going to inject. 

![image](https://github.com/user-attachments/assets/bd96d9c5-8345-414f-b794-5374e7875bb7)

Taking a look in ProcessHacker (or SystemInformer now), we can see that our DLL is correctly loaded into the process and we are even met with the DllMain call for spawning the message box.

### Exported Functions

It wasn't enough to be able to load in our DLL - I wanted to showcase how to run the functions exported from that DLL as well. To do that, I had to find the address of our DLL that we loaded in the remote process and find the offset of the function located within the DLL itself. To calculate the offset, we load the library locally and use GetProcAddress to get the function address and subject the base address of the DLL from the function address, and that should provide the offset. After finding the offset, we create a remote thread to execute at the address of our injected DLL and add the offset to execute the function. We can also pass in parameters this way, but that is not necessary here. 

![image](https://github.com/user-attachments/assets/26dfe79c-1d2e-43ff-89af-136c78d6c76e)

This module has been super helpful in teaching newer techniques to things I have explored previously and a good refresher on the things I was already familiar with. The next module includes payload obfuscation and the different ways to do that, so I look forward to showcasing that as well. 
