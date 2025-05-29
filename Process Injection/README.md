# Purpose

For this small project, I made a process injection malware. The whole point of this was to increase my level of understanding on how malware interacts with Windows APIs, and also to increase my investigative skills for process injection. A large part of what I coded was through external research (reading MSDN docs, YUCK!) and watching [this](https://www.youtube.com/watch?v=A6EKDAKBXPs) video. 

While I am not **remotely** close to an expert, I did learn a lot of things about the Windows environment and APIs, so I'll write them down here. 

## Windows APIs

When I first started, I knew in a very broad sense of how Windows APIs work, but I always wondered how an attacker could take advantage of those. I mean, they were always just sitting there for anyone to use right? Well, after seeing some live malware samples that utilized process injection, I began to Google what APIs were used in practice. 

Immediately, I found that there were two main libraries that you can use for this: **ntdll.dll** and **kernel32.dll**. The difference between the two is that **ntdll.dll** is a lower-level library, and it contains something called a "syscall"; this makes ntdll very desirable for threat actors, and because of that, common EDR and AV tools monitor this library using API hooks (which we're going to explore whenever I make a writeup on direct and indirect syscalls). Meanwhile, **kernel32.dll** is essentially a wrapper for ntdll.dll, and makes it nice and easy to use Winapi. The library that I used for this rudimentary project was kernel32.dll because, as I said previously, it makes interacting with Windows APIs much less aggravating. 

## Process Injection

In order to inject into another process using Windows APIs, you need to follow this generalized workflow: 

1. Open target process
2. Allocate virtual memory in target process
3. Write shellcode into virtual memory space in target process
4. Create a thread to execute target process memory

It seems easy enough, right? Well, kind of. Initially I had to grab the snapshot of current processes in memory using CreateToolhelp32Snapshot(), and had to find my target process by iterating through them until I found the process name. 
