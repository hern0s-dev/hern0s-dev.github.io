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

```cpp
#include <Windows.h>
#include <stdio.h>

#define PROCESS_ID

int main(){

HANDLE victim_handle = OpenProcess(PROCESS_QUERY_INFORMATION, NULL, pid);

}
```
{% if page.comments %} {% include disqus.html %} {% endif %}

