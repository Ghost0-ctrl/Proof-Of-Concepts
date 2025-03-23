# Remote DLL Injection
## Overview
This POC demonstrates a technique known as remote DLL injection. The goal is to force a target process (for example, Notepad) to load an external DLL (Dynamic Link Library). The process involves three main steps:

  1. Allocating Memory in the Remote Process: Reserve a block of memory in the target process’s address space.
  2. Writing the DLL Path: Write the path (as a byte string) of the DLL into the allocated memory.
  3. Forcing the DLL to Load: Use the Windows API function LoadLibraryA—located via GetProcAddress on kernel32.dll—by creating a remote thread that calls it, passing the address of the DLL path in memory.

This technique is commonly used for injecting code into a process for either legitimate purposes (such as extending the functionality of a running application) or by malware for nefarious reasons.

## Detailed Code Walkthrough

1. Importing Modules and Defining API Functions
    1. ctypes and wintypes:
       The code imports the ctypes module and its wintypes submodule. This allows the script to interact directly with Windows API functions. The API calls are performed by calling functions in kernel32.dll, a core Windows DLL.

    2. Function Prototypes:
       The POC defines the argument types (argtypes) and return types (restype) for the following functions:
         1. OpenProcess: Opens an existing process given its process ID (PID) with specific access rights.
         2. VirtualAllocEx: Allocates a block of memory within the address space of the target process.
         3. WriteProcessMemory: Writes data (the DLL path) into the allocated memory in the remote process.
         4. GetModuleHandleA: Retrieves a handle to a loaded module (here, kernel32.dll).
         5. GetProcAddress: Finds the address of an exported function (in this case, LoadLibraryA) within a module.
         6. CreateRemoteThread: Creates a new thread in the remote process that will call the specified function—in our case, to load the DLL.

    3. Defining Structures:
       The code also defines the _SECURITY_ATTRIBUTES structure. Although this structure isn’t used in every detail, it is necessary when creating a remote thread to specify attributes like whether handles are inherited by child processes.
