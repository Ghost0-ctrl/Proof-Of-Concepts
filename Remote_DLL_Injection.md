# Remote DLL Injection
## Overview
This POC demonstrates a technique known as remote DLL injection. The goal is to force a target process (for example, Notepad) to load an external DLL (Dynamic Link Library). The process involves three main steps:

  1. Allocating Memory in the Remote Process: Reserve a block of memory in the target process’s address space.
  2. Writing the DLL Path: Write the path (as a byte string) of the DLL into the allocated memory.
  3. Forcing the DLL to Load: Use the Windows API function LoadLibraryA—located via GetProcAddress on kernel32.dll—by creating a remote thread that calls it, passing the address of the DLL path in memory.

This technique is commonly used for injecting code into a process for either legitimate purposes (such as extending the functionality of a running application) or by malware for nefarious reasons.
