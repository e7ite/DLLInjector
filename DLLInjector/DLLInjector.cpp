#include <tchar.h>
#include <cstdio>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

// Obtains string literal for current library based on if Unicode is defined
#define _LOADLIBRARYSTRIMPL(a) #a
#define LOADLIBRARYSTRIMPL(a) _LOADLIBRARYSTRIMPL(a)
#define LOADLIBRARYSTR LOADLIBRARYSTRIMPL(LoadLibrary)

/**
 * Reports errors from Win32 API if errStr is specified, frees any handles
 * passed in through toFree, and calls system("pause") to allow user to acknowledge 
 *
 * @param errStr If not null, a string to output along with the converted error
 * @return -1
 */
int ReportError(LPCTSTR errStr);

/**
 * Gets a handle to the loaded DLL module with name Dllname from argument process
 * @param snap Snapshot of all processes from CreateToolHelp32Snapshot
 * @param dllName Pointer to null-terminated string with name of DLl to find
 * @param process THe process ID of which to search through the loaded modules
 * @return If success, a handle to the loaded DLL. nullptr if not found or error.
 */
HMODULE GetDllHandle(LPCTSTR dllName, DWORD processID);

/**
 * Gets the pid of the process specified by processName
 * @param snap Snapshot of all processes from CreateToolHelp32Snapshot
 * @param processName Pointer to null terminated TCHAR string of process name
 * @return If success, the process ID with name processName. -1 if not found or error
 */
DWORD GetProcessID(LPCTSTR processName);

/**
 * Wrapper to Win32 handles to faciliate freeing of OS resources upon termination
 * of program.
 * NOTE: Make sure to not terminate program such as using exit() as this will 
 * not invoke the destructor to release the resources
 */
struct HandleManager
{
    HANDLE handle;

    HandleManager(HANDLE handle) : handle(handle) {}
    HandleManager(const HandleManager &) = delete;
    HandleManager(HandleManager &&) = delete;
    HandleManager &operator=(const HandleManager &) = delete;

    ~HandleManager() 
    {
        if (this->handle != nullptr && !CloseHandle(this->handle))
        {
            ReportError(TEXT("CloseHandle"));
        }
    }

    operator HANDLE() { return this->handle; }
};

/**
 * Creates and manages memory allocated in the virtual address space of the
 * program. Simply pass in what you wish to store, which process, and the size.
 * NOTE: Make sure to not terminate program such as using exit() as this will 
 * not invoke the destructor to release the resources
 */
struct ExternMemManager
{
    LPVOID base;
    HANDLE process;

    ExternMemManager(HANDLE process, LPVOID buffer, DWORD size) : process(process)
    {
        // Reserve and commit memory in the virtual address space of the target program.
        // If this fails, we do not want to continue any more destruction just to 
        // avoid any further complications
        this->base= VirtualAllocEx(this->process, nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (this->base == nullptr)
        {
            ReportError(TEXT("VirtualAllocEx"));
            exit(EXIT_FAILURE);
        }

        // Store the buffer into this newly allocated memory for the remote process.
        if (!WriteProcessMemory(this->process, this->base, buffer, size, nullptr))
        {
            ReportError(TEXT("WriteProcessMemory"));
            exit(EXIT_FAILURE);
        }
    }

    ~ExternMemManager() 
    { 
        // Free the allocated resource for the target process
        if (!VirtualFreeEx(this->process, this->base, 0, MEM_RELEASE))
        {
            ReportError(TEXT("VirtualFreeEx")); 
            exit(EXIT_FAILURE);
        }
    }

    operator LPVOID() { return this->base; }
};

int ReportError(LPCTSTR errStr)
{
    // Format the system error message and save pointer to it in errMsg
    if (errStr != nullptr)
    {
        LPTSTR errMsg;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                      nullptr,
                      GetLastError(),
                      0,
                      (LPTSTR)&errMsg,
                      0,
                      nullptr);
    
        // Output the error message and free its resources
        _tprintf(TEXT("%s: %s"), errStr, errMsg);
        LocalFree(errMsg);
    }

    // TODO: If want to portability, replace this with something else to get the
    // same pausing effect
    system("pause");

    return -1;
}

DWORD GetProcessID(LPCTSTR processName)
{
    // Get a snapshot of all the current processes on the system
    HandleManager processesSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processesSnap == INVALID_HANDLE_VALUE)
        return ReportError(TEXT("CreateToolhelp32Snapshot"));

    // Obtain the first process based on the snapshot
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(processesSnap, &processInfo))
        return ReportError(TEXT("Process32First"));

    // Iterate through all processes and find the one with matching name as arg 
    // without the extension
    do
        if (!lstrcmp(processInfo.szExeFile, processName))
            return processInfo.th32ProcessID;
    while (Process32Next(processesSnap, &processInfo));

    return -1;
}

HMODULE GetDllHandle(LPCTSTR dllName, DWORD processID)
{
    // Get a snapshot of all the current 32-bit and 64-bit modules on the system 
    HandleManager modulesSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processID);
    if (modulesSnap == INVALID_HANDLE_VALUE)
    {
        ReportError(TEXT("CreateToolhelp32Snapshot"));
        return nullptr;
    }

    // Obtain the first process based on the snapshot
    MODULEENTRY32 moduleInfo;
    moduleInfo.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(modulesSnap, &moduleInfo))
    {
        ReportError(TEXT("Module32First"));
        return nullptr;
    }

    // Iterate through all processes and find the one with matching name as arg 
    // without the extension
    do
        if (!lstrcmp(moduleInfo.szModule, dllName))
            return moduleInfo.hModule;
    while (Module32Next(modulesSnap, &moduleInfo));

    return nullptr;
}

int _tmain(int argc, const TCHAR **argv)
{
    // Check command line arguments
    if (argc < 4)
    {
        _tprintf(TEXT("Invalid usage. Correct usage:\n%s <PROCESS> <load/unload> <DLL>\n"), argv[0]);
        return ReportError(nullptr);
    }

    // Get the full file path to the DLL and size accounting for Unicode + null terminator
    LPTSTR dllName;
    TCHAR fullDllPath[MAX_PATH];
    if (!GetFullPathName(argv[3], sizeof fullDllPath / sizeof TCHAR, fullDllPath, &dllName))
    {
        _tprintf(TEXT("Could not find %s\n"), argv[3]);
        return ReportError(nullptr);
    }
    
    // Attempt to locate the process specified and get its ID
    DWORD remoteProcessID = GetProcessID(argv[1]);
    if (remoteProcessID == -1)
    {
        _tprintf(TEXT("Could not find process %s\n"), argv[1]);
        return ReportError(nullptr);
    }

    // Get the handle to the OS process
    HandleManager remoteProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                                              PROCESS_VM_OPERATION | PROCESS_VM_WRITE | 
                                              PROCESS_VM_READ, 
                                              FALSE,
                                              remoteProcessID);
    if (remoteProcess == nullptr)
        return ReportError(TEXT("OpenProcess"));

    // Save the target's DLL path into the target process's address space
    ExternMemManager remoteDllPath(remoteProcess, fullDllPath, sizeof fullDllPath);

    // Get the start routine for the thread to execute
    LPVOID onStartArg = nullptr;
    LPTHREAD_START_ROUTINE onStart = nullptr;
    const char *onStartStr = nullptr;
    HMODULE kernelDllHandle = GetModuleHandle(TEXT("kernel32"));
    if (!lstrcmp(argv[2], TEXT("load")))
    {
        onStartStr = LOADLIBRARYSTR;
        onStartArg = remoteDllPath.base;
    }
    else if (!lstrcmp(argv[2], TEXT("unload")))
    {
        onStartStr = "FreeLibrary";
        onStartArg = GetDllHandle(dllName, remoteProcessID);
        if (onStartArg == nullptr)
        {
            _tprintf(TEXT("%s was not loaded in %s\n"), dllName, argv[1]);
            return ReportError(nullptr);
        }
    }
    if (onStartStr == nullptr)
    {
        _tprintf(TEXT("Invalid option specified: %s Should be \"load\" or \"unload\"\n"), argv[2]);
        return ReportError(nullptr);
    }

    // If valid option was specified, get the corresponding start routine from
    // kernel32.dll
    onStart = (LPTHREAD_START_ROUTINE)GetProcAddress(kernelDllHandle, onStartStr);
    if (onStart == nullptr)
        return ReportError(TEXT("GetProcAddress"));

    // Create a thread in target process, have it load the desired DLL
    // using LoadLibrary from kernel32.dll and the allocated file path for
    // the target DLL
    HandleManager remoteThread = CreateRemoteThread(remoteProcess, nullptr, 0, onStart, onStartArg, 0, nullptr);
    if (remoteThread == nullptr)
        return ReportError(TEXT("CreateRemoteThread"));

    // Wait for the thread in the target process to successfully load the dll
    if (WaitForSingleObject(remoteThread, INFINITE) == WAIT_FAILED)
        return ReportError(TEXT("WaitForSingleObject"));

    // Check result of requested kernel32.dll function. Both functions return 0 on failure.
    DWORD loadLibraryResult;
    if (GetExitCodeThread(remoteThread, &loadLibraryResult) == FALSE)
        return ReportError(TEXT("GetExitCodeThread"));
    if (!loadLibraryResult)
    {
#ifdef UNICODE
        _tprintf(TEXT("%S failed to %s %s\n"), onStartStr, argv[2], dllName);
#else
        _tprintf(TEXT("%s failed to %s %s\n"), onStartStr, argv[2], dllName);
#endif
        return ReportError(nullptr);
    }

    return 0;
}
