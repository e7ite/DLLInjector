// I dont intend for this to be portable, so will use Windows specific protocols

#include <iostream>
#include <cwchar>
#include <windows.h>
#include <tlhelp32.h>

/**
 * Reports errors from Win32 API if errStr is specified, frees any handles
 * passed in through toFree, and calls system("pause") to allow user to acknowledge 
 *
 * @param errStr If not null, a string to output along with the converted error
 * @return -1
*/
int ReportError(LPCWSTR errStr);

struct HandleManager
{
    HANDLE handle;

    HandleManager(HANDLE handle) : handle(handle) {}
    HandleManager(const HandleManager &) = delete;
    HandleManager(HandleManager &&) = delete;
    HandleManager &operator=(const HandleManager &) = delete;

    ~HandleManager() 
    {
        if (CloseHandle(handle) == FALSE)
            ReportError(L"CloseHandle");
    }

    operator HANDLE() { return handle; }
};

struct ExternMemManager
{
    LPVOID base;
    HANDLE process;

    ExternMemManager(HANDLE process, LPVOID buffer, DWORD size) : process(process)
    {
        this->base= VirtualAllocEx(this->process, nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (this->base == nullptr)
            ReportError(L"VirtualAllocEx");

        if (WriteProcessMemory(this->process, this->base, buffer, size, nullptr) == FALSE)
            ReportError(L"WriteProcessMemory");
    }

    ~ExternMemManager() 
    { 
        if (!VirtualFreeEx(this->process, this->base, 0, MEM_RELEASE))
            ReportError(L"VirtualFreeEx"); 
    }

    operator LPVOID() { return base; }
};

int ReportError(LPCWSTR errStr)
{
    // Format the system error message and save pointer to it in errMsg
    if (errStr != nullptr)
    {
        LPWSTR errMsg;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                      nullptr,
                      GetLastError(),
                      0,
                      (LPWSTR)&errMsg,
                      0,
                      nullptr);
    
        // Output the error message and free its resources
        std::wcerr << errStr << ": " << errMsg << std::endl;
        LocalFree(errMsg);
    }

    // TODO: If want to portability, replace this with something else to get the
    // same pausing effect
    system("pause");

    return -1;
}

DWORD GetProcessID(LPCWSTR processName)
{
    // Get a snapshot of all the current processes on the system
    HandleManager processesSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processesSnap == INVALID_HANDLE_VALUE)
        return ReportError(L"GetProcessID");

    // Obtain the first process based on the snapshot
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(processesSnap, &processInfo))
        return ReportError(L"Process32First");

    // Iterate through all processes and find the one with matching name as arg 
    // without the extension
    DWORD processID = -1;
    do
    {
        if (!wcsncmp(processInfo.szExeFile, processName, wcslen(processInfo.szExeFile) - 3))
        {
            processID = processInfo.th32ProcessID;
            break;
        }
    }
    while (Process32Next(processesSnap, &processInfo));

    return processID;
}

int wmain(int argc, const wchar_t **argv)
{
    // Check command line arguments
    if (argc < 4)
    {
        std::wcerr << L"Invalid usage. Correct usage:\n" << argv[0] << L" <PROCESS> <load/unload> <DLL>\n";
        return ReportError(nullptr);
    }

    // Get the full file path to the DLL and size accounting for Unicode + null terminator
    LPWSTR dllName;
    WCHAR fullDllPath[MAX_PATH];
    if (!GetFullPathName(argv[3], sizeof fullDllPath / sizeof WCHAR, fullDllPath, &dllName))
    {
        std::wcerr << L"Could not find " << argv[3] << L'\n';
        return ReportError(nullptr);
    }
    std::wcerr << L"FUll path name: " << fullDllPath << std::endl;


    // Attempt to locate the process specified and get its ID
    DWORD processID = GetProcessID(argv[1]);
    if (processID == -1)
    {
        std::wcerr << L"Could not find process " << argv[1] << L'\n';
        return ReportError(nullptr);
    }

    // Get the handle to the OS process
    HandleManager remoteProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (remoteProcess == nullptr)
        return ReportError(L"OpenProcess");

    // Save the target's DLL path into the target process's address space
    ExternMemManager remoteDllPath(remoteProcess, fullDllPath, sizeof fullDllPath);

    // Get the start routine for the thread to execute
    LPTHREAD_START_ROUTINE onStart = nullptr;
    const char *onStartStr = nullptr;
    HMODULE kernelDllHandle = GetModuleHandle(L"kernel32");
    if (!wcsncmp(argv[2], L"load", sizeof L"load"))
        onStartStr = "LoadLibraryW";
    else if (!wcsncmp(argv[2], L"unload", sizeof L"unload"))
        onStartStr = "FreeLibrary";
    if (onStartStr == nullptr)
    {
        std::wcerr << L"Invalid option specified: " << argv[2] << L"\nShould be \"load\" or \"unload\"\n";
        return ReportError(nullptr);
    }

    // If valid option was specified, get the corresponding start routine from
    // kernel32.dll
    onStart = (LPTHREAD_START_ROUTINE)GetProcAddress(kernelDllHandle, onStartStr);
    if (onStart == nullptr)
        return ReportError(L"GetProcAddress");

    // Create a thread in target process, have it load the desired DLL
    // using LoadLibrary from kernel32.dll and the allocated file path for
    // the target DLL
    HandleManager remoteThread = CreateRemoteThread(remoteProcess, nullptr, 0, onStart, remoteDllPath, 0, nullptr);
    if (remoteThread == nullptr)
        return ReportError(L"CreateRemoteThread");

    // Wait for the thread in the target process to successfully load the dll
    if (WaitForSingleObject(remoteThread, INFINITE) == WAIT_FAILED)
        return ReportError(L"WaitForSingleObject");

    // Check result of error code
    DWORD remoteThreadResult;
    if (GetExitCodeThread(remoteThread, &remoteThreadResult) == FALSE)
        return ReportError(L"GetExitCodeThread");
    if (!remoteThreadResult)
    {
        std::cerr << onStartStr;
        std::wcerr << L" failed to " << argv[2] << L" " << dllName << L'\n';
        return ReportError(nullptr);
    }

    return 0;
}
