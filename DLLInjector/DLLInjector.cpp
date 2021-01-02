// I dont intend for this to be portable, so will use Windows specific protocols

#include <iostream>
#include <cwchar>
#include <windows.h>
#include <tlhelp32.h>

template <typename ...Handles>
void GetErrorInfo(LPCWSTR errStr, Handles ...toFree)
{
    // Format the system error message and save pointer to it in errMsg
    LPWSTR errMsg;
    va_list args;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                  nullptr,
                  GetLastError(),
                  0,
                  (LPWSTR)&errMsg,
                  0,
                  nullptr);
    
    // Output the error message and free its resources
    std::cerr << errStr << ": " << errMsg << std::endl;
    LocalFree(errMsg);

    // TODO: Close all handles in variadic argument pack toFree
}

DWORD GetProcessID(LPCWSTR processName)
{
    // Get a snapshot of all the current processes on the system
    HANDLE processesSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processesSnap == INVALID_HANDLE_VALUE)
        GetErrorInfo(L"GetProcessID");

    // Obtain the first process based on the snapshot
    PROCESSENTRY32 processInfo;
    if (!Process32First(processesSnap, &processInfo))
    {
        GetErrorInfo(L"Process32First");
        CloseHandle(processesSnap);
        return -1;
    }

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

    CloseHandle(processesSnap);
    return processID;
}

int wmain(int argc, const wchar_t **argv)
{
    // Check command line arguments
    if (argc < 4)
    {
        std::wcerr << L"Invalid usage. Correct usage:\n" << argv[0] << L" <PROCESS> <load/unload> <DLL>\n";
        system("pause");    
        exit(EXIT_FAILURE);
    }

    // Get the full file path to the DLL
    TCHAR dllPath[MAX_PATH];
    DWORD dllPathLen = GetFullPathName(argv[3], sizeof dllPath, dllPath, nullptr);
    if (!dllPathLen)
    {
        std::wcerr << L"Could not find " << argv[3] << L'\n';
        system("pause");
        exit(EXIT_FAILURE);
    }

    // Attempt to locate the process specified and get its ID
    DWORD processID = GetProcessID(argv[2]);
    if (processID == -1)
    {
        std::wcerr << L"Could not find process " << argv[0] << L'\n';
        system("pause");    
        exit(EXIT_FAILURE);
    }

    // Get the handle to the OS process
    HANDLE remoteProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                                       PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                       PROCESS_VM_READ,
                                       FALSE,
                                       processID);
    if (remoteProcess == nullptr)
    {
        GetErrorInfo(L"OpenProcess");
        system("pause");
        exit(EXIT_FAILURE);
    }

    // Allocate space for the target dll's full path into the target processes's
    // address space.
    LPVOID remoteDllPath = VirtualAllocEx(remoteProcess,
                                          nullptr,
                                          dllPathLen + 1,
                                          MEM_RESERVE | MEM_COMMIT,
                                          PAGE_READONLY);
    if (remoteDllPath == nullptr)
    {
        GetErrorInfo(L"VirtualAllocEx");
        system("pause");
        CloseHandle(remoteProcess);
        exit(EXIT_FAILURE);
    }

    // Write the dll's full path into this new memory region
    if (!WriteProcessMemory(remoteProcess, remoteDllPath, dllPath, dllPathLen + 1, nullptr))
    {
        GetErrorInfo(L"WriteProcessMemory");
        system("pause");
        CloseHandle(remoteProcess);
        exit(EXIT_FAILURE);
    }

    // Get the start routine for the thread to execute
    LPTHREAD_START_ROUTINE onStart = nullptr;
    const char *onStartStr = nullptr;
    HMODULE kernelDllHandle = GetModuleHandle(L"kernel32");
    if (!wcsncmp(argv[1], L"load", sizeof L"load"))
        onStartStr = "LoadLibraryW";
    else if (!wcsncmp(argv[1], L"unload", sizeof L"unload"))
        onStartStr = "FreeLibrary";
    else
        std::cerr << L"Invalid option\n";

    onStart = (LPTHREAD_START_ROUTINE)GetProcAddress(kernelDllHandle, onStartStr);

    if (onStartStr == nullptr)
        std::wcerr << L"Invalid option specified: " << argv[1] << L'\n';
    else if (onStart == nullptr)
        GetErrorInfo(L"GetProcAddress");

    // Create a thread in target process, have it load the desired DLL
    // using LoadLibrary from kernel32.dll and the allocated file path for
    // the target DLL
    HANDLE loadDllThread = CreateRemoteThread(remoteProcess, nullptr, 0, onStart, remoteDllPath, 0, nullptr);
    if (loadDllThread == nullptr)
    {
        GetErrorInfo(L"CreateRemoteThread");
        system("pause");
        exit(EXIT_FAILURE);
    }

    // Wait for the thread in the target process to successfully load the dll
    if (WaitForSingleObject(loadDllThread, INFINITE) == WAIT_FAILED)
    {
        GetErrorInfo(L"WaitForSingleObject");
        system("pause");
        CloseHandle(remoteProcess);
        exit(EXIT_FAILURE);
    }
        
    // Free the allocated dll path from the remote process
    if (!VirtualFreeEx(remoteProcess, remoteDllPath, 0, MEM_RELEASE))
    {
        GetErrorInfo(L"VirtualFreeEx");
        system("pause");
        CloseHandle(remoteProcess);
        exit(EXIT_FAILURE);
    }

    remoteDllPath = nullptr;
    CloseHandle(loadDllThread);
    CloseHandle(remoteProcess);

    return 0;
}
