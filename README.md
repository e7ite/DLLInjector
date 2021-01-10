[![Build status](https://ci.appveyor.com/api/projects/status/lem2q5j6egp5g8x2?svg=true)](https://ci.appveyor.com/project/e7ite/dllinjector)

# DLLInjector
Simple Windows DLL Injector via command line. Creates a thread in the target process that calls LoadLibrary to load the DLL. Can load and unload DLLs.

## Usage
    DLLInjector.exe <PROCESS> <load/unload> <DLL>
  
## Build Instructions
1. Open DLLInjector.sln with Microsoft Visual Studio
2. Compile with Debug x86 or Release x86 mode
3. Run DLLInjector.exe with your terminal.
