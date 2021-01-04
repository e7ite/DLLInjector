# DllInjector
Simple Windows DLL Injector via command line. Creates a thread in the target process, which calls LoadLibrary to load the DLL. Can load and unload DLLs.

## Usage
  -DLLInjector.exe <PROCESS> <load/unload> <DLL>
  
## Build Instructions
1. Open DLLInjector.sln with Microsoft Visual Studio
2. Compile with Debug x86 or Release x86 mode
3. Run DLLInector.exe with your terminal.
