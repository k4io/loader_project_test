// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <process.h>
#include <iostream>
#include <Windows.h>

void OnEntry()
{
    Beep(5000, 50);

    system("start \"\" \"https://www.youtube.com/watch?v=dQw4w9WgXcQ\"");
}

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //MessageBox(GetActiveWindow(), L"Attached", L"Worked bitch JAY IS GAY :)", 0);
        //system("start \"\" \"https://www.youtube.com/watch?v=dQw4w9WgXcQ\"");
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)OnEntry, 0, 0, 0);
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

