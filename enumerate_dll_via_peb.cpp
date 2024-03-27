#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <wchar.h>
#include <stdio.h>
#include <iostream>
#include "undocumented.h"
#include <cstdio>



//ridefinisco la funzione NtQueryInformationProcess perche' da problemi di linking e si puo' usare solo a runtime
typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    IN  HANDLE ProcessHandle,
    IN  PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN  ULONG ProcessInformationLength,
    OUT PULONG ReturnLength    OPTIONAL
    );





pfnNtQueryInformationProcess gNtQueryInformationProcess;


HMODULE sm_LoadNTDLLFunctions()
{
    // Load NTDLL Library and get entry address

    // for NtQueryInformationProcess

    HMODULE hNtDll = LoadLibrary((LPCSTR)"ntdll.dll");
    if(hNtDll == NULL) return NULL;

    gNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll,
                                                        "NtQueryInformationProcess");
    if(gNtQueryInformationProcess == NULL) {
        FreeLibrary(hNtDll);
        return NULL;
    }
    return hNtDll;
}

//funzione che restituisce il PID di un processo dato il nome
int get_process_id(const char *procname) {

  HANDLE hSnapshot;
  PROCESSENTRY32 pe;
  int pid = 0;
  BOOL hResult;

  // snapshot of all processes in the system
  hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

  // initializing size: needed for using Process32First
  pe.dwSize = sizeof(PROCESSENTRY32);

  // info about first process encountered in a system snapshot
  hResult = Process32First(hSnapshot, &pe);

  // retrieve information about the processes
  // and exit if unsuccessful
  while (hResult) {
    // if we find the process: return process ID
    if (strcmp(procname, (const char*)pe.szExeFile) == 0) {
      pid = pe.th32ProcessID;
      break;
    }
    hResult = Process32Next(hSnapshot, &pe);
  }

  // closes an open handle (CreateToolhelp32Snapshot)
  CloseHandle(hSnapshot);
  return pid;
}

//function that enumerates modules attached to a process given an handle to the process
void enumerate_dll_via_peb(HANDLE process){

    //i utilize custom structures since many fields of the original one are undocumented
    //check undocumented.h
    PEB peb ;
    PROCESS_BASIC_INFORMATION pbi;
    _PEB_LDR_DATA_2 ldr;
    printf("prima di sm_LoadNTDLLFunctions\n");

    sm_LoadNTDLLFunctions();
    printf("prima di NtQueryInformationProcess\n");
    printf("%x\n", gNtQueryInformationProcess);

    //Sarebbe bello usare NtQueryInformationProcess ma Microsoft e' infame e dobbiamo linkarla a runtime: https://stackoverflow.com/questions/7051558/ntqueryinformationprocess-wont-work-in-visual-studio-2010
    //NtQueryInformationProcess(process, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr); //prendo informazioni sul processo e le metto in pbi
    //Use NtQueryInformationProcess to get the PROCESS_BASIC_INFORMATION from where i get the PEB base address
    gNtQueryInformationProcess(process, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), nullptr); //prendo informazioni sul processo e le metto in pbi
    printf("PBI: %p\n", pbi.PebBaseAddress);


    //save peb base address in peb struct
    ReadProcessMemory(process, (LPCVOID)pbi.PebBaseAddress, &peb,sizeof(PEB), nullptr); //leggo dalla memoria del processo la struct pbi e metto in peb il base address del PeB
    printf("PEB: %p\n", pbi.PebBaseAddress);


    //get ldr field from peb struct
    ReadProcessMemory(process, (LPCVOID)peb.Ldr, &ldr, sizeof(_PEB_LDR_DATA_2), nullptr); //leggo dalla memoria del processo la struct peb e metto in ldr il base address del Ldr
    printf("LDR: %p\n", peb.Ldr);



    //this is some serious fucked up stuff lol
    LIST_ENTRY *head = (LIST_ENTRY *)ldr.InLoadOrderModuleList.Flink;
    LIST_ENTRY *current = ldr.InLoadOrderModuleList.Flink;

    Sleep(1000);

    //iterate the list of loaded modules until i get to the last
    do
    {   
        _LDR_DATA_TABLE_ENTRY_2 lstEntry = { 0 };
        //LDR_DATA_TABLE_ENTRY dte = *head_tmp;

        ReadProcessMemory(process, (LPCVOID)current, &lstEntry,sizeof(_LDR_DATA_TABLE_ENTRY_2), nullptr);
        
        UNICODE_STRING dll_name; 
        //go to the next node
        current = lstEntry.InLoadOrderLinks.Flink;

		WCHAR strFullDllName[MAX_PATH] = { 0 };

        ReadProcessMemory(process, (LPCVOID)lstEntry.FullDllName.Buffer, &strFullDllName,lstEntry.FullDllName.Length, nullptr);
        
        wprintf(L"Dll Name: %s, \nDll Base: %pEntry point: %p\n\nSize of Image: %X\n", strFullDllName,lstEntry.DllBase, lstEntry.EntryPoint, lstEntry.SizeOfImage);


        Sleep(200);
    }while (head != current);
}

//function literally equal to the enumerate one but returns the base address of a module given its name 
PVOID get_module_address(HANDLE process, const char *module_name) {

    PEB peb ;
    PROCESS_BASIC_INFORMATION pbi;
    _PEB_LDR_DATA_2 ldr;
    printf("prima di sm_LoadNTDLLFunctions\n");

    sm_LoadNTDLLFunctions();
    printf("prima di NtQueryInformationProcess\n");
    printf("%x\n", gNtQueryInformationProcess);

    //Sarebbe bello usare NtQueryInformationProcess ma Microsoft e' infame e dobbiamo linkarla a runtime: https://stackoverflow.com/questions/7051558/ntqueryinformationprocess-wont-work-in-visual-studio-2010
    //NtQueryInformationProcess(process, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr); //prendo informazioni sul processo e le metto in pbi
    gNtQueryInformationProcess(process, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), nullptr); //prendo informazioni sul processo e le metto in pbi
    printf("PBI: %p\n", pbi.PebBaseAddress);

    //Sleep(2000);

    ReadProcessMemory(process, (LPCVOID)pbi.PebBaseAddress, &peb,sizeof(PEB), nullptr); //leggo dalla memoria del processo la struct pbi e metto in peb il base address del PeB
    printf("PEB: %p\n", pbi.PebBaseAddress);

    //Sleep(2000);


    ReadProcessMemory(process, (LPCVOID)peb.Ldr, &ldr, sizeof(_PEB_LDR_DATA_2), nullptr); //leggo dalla memoria del processo la struct peb e metto in ldr il base address del Ldr
    printf("LDR: %p\n", peb.Ldr);

    //Sleep(2000);

    LIST_ENTRY *head = (LIST_ENTRY *)ldr.InLoadOrderModuleList.Flink;
    LIST_ENTRY *current = ldr.InLoadOrderModuleList.Flink;

    Sleep(1000);

    do
    {   
        _LDR_DATA_TABLE_ENTRY_2 lstEntry = { 0 };
        //LDR_DATA_TABLE_ENTRY dte = *head_tmp;

        ReadProcessMemory(process, (LPCVOID)current, &lstEntry,sizeof(_LDR_DATA_TABLE_ENTRY_2), nullptr);
        
        UNICODE_STRING dll_name; 
        current = lstEntry.InLoadOrderLinks.Flink;

		WCHAR strFullDllName[MAX_PATH] = { 0 };

        ReadProcessMemory(process, (LPCVOID)lstEntry.FullDllName.Buffer, &strFullDllName,lstEntry.FullDllName.Length, nullptr);
        
        if(!wcscmp(strFullDllName, (WCHAR *)module_name)){
            return lstEntry.DllBase;
        }

        Sleep(50);
    }while (head != current);
}



int main(){
    int pid;
    pid = get_process_id("notepad.exe");

    printf("PID: %d\n", pid);

    if(pid == 0){
        printf("Process not found\n");
        Sleep(5000);
        return 1;
    }
    printf("Prima di OpenProcess\n");

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    printf("Dopo di OpenProcess\n");

//ucrtbase.dll
    //enumerate_dll_via_peb(process);
    PVOID module_base = get_module_address(process, "ucrtbase.dll");
    printf("Module base: %p\n", module_base);

    Sleep(5000);
    return 0;
}