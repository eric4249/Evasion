#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

// --- 1. 定義所有的函數指標類型 ---
typedef FARPROC(WINAPI* fn_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef LPVOID(WINAPI* fn_VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI* fn_VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef HANDLE(WINAPI* fn_CreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

/**
 * 簡單的 XOR 加解密函數
 */
void xor_encrypt_decrypt(unsigned char* data, size_t data_len, const char* key) {
  size_t key_len = strlen(key);
  for (size_t i = 0; i < data_len; i++) {
    data[i] ^= key[i % key_len];
  }
}

/**
 * 手動解析 EAT (Export Address Table) 獲取函數位址
 * 使用 SEH (__try/__except) 保護，防止非法記憶體存取導致崩潰
 */
FARPROC GetSymbolAddress(HMODULE hModule, const char* targetName) {
  PBYTE base = (PBYTE)hModule;

  // 使用結構化異常處理 (SEH) 保護記憶體讀取過程
  __try {
    // 1. 獲取 DOS Header 並驗證標誌
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
      return NULL;
    }

    // 2. 獲取 NT Headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);

    // 3. 定位導出表目錄 (Export Directory)
    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) {
      return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(base + exportDirRVA);

    // 4. 獲取名稱、位址、序號三個關鍵陣列的起點
    PDWORD names = (PDWORD)(base + exportDir->AddressOfNames);
    PDWORD functions = (PDWORD)(base + exportDir->AddressOfFunctions);
    PWORD ordinals = (PWORD)(base + exportDir->AddressOfNameOrdinals);

    // 5. 遍歷名稱陣列進行比對
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
      char* name = (char*)(base + names[i]);
      if (strcmp(name, targetName) == 0) {
        // 透過序號表 (Ordinal Table) 找到對應的函數位址索引
        // 注意：functions 陣列的索引是從 ordinals 陣列取出的值
        return (FARPROC)(base + functions[ordinals[i]]);
      }
    }
  }
  __except (EXCEPTION_EXECUTE_HANDLER) {
    // 如果發生 Access Violation (例如 hModule 是無效位址)，會跳到這裡
    return NULL;
  }

  return NULL;
}

int main() {
  const char* key = "secret";

  // --- 3. 準備加密後的字串 ---
  // "GetProcAddress"
  unsigned char v_gpa[] = { 0x31, 0x00, 0x17, 0x12, 0x17, 0x08, 0x05, 0x27, 0x02, 0x02, 0x14, 0x03, 0x15, 0x15, 0x00 };
  // "VirtualAlloc"
  unsigned char v_alloc[] = { 0x25, 0x0C, 0x11, 0x06, 0x10, 0x15, 0x1F, 0x24, 0x0F, 0x1E, 0x0A, 0x17, 0x00 };
  // "VirtualProtect"
  unsigned char v_prot[] = { 0x25, 0x0C, 0x11, 0x06, 0x10, 0x15, 0x1F, 0x35, 0x11, 0x1D, 0x11, 0x11, 0x10, 0x11, 0x00 };
  // "CreateThread"
  unsigned char c_thread[] = { 0x30, 0x17, 0x06, 0x13, 0x11, 0x11, 0x27, 0x0D, 0x11, 0x17, 0x04, 0x10, 0x00 };

  // --- 4. 解密 GetProcAddress 字串並獲取位址 ---
  xor_encrypt_decrypt(v_gpa, sizeof(v_gpa) - 1, key);

  HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
  if (hKernel32 == NULL) return -1;

  // 使用自定義函數獲取 GetProcAddress 位址
  fn_GetProcAddress pDynamicGPA = (fn_GetProcAddress)GetSymbolAddress(hKernel32, (char*)v_gpa);

  if (pDynamicGPA != NULL) {
    // 解密剩餘的 API 名稱
    xor_encrypt_decrypt(v_alloc, sizeof(v_alloc) - 1, key);
    xor_encrypt_decrypt(v_prot, sizeof(v_prot) - 1, key);
    xor_encrypt_decrypt(c_thread, sizeof(c_thread) - 1, key);

    // 透過 pDynamicGPA 獲取其餘函數指標
    fn_VirtualAlloc new_VAlloc = (fn_VirtualAlloc)pDynamicGPA(hKernel32, (LPCSTR)v_alloc);
    fn_VirtualProtect new_VProtect = (fn_VirtualProtect)pDynamicGPA(hKernel32, (LPCSTR)v_prot);
    fn_CreateThread new_create_thr = (fn_CreateThread)pDynamicGPA(hKernel32, (LPCSTR)c_thread);

    if (new_VAlloc && new_VProtect && new_create_thr) {
      printf("[+] Successfully resolved all functions dynamically!\n");
      // 在此處可以使用解析出來的函數進行後續操作，例如 Shellcode 注入
    } else {
      printf("[-] Failed to resolve one or more functions.\n");
    }
  } else {
    printf("[-] Could not find GetProcAddress address.\n");
  }

  return 0;
}
