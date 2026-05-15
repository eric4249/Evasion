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
        // 透過序號陣列找到對應的函數位址索引
        DWORD functionOffset = functions[ordinals[i]];
        
        // 檢查是否為 Forwarder RVA (指向另一個 DLL 的導出)
        if (functionOffset >= exportDirRVA && functionOffset < (exportDirRVA + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)) {
          // 本範例簡化處理，不實現 Forwarder 解析
          return NULL; 
        }
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


// PBYTE base = (PBYTE)hModule;這句是用於定位某個dll, 比如kernel32.dll/user32.dll的virtual memory地址(即指針), 至於為何型別使用PBYTE, 它其實相當於char*, 是因為windows底層最少移動單位是1個byte

// 要點: 各個exe加載進memory後, 變成process, 有不同的base位置, 各個process的主base, 即exe base的位置是不同的, 但再加載dll, 比如kernel32.dll/user32.dll, 這些附屬的base, 即dll base的位置, 各個process是一樣的, 不同process共取dll base的位置, 使OS高效, 也使隱藏GetProcAddress, 即將其自定義, 變得可能

// PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;

// 這個是把base化為PIMAGE_DOS_HEADER這個型別, 至於它的型別為何有"DOS"這個字眼, 是因為dll它其實真的是在DOS年代一路發展出來的

// if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { return NULL; }

// 這個是如果找到的這個謂dosHeader沒有e_magic這個實際上是"MZ"這個代表microsoft初代工程師名字的字眼, 就是找錯地方了, 這個不是dll的base, 即入口地址

// PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);

// 這個是為了用base + (dosHeader->e_lfanew), 即base+各個dll不同, 但恒久的偏移量e_lfanew, 跳過所有DOS年代遺留的老古董, 跳到現代dll的可執行位置, 就是這裏以PIMAGE_NT_HEADERS作為型別的ntHeaders

// DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

// if (exportDirRVA == 0) { return NULL; }

// 這個是用"base + e_lfanew這個偏移量"這種方式, 找出的指針ntHeaders, 直接用->在指針所指的空間取出OptionalHeader這個struct中的, 叫DataDirectory的array中的第0個中以DWORD為型別的VirtualAddress, 它是一個偏移量, 用以從base開始數起, "exportDirRVA"個byte的距離, 便可取得exportDir這個可用來找到某個(比如kernel32.dll)所有winapi function位置的struct的pointer, 即base+exportDirRVA, 便可找到exportDir這個struct的pointer

// 要點: 絕大多數偏移量都是用於由base算起, 即以base為源頭, 找到某東西

// PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(base + exportDirRVA);這是真正找到這個叫exportDir的struct

// PDWORD names = (PDWORD)(base + exportDir->AddressOfNames);

// 比如這個, 其實我覺得PDWORD names = (PDWORD)((base + exportDir)->AddressOfNames);更為恰當, 它取出由base+exportDir偏移量算出的memory addr(是個pointer), 從pointer所指的房間直接用->取出一個array, 這個array中載有各個指向不同kernel32.dll的winapi function的偏移量, 用base+這些偏移量, 便可找出載有這些winapi function name的房間的指針, 在for loop解指針後, 即可取出這些winapi function的名字

// 要點: 找到名字的排位, 比如VirtualAlloc是array的第10個, 便到ordinals的第10個中找出VirtualAlloc這function, 在functions這個載有真實winapi function address的array中找出排位的, 比如在ordinals的第10個讀到數字1058, 便在functions這個array中的第1058個中找到VirtualAlloc的真實地址, return (FARPROC)(base + functions[ordinals[i]]);這句便是這個意思
