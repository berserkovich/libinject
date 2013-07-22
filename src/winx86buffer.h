
static const unsigned char x86TemplateBuffer[] = 
{ 
    0x33, 0xC0,                         // xor eax, eax                     ; clear eax
    0x3C, 0x01,                         // cmp al, 1                        ; change to 0 for debugging
    0x75, 0x02,                         // jne 2                            ; jump over next instruction
    0xEB, 0xFE,                         // jmp eip                          ; infinite loop for debugging

    0xFC,                               // cld		                        ; clear the direction flag for the loop
    0x33, 0xD2,                         // xor edx, edx
    0x64, 0x8B, 0x52, 0x30,             // mov edx, dword ptr fs:[edx+30h]  ; get a pointer to the PEB
    0x8B, 0x52, 0x0C,                   // mov edx, dword ptr [edx+0Ch]     ; get PEB->Ldr
    0x8B, 0x52, 0x14,                   // mov edx, dword ptr [edx+14h]     ; get the first module from the InMemoryOrder module list
    // next_mod:
    0x8B, 0x72, 0x28,                   // mov esi, dword ptr [edx+28h]     ; get pointer to modules name (unicode string)
    0x6A, 0x18,                         // push 18h                         ; push down the length we want to check
    0x59,                               // pop ecx                          ; set ecx to this length for the loop
    0x33, 0xFF,                         // xor edi, edi                     ; clear edi which will store the hash of the module name
    // loop_modname:
    0x33, 0xC0,                         // xor eax, eax                     ; clear eax
    0xAC,                               // lods byte ptr [esi]              ; read in the next byte of the name
    0x3C, 0x61,                         // cmp al, 'a'                      ; some versions of Windows use lower case module names
    0x7C, 0x02,                         // jl not_lowercase
    0x2C, 0x20,                         // sub al, 20h                      ; if so normalise to uppercase
    // not_lowercase:
    0xC1, 0xCF, 0x0D,                   // ror edi, 0Dh                     ; rotate right our hash value
    0x03, 0xF8,                         // add edi, eax                     ; add the next byte of the name to the hash
    0xE2, 0xF0,                         // loop loop_modname                ; loop until we have read enough
    0x81, 0xFF, 0x5B, 0xBC, 0x4A, 0x6A, // cmp edi, 0x6A4ABC5B              ; compare the hash with that of KERNEL32.DLL
    0x8B, 0x5A, 0x10,                   // mov ebx, [edx+10h]               ; get this modules base address
    0x8B, 0x12,                         // mov edx, [edx]                   ; get the next module
    0x75, 0xDB,                         // jne next_mod                     ; if it doesn't match, process the next module
    0x8B, 0xC3,                         // mov eax, ebx                     ; store result in eax
	0x89, 0x45, 0x04,					// mov [ebp + 4], eax				; save kernel32.dll address to our variable
    0xEB, 0x4C,                         // jmp find_function_end

    // find_function_address:
    0x55,                               // push epb/rbp                     ; prologue
    0x54,                               // push esp/rsp
    0x8B, 0x6C, 0x24, 0x10,             // mov ebp, [esp + 0x10]
    0x8B, 0x55, 0x3C,                   // mov edx, [ebp + 0x3c]            ; Skip over the MSDOS header to the start of the PE header
    0x8B, 0x54, 0x15, 0x78,             // mov edx, [ebp + edx + 0x78]      ; The export table is 0x78 bytes from the start of the PE header. Extract it and store the relative address in edx.
    0x03, 0xD5,                         // add edx, ebp                     ; Make the export table address absolute by adding the base address to it.
    0x8B, 0x4A, 0x18,                   // mov ecx, [edx + 18h]             ; Extract the number of exported items and store it in ecx which will be used as the counter.
    0x8B, 0x5A, 0x20,                   // mov ebx, [edx + 20h]             ; Extract the names table relative offset and store it in ebx.
    0x03, 0xDD,                         // add ebx, ebp                     ; Make the names table address absolute by adding the base address to it.
    // find_function_loop:
    0xE3, 0x30,                         // jecxz find_function_finished     ; If ecx is zero then the last symbol has been checked
    0x49,                               // dec ecx
    0x8B, 0x34, 0x8B,                   // mov esi, [ebx + ecx * 4]         ; Extract the relative offset of the name associated with the current symbol and store it in esi.
    0x03, 0xF5,                         // add ebx, ebp                     ; Make the address of the symbol name absolute by adding the base address to it.
    0x33, 0xFF,                         // xor edi, edi                     ; zero edi
    0x33, 0xC0,                         // xor eax, eax                     ; zero eax
    0xFC,                               // cld
    // compute_hash_again:
    0xAC,                               // lodsb
    0x84, 0xC0,                         // test al, al
    0x74, 0x07,                         // jz compute_hash_finished
    0xC1, 0xCF, 0x0D,                   // ror edi, 0x0D
    0x03, 0xF8,                         // add edi, eax
    0xEB, 0xF4,                         // jmp compute_hash_again
    0x3B, 0x7C, 0x24, 0x0C,             // cmp edi, [esp+0x0C]
    0x75, 0xE1,                         // jnz find_function_loop
    0x8B, 0x5A, 0x24,                   // mov ebx, [edx + 24h]
    0x03, 0xDD,                         // add ebx, ebp
    0x66, 0x8B, 0x0C, 0x4B,             // mov cx, [ebx + 2 * ecx]
    0x8B, 0x5A, 0x1C,                   // mov ebx, [edx + 0x1C]
    0x03, 0xDD,                         // add ebx, ebp
    0x8B, 0x04, 0x8B,                   // mov eax, [ebx + 4 * ecx]
    0x03, 0xC5,                         // add eax, ebp                     ; eax has function address
    0x5C,                               // pop esp/rsp                      ; epilogue
    0x5D,                               // pop ebp/rbp
    0xC3,                               // ret
    // find_function_end:

    // Get LoadLibraryW address
    0x50,                               // push eax                         ; kernel32Addr in EAX
    0x68, 0xA4, 0x4E, 0x0E, 0xEC,       // push 0xEC0E4EA4                  ; LoadLibraryW hash
    0xE8, 0xA9, 0xFF, 0xFF, 0xFF,       // call find_function_address
	0x89, 0x45, 0x08,					// mov [ebp + 8], eax				; save LoadLibraryW address to our variable
    0x83, 0xC4, 0x04,                   // add esp, 0x04                    ; restore stack

    //// Get GetProcAddress address
    0x68, 0xAA, 0xFC, 0x0D, 0x7C,       // push 0x7C0DFCAA                  ; GetProcAddress hash
    0xE8, 0x99, 0xFF, 0xFF, 0xFF,       // call find_function_address
    0x83, 0xC4, 0x08,                   // add esp, 0x08                    ; restore stack
	0x89, 0x45, 0x0C,					// mov [ebp + C], eax				; save GetProcAddress address to our variable

	//// Get GetLastError address
	0x8B, 0xD5,							// mov edx, ebp						; 
	0x83, 0xC2, 0x18,					// add edx, 0x18					; get pointer to 'GetLastError' 
	0x52,								// push edx							; push 'GetLastError' address
	0xFF, 0x75, 0x04,					// push [ebp + 4]					; push kernel32.dll address
	0x8B, 0x45, 0x0C,					// mov eax, [ebp + C]				; get 'GetProcAddress' pointer
	0xFF, 0xD0,							// call eax							; call 'GetProcAddress'
	0x89, 0x45, 0x10,					// mov [ebp + 10], eax				; save GetLastError address to our variable

    //// Injected dll loading.
    0x8B, 0x45, 0x08,                   // mov eax, [ebp + 8]               ; Move the address of LoadLibraryW into EAX
	0x8B, 0xD5,							// mov edx, ebp
    0x83, 0xC2, 0x28,                   // add edx, 28h                     ; get pointer to injected dll name
    0x52,                               // push edx                         ; push injected dll name address into stack
    0xFF, 0xD0,                         // call eax                         ; Call LoadLibraryW
	0x89, 0x45, 0x14,					// mov [ebp + 0x14], eax			; save injected DLL's module address to our variable
	0x8B, 0x45, 0x10,                   // mov eax, [ebp + 10]               ; Move the address of GetLastError into EAX
    0xFF, 0xD0,                         // call eax                         ; Call GetLastError
	0x89, 0x45, 0x00,					// mov [ebp], eax					; save last error to our variable

    0xEB, 0xFE,                         // jmp eip                          ; infinite loop for signaling end of routine
    
};

static const unsigned char x86TemplateBufferData[] = 
{
    // data
	0x00, 0x00, 0x00, 0x00,																									// last error
    0x00, 0x00, 0x00, 0x00,                                                                                                 // kernel32.dll address
    0x00, 0x00, 0x00, 0x00,                                                                                                 // LoadLibraryW address
    0x00, 0x00, 0x00, 0x00,                                                                                                 // GetProcAddress address
    0x00, 0x00, 0x00, 0x00,                                                                                                 // GetLastError address
    0x00, 0x00, 0x00, 0x00,                                                                                                 // injected DLL's module address
    'G','e','t','L','a','s','t','E','r','r','o','r','\0', 0x00, 0x00, 0x00,                                                 // "GetLastError"
};
