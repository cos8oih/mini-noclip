; HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
; BOOL Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
; BOOL Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
; HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
; BOOL Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
; BOOL Module32Next(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
; BOOL VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
; BOOL WriteProcessMemory(HANDLE hProcess,LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
; BOOL CloseHandle(HANDLE hObject);

global _getProcessID
global _getProcessHandle
global _getProcessBase
global _wpm
global _closeProcessHandle

section .text

    ; return kernel32 base in ebx
    _winapiInit:
        mov eax, [fs:30h]
        mov eax, [eax + 0xC]
        mov eax, [eax + 0xC]
        mov eax, [eax]
        mov eax, [eax]
        mov ebx, [eax + 0x18]
        ret

    ; null terminated string expected in esi
    ; return hash in eax
    _doHash:
        push ecx
        xor eax, eax

        .hashing:
        movzx ecx, byte [esi]
        test ecx, ecx
        je .finish
        add eax, ecx
        rol eax, 27
        inc esi
        jmp .hashing

        .finish:
        pop ecx
        ret

    ; base address expected in ebx
    ; hash expected in edx
    ; return pointer in eax
    _getFunctionPointer:
        push ebx
        push ecx
        push esi
        push edi

        call _winapiInit

        ; get export table
        mov eax, [ebx + 0x3C]
        mov eax, [ebx + eax + 0x78]
        add eax, ebx
        mov ecx, eax

        ; get address of functions
        mov eax, [ecx + 0x1C]
        add eax, ebx
        push eax

        ; get address of names
        mov eax, [ecx + 0x20]
        add eax, ebx
        push eax

        ; get address of ordinals
        mov eax, [ecx + 0x24]
        add eax, ebx
        push eax

        ; get number of names
        mov ecx, [ecx + 0x18]
        dec ecx

        .loopNames:
        ; hash name
        mov esi, [esp + 0x4]
        mov esi, [esi + ecx * 0x4]
        add esi, ebx
        call _doHash

        ; compare hashes
        cmp eax, edx
        je .foundMatch
        loop .loopNames
        xor eax, eax
        jmp .finish

        .foundMatch:
        mov edi, [esp]
        mov di, [edi + ecx * 0x2]
        and edi, 0xFFFF
        mov eax, [esp + 8]
        mov eax, [eax + edi * 0x4]
        add eax, ebx

        .finish:
        add esp, 0xC
        pop edi
        pop esi
        pop ecx
        pop ebx
        ret

    ; hashed exe name expected in edx
    ; return handle expected in eax
    _getProcessID:
        push ebx
        push ecx
        mov ebx, edx
        sub esp, 0x128
        mov [esp], dword 0x128

        ; create snapshot
        mov edx, 0x714A215B
        call _getFunctionPointer

        push 0
        push 2
        call eax

        mov ecx, eax

        ; find process id
        mov edx, 0xD45CC0FC
        call _getFunctionPointer

        mov edx, esp
        push ecx
        push edx
        push ecx
        call eax
        pop ecx

        mov edx, 0x95109F26
        call _getFunctionPointer
        mov edi, eax

        .checkProcess:
        mov esi, esp
        add esi, 0x24
        call _doHash
        cmp eax, ebx
        je .foundProcess

        mov edx, esp
        push ecx
        push edx
        push ecx
        call edi
        pop ecx

        cmp eax, 0
        je .finish
        jmp .checkProcess
        
        .foundProcess:
        mov eax, [esp + 0x8]

        .finish:
        add esp, 0x128
        pop ecx
        pop ebx
        ret

    ; process id expected in edx
    ; return in eax
    _getProcessHandle:
        push edx

        mov edx, 0x26D50756
        call _getFunctionPointer

        push 0
        push 0x1FFFFF
        call eax

        ret

    ; process id expected in ebx
    ; hashed exe name expected in edx
    _getProcessBase:
        push esi
        sub esp, 0x224
        mov [esp], dword 0x224
        push ebx
        mov ebx, edx

        ; create snapshot
        mov edx, 0x714A215B
        call _getFunctionPointer

        push 8
        call eax

        mov ecx, eax

        ; find process base
        mov edx, 0x628C2E9
        call _getFunctionPointer

        mov edx, esp
        push ecx
        push edx
        push ecx
        call eax
        pop ecx

        mov edx, 0xCE90DCAC
        call _getFunctionPointer
        mov edi, eax

        .checkProcess:
        mov esi, esp
        add esi, 0x20
        call _doHash
        cmp eax, ebx
        je .foundProcess

        mov edx, esp
        push ecx
        push edx
        push ecx
        call edi
        pop ecx

        cmp eax, 0
        je .finish
        jmp .checkProcess
        
        .foundProcess:
        mov eax, [esp + 0x1C]

        .finish:
        add esp, 0x224
        pop esi
        ret

    ; size in eax
    ; address in ebx
    ; handle in edx
    ; bytes in stack
    _wpm:
        mov edi, esp
        add edi, 4
        mov esi, eax
        push edx

        ; write to process
        mov edx, 0x5E934ED0
        call _getFunctionPointer

        pop edx

        push 0
        push esi
        push edi
        push ebx
        push edx
        call eax

        ret

    ; handle expected in edx
    _closeProcessHandle:
        push edx
        
        mov edx, 0x5A6297B0
        call _getFunctionPointer

        call eax

        ret