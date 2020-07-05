extern _getProcessID
extern _getProcessHandle
extern _getProcessBase
extern _wpm
extern _closeProcessHandle

section .text
    _start:
        ; get process ID
        mov edx, 0xF7998463
        call _getProcessID

        push eax

        ; get process handle
        mov edx, eax
        call _getProcessHandle

        pop ebx
        push eax

        ; get process base
        mov edx, 0xF7998463
        call _getProcessBase

        ; write process memory
        mov ebx, 0x20A23C
        add ebx, eax
        mov eax, 5
        pop edx
        push word 0x9000
        push word 0x0006
        push word 0x79E9
        call _wpm

        ; close process handle
        mov edx, eax
        call _closeProcessHandle

        ret
