    [BITS 64]

    global   _start
    section  .text

_start:
    mov   rdi,   buffer
    mov   rsi,   something
    mov   ecx,   something_len
    rep   movsb

    mov   rsi,   otherthing
    mov   ecx,   otherthing_len
    rep   movsb

    mov   eax,   1
    xchg  rsi,   rdi
    mov   edi,   1
    mov   edx,   something_len + otherthing_len
    syscall

    mov   eax,   0x3C
    xor   edi,   edi
    syscall

    section  .data
something: db "this is a string", 0x0A
something_len equ $ - something

    section  .rodata
otherthing: db "this is an other string", 0x0A
otherthing_len equ $ - otherthing

    section  .bss
buffer: resb 256
