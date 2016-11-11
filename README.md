# SysSec
SysSec coursework


exploit in shell.txt
to generate bin input
xdd -p -r shell.txt > badfile

exploit overwites 24B of buffer space 8B of extra untill saved ebp 4B ebp and then overwrites the saved return address followed by nop sled and shellcode
at ret instruction %esp points at ret pointer and nop sled should begin at %esp+4 in gdb %esp+4 = 0xbffff4d0 / without it gdb it should be higher
exploit jumps to 0xbffff5c0


for setting uid to 0 use shell-suid.txt 
it prepends the shellcode with
xor %ebx, %ebx
xor %eax, %eax
mov %al , 0x17
int 0x80

