Volatility Plugin - Hushsum
Created by Eliad Mualem
Hashsum purpose is to identify similar code flows in memory and unite them to a single flow that can be investigated one time.



Installation 
To install this plugin just put the script in the volatility plugin folder located in:
{Volatility-folder}\volatility\plugins

to run just use his name:
C:\Python27\python.exe .\vol.py -f MEMORY_DUMP hashsum

Code Sources
Hashsum gets his code flows by going though the VadTree structure of every process and scans only the executable pages
It also uses the apihooks module results and takes the last disassembly made by apihooks

Hashsum flow
Hashsum uses distorm3 to disassemble the code and then uses MD5 hash on the readable commands after omitting the numbered parameters, for example:

0x6f0c3cb8 488bc4                           MOV RAX, RSP
0x6f0c3cbb 57                               PUSH RDI
0x6f0c3cbc 4881ecd0000000                   SUB RSP, 0xd0
0x6f0c3cc3 48c7442420feffffff               MOV QWORD [RSP+0x20], 0xfffffffe
0x6f0c3ccc 48895808                         MOV [RAX+0x8], RBX
0x6f0c3cd0 488bf9                           MOV RDI, RCX
looking at the first line, the plugin will split the commands with spaces:

['MOV', 'RAX', 'RSP']
now the plugin will go through each part of the command and if it does not contain a numerical parameter it will add it to a string

hash_string = 'MOVRAXRSP'
for the third line it will create this string:

['SUB', 'RSP', '0xd0']
hash_string = 'SUBRSP' ('0xd0' is a numerical parameter so it won't be added)
the omitting of numerical parameters is done to prevent an option which a similar code flows that uses a different parameters will still be united to a single flow.

Hashsum will do it for each line until finally our hash string will be: (I'v added spaces between commands so it will be easier to understand)

hash_string = 'MOV RAX RSP PUSH RDI SUB RSP MOV QWORD MOV RBX MOV RDI RCX'
Then it saves the MD5 hash of the string to a dictionary which saves all the appearances of the same hash and display it to the user

Understanding the output
The output is written in this structure:

------------------
source hash total_appearances
process_name appearances list
process_name appearances list
process_name appearances list
...
...
 
disassembled_code
------------------
source - the source of this code flow (VadTree or Apihooks)

hash - the MD5 hash

total_appearances - the total number of appearances for this hash

process_name - the process name

appearances - the total number of appearances for this hash in this specific process

list - a list containing the pid and addresses for the code flow in that process (maximum of 3)

disassembled_code - the disassembled code of the flow



An output example:

--------------------
VadTree 0ee09cf34207ff4515d7f79012f485c4 3
sqlwriter.exe 1 [(4324, 13959168L)]
cmd.exe 2 [(4216, 177143808L), (8124, 177143808L)]
 
0xd50000L           e9db2ded73          JMP 0x74c22de0
0xd50005L           4883ec28            SUB RSP, 0x28
0xd50009L           e83aa2d4ff          CALL 0xa9a248
0xd5000eL           e9129dd4ff          JMP 0xa99d25
0xd50013L           0000                ADD [RAX], AL
0xd50015L           0000                ADD [RAX], AL
0xd50017L           00                  DB 0x0
--------------------
