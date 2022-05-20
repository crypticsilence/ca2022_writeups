# rev_omega_one

I'll admit, I am not amazing at reverse engineering, but got lucky working hard poking through the file.  I noticed a data structure and guessed what it was doing for this one.

Loaded the binary up in Ghidra to sort through what it was doing, noticed this interesting part:

```
                             s_Lendrens_00102140                             XREF[1]:     FUN_00100b4c:00100b74(*)  
        00102140 4c 65 6e        ds         "Lendrens"
                 64 72 65 
                 6e 73 00
                             DAT_00102149                                    XREF[1]:     FUN_00100b4c:00100b7b(*)  
        00102149 6b              ??         6Bh    k
        0010214a 00              ??         00h
                             s_Thauv'i_0010214b                              XREF[1]:     FUN_00100b4c:00100b91(*)  
        0010214b 54 68 61        ds         "Thauv'i"
                 75 76 27 
                 69 00
                             DAT_00102153                                    XREF[1]:     FUN_00100b4c:00100b98(*)  
        00102153 64              ??         64h    d
        00102154 00              ??         00h
                             s_Throrqiek_00102155                            XREF[1]:     FUN_00100b4c:00100bae(*)  
        00102155 54 68 72        ds         "Throrqiek"
                 6f 72 71 
                 69 65 6b 00
                             DAT_0010215f                                    XREF[1]:     FUN_00100b4c:00100bb5(*)  
        0010215f 50              ??         50h    P
        00102160 00              ??         00h
                             s_Inqods_00102161                               XREF[1]:     FUN_00100b4c:00100bcb(*)  
        00102161 49 6e 71        ds         "Inqods"
```
I grabbed all this output from ghidra, it looks like a conversion table to me, since output.txt contains the words:

Throrqiek 
Inqods 
[..]

I think I could make one, hope this would be useful..
```
└──╼ #cat conv.txt | grep "h\|ds" | grep -v XREF > conv3.txt

└──╼ #cat conv3.txt | awk '{print $5;print $6}' | grep -v "ds" | sed '/^[[:space:]]*$/d' > conv4.txt
```
But, not quite so straightforward.. After parsing and examining the output, there are multiple letters for each word/name in my conversion table file..
```
"Lendrens"
k
"Thauv'i"
d
"Throrqiek"
P
e
"Tarquts"
6
D
u
t
p
"Krolkel"
A
E
m
o
i
n
```
Ok so thinking of a conversion table, how this would look. I think I have one input word, with quotes around it, and then an array of letters after that, until another word with quotes

Then, the array of letters, might be for occurrences??
I.e, first “Krolkel” is A, 2nd Krokel is E, 3rd is m, etc.... Maybe?? Worth a try I guess, can tweak after.

pseudocode:
```
read until "
grab string between "'s
read letter per line into array until next "
```
Ended up writing this up in python but there were some mistakes at first..
```
[+] Translation:
['H']
['T']
['B']
['{']
['l']
['3']
['4']
['t']
['m']
['3']
['b']
['u']
['t']
['3']
['t']
['t']
['y']
['s']
['l']
['0']
['w']
['!', 'X', 'a', 'n', 'X']
['}']
['1']

[.] List (78 words found):

{'Lendrens': ['k'], "Thauv'i": ['d'], 'Throrqiek': ['P', 'e'], 'Tarquts': ['6', 'D', 'u', 't', 'p'], 'Krolkel': ['A', 'E', 'm', 'o', 'i', 'n'], 'Dakroith': ['|'], 'Creiqex': ['*'], 'Thomois': ['Y'], "Groz'ens": ['4'], 'Urqek': ['D', 'N', 'i', 'd', 'v'], 'Crerceon': ['H'], 'Yonphie': ['#', 'X', 'i', 't', 's', 'S'], 'Thohul': ['I'], 'Zahrull': ['W'], "Om'ons": ['i'], 'Kradraks': ['F'], 'Ielkul': ['+'], 'Vranix': ['q', 'T', 'r', 'u', 'n', 'M'], "Craz'ails": ['h'], "Xoq'an": ['.', 'U', 'k', 'o', 'x', 'r', 'N'], 'Taxan': [';'], 'Munis': ['b'], 'Trurkror': ['g'], 'Tulphaer': ['?', 'E', 'h', 'n', 'u', '_'], 'Krets': ['$'], 'Grons': [','], 'Ingell': [')'], 'Ecruns': ['('], 'Khehlan': ['m'], 'Velzaeth': ['R'], 'Cuhix': ['Q'], 'Vinzo': ['l'], 'Istrur': ['E'], 'Zuvas': ['>'], 'Honzor': ['s'], 'Ukteils': ['0'], 'Baadix': ['}'], 'Zonnu': ['{'], 'Aarcets': ['\\'], 'Nevell': ['['], 'Dhohmu': ['!', 'X', 'a', 'n', 'X'], 'Zissat': ['O'], 'Iscax': ['x'], 'Pheilons': ['t'], 'Ghiso': ['`'], 'Scrigvil': ['-'], 'Ummuh': ['B'], 'Inphas': ['u'], 'Vurqails': ['/'], 'Vruziels': ['a'], "Ghut'ox": [':'], 'Aahroill': ['^'], 'Gairqeik': ['L', 'Q', 'e', 'k', 's', 'U'], 'Scuvvils': ["'"], 'Ohols': ['3'], "Som'ir": ['5'], 'Onzear': ['C'], 'Dhaesux': ['2'], 'Falnain': ['w'], 'Yemor': ['G'], 'Thraurgok': ['c'], '': ['1'], 'Gagro': ['Z', 'Z', 'a', 'd', '='], 'Dhieqe': ['f'], 'Xustrek': ['&'], 'Harned': ['o'], 'Dhulgea': ['V'], 'Zimil': ['y'], 'Thretex': ['z'], 'Bravon': ['8'], 'Krugreall': ['%'], 'Vaendred': ['J', 'O', 's', 'u', 'x', '@'], 'Ezains': ['T'], "Mik'ed": ['K'], "Cruz'oll": ['<'], 'Dhognot': [']', '7'], 'Drercieks': ['9'], 'Statars': ['j']}


[.] Reading output.txt as phrase..


[+] Translation:
HTB{l__34__t_m3_but___3tty_sl0w!}1
```
Looks like I am missing some words for sure..
Looked back and for sure I am missing some.  Luckily, the harder work is done and I just need the correct translation table now which is a long dict.

i.e: Throrqiek has 2 letters but found Ingods has e , missing from my list!

'Throrqiek': ['P', 'e'], 'Tarquts': ['6', 'D', 'u', 't', 'p'], '
```
        00102155 54 68 72        ds         "Throrqiek"
                 6f 72 71
                 69 65 6b 00
                             DAT_0010215f                                    XREF[1]:     FUN_00100b4c:00100bb5(*)
        0010215f 50              ??         50h    P
        00102160 00              ??         00h
                             s_Inqods_00102161                               XREF[1]:     FUN_00100b4c:00100bcb(*)
        00102161 49 6e 71        ds         "Inqods"    <---- missing
                 6f 64 73 00
                             DAT_00102168                                    XREF[1]:     FUN_00100b4c:00100bd2(*)
        00102168 65              ??         65h    e
        00102169 00              ??         00h
                             s_Tarquts_0010216a                              XREF[1]:     FUN_00100b4c:00100be8(*)
        0010216a 54 61 72        ds         "Tarquts"
```
Checked and foudn my conv4.txt def is missing them:
```
"Throrqiek"
P
e
"Tarquts"
6
D
```
Maybe I can do a better job grabbing them from the file.  Lets try strings first:

Nope, cant get it w/ strings.  Copied the bytes directly from ghidra, luckily you can copy as a python byte array, this is handy.

Rewrote the dictionary file generation code:
```
def makedictfile():
    # This is meant to be run on its own..  python3 conv.py > conv5.txt..
    # Converted from ghidra - copy python byte array
    bytes=[ 0x4c, 0x65, 0x6e, 0x64, 0x72, 0x65, 0x6e, 0x73, 0x00, 0x6b, 0x00, 0x54, 0x68, 0x61, 0x75, 0x76, 0x27, 0x69, 0x00, 0x64, 0x00, 0x54, 0x68,>
    for c in bytes:
        if c:
            print(chr(c),end='')
        else:
            print()  # if \0 print CRLF
    exit()
```
Modified the other code a bit, this is outputting a single letter per word now, thank god. The /0's were important.  So much for the shitty manual way, this shuold have taken 20 mins in ghidra if I was actually good with python lol!!
```
import os
import re
import json

def translate(trans,inputsentence):
    wordlist = inputsentence.split(' ')
    new_sentence = [trans[w] for w in wordlist]
    print(' '.join(new_sentence))

#######################################

words = {}
word=""
temp=[]
x=0

# OLD ROUTINE PARSED MANUALLY. But, should work for the conv5.txt also
#with open("conv4.txt") as file:
with open("conv5.txt") as file:
    lines = file.readlines()
    lines = [line.rstrip() for line in lines]

for line in lines:
    if line:
        if len(line)>1:
            if temp:
                words[word]=temp
                temp=[]
                x+=1
            print()
            print(x,end='- ')
            word=line.replace('"','')
            print(word)
        else:
            #print(x)
            temp.append(line[0])
            print(line,end='')
    if temp:   # catch last letters, since there is not another "
        words[word]=temp
        temp=[]
        x+=1

#print("\n\n[!] Making dictionary...")
#makedictfile()

print("\n\n[.] List ("+str(x)+" words found):\n")
print(words)
# Pretty print w/ json:
#print(json.dumps(words,sort_keys=False, indent=4))

print("\n\n[.] Reading output.txt as phrase..")
phrase=""
with open("output.txt") as file:
    lines = file.readlines()
    lines = [line.rstrip() for line in lines]
for line in lines:
    phrase+=line
    phrase+=" "

print("\n\n[+] Translation:")
x=0
j=[]
for w in phrase.split(" "):
    if w in words:
        print(words[w][0],end='')
    else:
        print("_",end='')
```

Ran it.  Output:
```
[.] List (93 words found):

{'Lendrens': ['k'], "Thauv'i": ['d'], 'Throrqiek': ['P'], 'Inqods': ['e'], 'Tarquts': ['6'], 'Dut': ['p'], 'Krolkel': ['A'], 'Emoi': ['n'], 'Dakroith': ['|'], 'Creiqex': ['*'], 'Thomois': ['Y'], "Groz'ens": ['4'], 'Urqek': ['D'], 'Nid': ['v'], 'Crerceon': ['H'], 'Yonphie': ['#'], 'Xits': ['S'], 'Thohul': ['I'], 'Zahrull': ['W'], "Om'ons": ['i'], 'Kradraks': ['F'], 'Ielkul': ['+'], 'Vranix': ['q'], 'Trun': ['M'], "Craz'ails": ['h'], "Xoq'an": ['.'], 'Ukox': ['r'], 'Evods': ['N'], 'Taxan': [';'], 'Munis': ['b'], 'Trurkror': ['g'], 'Tulphaer': ['?'], 'Ehnu': ['_'], 'Krets': ['$'], 'Grons': [','], 'Ingell': [')'], 'Ecruns': ['('], 'Khehlan': ['m'], 'Velzaeth': ['R'], 'Cuhix': ['Q'], 'Vinzo': ['l'], 'Istrur': ['E'], 'Zuvas': ['>'], 'Honzor': ['s'], 'Ukteils': ['0'], 'Baadix': ['}'], 'Zonnu': ['{'], 'Aarcets': ['\\'], 'Nevell': ['['], 'Dhohmu': ['!'], 'Xan': ['X'], 'Zissat': ['O'], 'Iscax': ['x'], 'Pheilons': ['t'], 'Ghiso': ['`'], 'Scrigvil': ['-'], 'Ummuh': ['B'], 'Inphas': ['u'], 'Vurqails': ['/'], 'Vruziels': ['a'], "Ghut'ox": [':'], 'Aahroill': ['^'], 'Gairqeik': ['L'], 'Qeks': ['U'], 'Scuvvils': ["'"], 'Ohols': ['3'], "Som'ir": ['5'], 'Onzear': ['C'], 'Dhaesux': ['2'], 'Falnain': ['w'], 'Yemor': ['G'], 'Thraurgok': ['c'], 'Vogeath': ['"'], 'Cuzads': ['1'], 'Gagro': ['Z'], 'Zad': ['='], 'Dhieqe': ['f'], 'Xustrek': ['&'], 'Harned': ['o'], 'Dhulgea': ['V'], 'Zimil': ['y'], 'Thretex': ['z'], 'Bravon': ['8'], 'Krugreall': ['%'], 'Vaendred': ['J'], 'Osux': ['@'], 'Ezains': ['T'], "Mik'ed": ['K'], "Cruz'oll": ['<'], 'Dhognot': [']'], 'Drids': ['7'], 'Drercieks': ['9'], 'Statars': ['j']}


[.] Reading output.txt as phrase..


[+] Translation:
HTB{l1n34r_t1m3_but_pr3tty_sl0w!}_┌
```

Removed junk characters, and donezo.  Another one, this one went really quick luckily.
