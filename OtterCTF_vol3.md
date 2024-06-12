## OtterCTF memory forensics with Volatility 3 

The OtterCTF 2018 - Memory Forensics challenge includes reverse engineering, steganography, network traffic, and other forensics challenges.  In order to improve my forensics skills, I worked through the writeup posted by Peter M. Stewart and updated the original Volatility 2 commands to the newer Volatility 3 Framework 2.7.1.  See the original writeup at: [https://www.petermstewart.net/otterctf-2018-memory-forensics-write-up/](https://www.petermstewart.net/otterctf-2018-memory-forensics-write-up/).  

Flag format:  CTF{...}

First, I downloaded OtterCTF.vmem and checked the MD5 and SHA1 hashes:

```
└─$ md5sum OtterCTF.vmem 
ad51f4ada4151eab76f2dce8dea69868  OtterCTF.vmem

sha1sum OtterCTF.vmem   
e6929ec61eb22af198186238bc916497e7c2b1d2  OtterCTF.vmem
```

These matched the hashes in the original writeup.

## QUESTION 1 - What is the password?
From the memory dump of Rick's PC, can you find his user password?

```
─$ python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem windows.info.Info

Variable        Value

Kernel Base     0xf80002a52000
DTB     0x187000
Symbols file:///home/kali/13_memory/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/3844DBB920174967BE7AA4A2C20430FA-2.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 FileLayer
KdDebuggerDataBlock     0xf80002c430a0
NTBuildLab      7601.17514.amd64fre.win7sp1_rtm.
CSDVersion      1
KdVersionBlock  0xf80002c43068
Major/Minor     15.7601
MachineType     34404
KeNumberProcessors      2
SystemTime      2018-08-04 19:34:22
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  6
NtMinorVersion  1
PE MajorOperatingSystemVersion  6
PE MinorOperatingSystemVersion  1
PE Machine      34404
PE TimeDateStamp        Sat Nov 20 09:30:02 2010
```

I found password hashes by using hashdump, a dump of the NTLM hashes from the SYSTEM and SAM registry hives.

```
$ python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem hashdump

User    rid     lmhash  nthash

Administrator   500     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
Guest           501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
Rick            1000    aad3b435b51404eeaad3b435b51404ee        518172d012f97d3a8fcc089615283940
```

I tried extracting the plaintext password from LSA secrets using lsadump:

```
└─$ python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem lsadump

Key             Secret                      Hex
DefaultPassword (MortyIsReallyAnOtter       28 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4d 00 6f 00 72 00 74 00 79 00 49 00 73 00 52 00 65 00 61 00 6c 00 6c 00 79 00 41 00 6e 00 4f 00 74 00 74 00 65 00 72 00 00 00 00 00 00 00 00 00
```              
### PASSWORD:  CTF{MortyIsReallyAnOtter}

## QUESTION 2: General Info
What is the name of the PC and the IP address?

To find the computer name, I searched the hive for REGISTRY\MACHINE\SYSTEM
```
└─$ python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem hivelist

Offset          FileFullPath                            File output

0xf8a00000f010                                          Disabled

0xf8a000024010  \REGISTRY\MACHINE\SYSTEM                Disabled
                 
0xf8a000053320  \REGISTRY\MACHINE\HARDWARE              Disabled
0xf8a000109410  \SystemRoot\System32\Config\SECURITY    Disabled
0xf8a00033d410  \Device\HarddiskVolume1\Boot\BCD        Disabled
0xf8a0005d5010  \SystemRoot\System32\Config\SOFTWARE    Disabled
0xf8a001495010  \SystemRoot\System32\Config\DEFAULT     Disabled
0xf8a0016d4010  \SystemRoot\System32\Config\SAM Disabled
0xf8a00175b010  \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DATDisabled
0xf8a00176e410  \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT Disabled
0xf8a002090010  \??\C:\Users\Rick\ntuser.dat    Disabled
0xf8a0020ad410  \??\C:\Users\Rick\AppData\Local\Microsoft\Windows\UsrClass.dat  Disabled
0xf8a00377d2d0  \??\C:\System Volume Information\Syscache.hve   Disabled
```

I printed the information stored in the registry by using the offset, 0xf8a000024010, and the registry key, ControlSet001\Control\ComputerName\ComputerName

```
$ python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem printkey --offset 0xf8a000024010 --key "ControlSet001\Control\ComputerName\ComputerName"

Last Write Time                 Hive Offset     Type    Key                                                                             Name            Data    Volatile

2018-06-02 19:23:00.000000      0xf8a000024010  REG_SZ  \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ComputerName        (Default)       "mnmsrvc"       False
2018-06-02 19:23:00.000000      0xf8a000024010  REG_SZ  \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ComputerName        ComputerName    "WIN-LO6FAF3DTFE"       False
```
### Computer Name: CTF{WIN-LO6FAF3DTFE}

To get the IP address, I used netscan.  The local address (LocalAddr) contains 192.168.202.131 along with 127.0.0.1 and 0.0.0.0.  See
[https://superuser.com/questions/949428/whats-the-difference-between-127-0-0-1-and-0-0-0-0](https://superuser.com/questions/949428/whats-the-difference-between-127-0-0-1-and-0-0-0-0)

```
$ python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem netscan

Offset          Proto   LocalAddr       LocalPort       ForeignAddr     ForeignPort     State   PID     Owner   Created

0x7d42ba90      TCPv4   -       0       56.219.196.26   0       CLOSED 2836     BitTorrent.exe  N/A
0x7d60f010      UDPv4   0.0.0.0 1900    *       0               2836   BitTorrent.exe   2018-08-04 19:27:17.000000 
0x7d6124d0      TCPv4   192.168.202.131 49530   77.102.199.102  7575   CLOSED   708     LunarMS.exe     -
0x7d62b3f0      UDPv4   192.168.202.131 6771    *       0              2836     BitTorrent.exe  2018-08-04 19:27:22.000000 
0x7d62d690      TCPv4   192.168.202.131 49229   169.1.143.215   8999   CLOSED   2836    BitTorrent.exe  N/A
0x7d62f4c0      UDPv4   127.0.0.1       62307   *       0              2836     BitTorrent.exe  2018-08-04 19:27:17.000000 
0x7d62f920      UDPv4   192.168.202.131 62306   *       0              2836     BitTorrent.exe  2018-08-04 19:27:17.000000 
0x7d634350      TCPv6   -       0       38db:c41a:80fa:ffff:38db:c41a:80fa:ffff 0       CLOSED  2836    BitTorrent.exe  N/A
0x7d6424c0      UDPv4   0.0.0.0 50762   *       0               4076   chrome.exe       2018-08-04 19:33:37.000000 
0x7d6b4250      UDPv6   ::1     1900    *       0               164    svchost.exe      2018-08-04 19:28:42.000000 
0x7d6e3230      UDPv4   127.0.0.1       6771    *       0              2836     BitTorrent.exe  2018-08-04 19:27:22.000000 
0x7d6ed650      UDPv4   0.0.0.0 5355    *       0               620    svchost.exe      2018-08-04 19:34:22.000000 
0x7d6f27f0      TCPv4   192.168.202.131 50381   71.198.155.180  34674  CLOSED   2836    BitTorrent.exe  -
0x7d704010      TCPv4   192.168.202.131 50382   92.251.23.204   6881   CLOSED   2836    BitTorrent.exe  -
0x7d708cf0      TCPv4   192.168.202.131 50364   91.140.89.116   31847  CLOSED   2836    BitTorrent.exe  -
0x7d71c8a0      UDPv4   0.0.0.0 0       *       0               868    svchost.exe      2018-08-04 19:34:22.000000 
0x7d71c8a0      UDPv6   ::      0       *       0               868    svchost.exe      2018-08-04 19:34:22.000000 
0x7d729620      TCPv4   -       50034   142.129.37.27   24578   CLOSED 2836     BitTorrent.exe  -
0x7d72cbe0      TCPv4   192.168.202.131 50340   23.37.43.27     80     CLOSED   3496    Lavasoft.WCAss  -
0x7d7365a0      TCPv4   192.168.202.131 50358   23.37.43.27     80     CLOSED   3856    WebCompanion.e  -
0x7d74a390      UDPv4   127.0.0.1       52847   *       0              2624     bittorrentie.e  2018-08-04 19:27:24.000000 
0x7d7602c0      UDPv4   127.0.0.1       52846   *       0              2308     bittorrentie.e  2018-08-04 19:27:24.000000 
0x7d787010      UDPv4   0.0.0.0 65452   *       0               4076   chrome.exe       2018-08-04 19:33:42.000000 
0x7d789b50      UDPv4   0.0.0.0 50523   *       0               620    svchost.exe      2018-08-04 19:34:22.000000 
0x7d789b50      UDPv6   ::      50523   *       0               620    svchost.exe      2018-08-04 19:34:22.000000 
0x7d81c890      TCPv4   192.168.202.131 50335   185.154.111.20  60405  CLOSED   2836    BitTorrent.exe  -
0x7d8bb390      TCPv4   0.0.0.0 9008    0.0.0.0 0       LISTENING      4System  -
0x7d8bb390      TCPv6   ::      9008    ::      0       LISTENING      4System  -
0x7d8fd530      TCPv4   192.168.202.131 50327   23.37.43.27     80     CLOSED   3496    Lavasoft.WCAss  -
0x7d92a230      UDPv4   0.0.0.0 0       *       0               868    svchost.exe      2018-08-04 19:34:22.000000 
0x7d92a230      UDPv6   ::      0       *       0               868    svchost.exe      2018-08-04 19:34:22.000000 
0x7d9a9240      TCPv4   0.0.0.0 8733    0.0.0.0 0       LISTENING      4System  -
0x7d9a9240      TCPv6   ::      8733    ::      0       LISTENING      4System  -
0x7d9cecf0      TCPv4   192.168.202.131 50373   173.239.232.46  2997   CLOSED   2836    BitTorrent.exe  -
0x7d9d7cf0      TCPv4   192.168.202.131 50371   191.253.122.149 59163  CLOSED   2836    BitTorrent.exe  -
0x7d9e19e0      TCPv4   0.0.0.0 20830   0.0.0.0 0       LISTENING      2836     BitTorrent.exe  -
0x7d9e19e0      TCPv6   ::      20830   ::      0       LISTENING      2836     BitTorrent.exe  -
0x7d9e1c90      TCPv4   0.0.0.0 20830   0.0.0.0 0       LISTENING      2836     BitTorrent.exe  -
0x7d9e8b50      UDPv4   0.0.0.0 20830   *       0               2836   BitTorrent.exe   2018-08-04 19:27:15.000000 
0x7d9f4560      UDPv4   0.0.0.0 0       *       0               3856   WebCompanion.e   2018-08-04 19:34:22.000000 
0x7d9f8cb0      UDPv4   0.0.0.0 20830   *       0               2836   BitTorrent.exe   2018-08-04 19:27:15.000000 
0x7d9f8cb0      UDPv6   ::      20830   *       0               2836   BitTorrent.exe   2018-08-04 19:27:15.000000 
0x7daefec0      UDPv4   0.0.0.0 0       *       0               3856   WebCompanion.e   2018-08-04 19:34:22.000000 
0x7daefec0      UDPv6   ::      0       *       0               3856   WebCompanion.e   2018-08-04 19:34:22.000000 
0x7db000a0      TCPv4   -       50091   93.142.197.107  32645   CLOSED 2836     BitTorrent.exe  -
0x7db132e0      TCPv4   192.168.202.131 50280   72.55.154.81    80     CLOSED   3880    WebCompanionIn  N/A
0x7db83b90      UDPv4   0.0.0.0 0       *       0               3880   WebCompanionIn   2018-08-04 19:33:30.000000 
0x7db83b90      UDPv6   ::      0       *       0               3880   WebCompanionIn   2018-08-04 19:33:30.000000 
0x7db9cdd0      UDPv4   0.0.0.0 0       *       0               2844   WebCompanion.e   2018-08-04 19:30:05.000000 
0x7db9cdd0      UDPv6   ::      0       *       0               2844   WebCompanion.e   2018-08-04 19:30:05.000000 
0x7dbc3010      TCPv6   -       0       4847:d418:80fa:ffff:4847:d418:80fa:ffff 0       CLOSED  4076    chrome.exe      N/A
0x7dc2dc30      UDPv4   0.0.0.0 50879   *       0               4076   chrome.exe       2018-08-04 19:30:41.000000 
0x7dc2dc30      UDPv6   ::      50879   *       0               4076   chrome.exe       2018-08-04 19:30:41.000000 
0x7dc4ad30      TCPv4   0.0.0.0 49155   0.0.0.0 0       LISTENING      500      lsass.exe       -
0x7dc4ad30      TCPv6   ::      49155   ::      0       LISTENING      500      lsass.exe       -
0x7dc4b370      TCPv4   0.0.0.0 49155   0.0.0.0 0       LISTENING      500      lsass.exe       -
0x7dc83080      TCPv4   192.168.202.131 50377   179.108.238.10  19761  CLOSED   2836    BitTorrent.exe  -
0x7dc83810      UDPv4   0.0.0.0 5355    *       0               620    svchost.exe      2018-08-04 19:34:22.000000 
0x7dc83810      UDPv6   ::      5355    *       0               620    svchost.exe      2018-08-04 19:34:22.000000 
0x7dd451f0      TCPv4   192.168.202.131 50321   45.27.208.145   51414  CLOSED   2836    BitTorrent.exe  -
0x7dd71010      TCPv4   0.0.0.0 445     0.0.0.0 0       LISTENING      4System  -
0x7dd71010      TCPv6   ::      445     ::      0       LISTENING      4System  -
0x7dd82c30      UDPv4   0.0.0.0 5355    *       0               620    svchost.exe      2018-08-04 19:26:38.000000 
0x7ddae890      TCPv4   -       50299   212.92.105.227  8999    CLOSED 2836     BitTorrent.exe  -
0x7ddca6b0      TCPv4   0.0.0.0 49156   0.0.0.0 0       LISTENING      492      services.exe    -
0x7ddcbc00      TCPv4   0.0.0.0 49156   0.0.0.0 0       LISTENING      492      services.exe    -
0x7ddcbc00      TCPv6   ::      49156   ::      0       LISTENING      492      services.exe    -
0x7ddff010      TCPv4   192.168.202.131 50379   23.37.43.27     80     CLOSED   3856    WebCompanion.e  -
0x7de09c30      TCPv4   0.0.0.0 49152   0.0.0.0 0       LISTENING      396      wininit.exe     -
0x7de09c30      TCPv6   ::      49152   ::      0       LISTENING      396      wininit.exe     -
0x7de0d7b0      TCPv4   0.0.0.0 49152   0.0.0.0 0       LISTENING      396      wininit.exe     -
0x7de424e0      TCPv4   0.0.0.0 49153   0.0.0.0 0       LISTENING      808      svchost.exe     -
0x7de45ef0      TCPv4   0.0.0.0 49153   0.0.0.0 0       LISTENING      808      svchost.exe     -
0x7de45ef0      TCPv6   ::      49153   ::      0       LISTENING      808      svchost.exe     -
0x7df00980      UDPv4   0.0.0.0 0       *       0               620    svchost.exe      2018-08-04 19:34:22.000000 
0x7df00980      UDPv6   ::      0       *       0               620    svchost.exe      2018-08-04 19:34:22.000000 
0x7df04cc0      UDPv4   0.0.0.0 5355    *       0               620    svchost.exe      2018-08-04 19:26:38.000000 
0x7df04cc0      UDPv6   ::      5355    *       0               620    svchost.exe      2018-08-04 19:26:38.000000 
0x7df3d270      TCPv4   0.0.0.0 49154   0.0.0.0 0       LISTENING      868      svchost.exe     -
0x7df3eef0      TCPv4   0.0.0.0 49154   0.0.0.0 0       LISTENING      868      svchost.exe     -
0x7df3eef0      TCPv6   ::      49154   ::      0       LISTENING      868      svchost.exe     -
0x7df5f010      UDPv4   0.0.0.0 55175   *       0               620    svchost.exe      2018-08-04 19:34:22.000000 
0x7dfab010      UDPv4   0.0.0.0 58383   *       0               620    svchost.exe      2018-08-04 19:34:22.000000 
0x7dfab010      UDPv6   ::      58383   *       0               620    svchost.exe      2018-08-04 19:34:22.000000 
0x7e0057d0      TCPv4   192.168.202.131 50353   85.242.139.158  51413  CLOSED   2836    BitTorrent.exe  -
0x7e0114b0      TCPv4   192.168.202.131 50339   77.65.111.216   8306   CLOSED   2836    BitTorrent.exe  -
0x7e042cf0      TCPv4   192.168.202.131 50372   83.44.27.35     52103  CLOSED   2836    BitTorrent.exe  -
0x7e08a010      TCPv4   192.168.202.131 50374   89.46.49.163    20133  CLOSED   2836    BitTorrent.exe  -
0x7e092010      TCPv4   192.168.202.131 50378   120.29.114.41   13155  CLOSED   2836    BitTorrent.exe  -
0x7e094b90      TCPv4   192.168.202.131 50365   52.91.1.182     55125  CLOSED   2836    BitTorrent.exe  N/A
0x7e09ba90      TCPv6   -       0       68f0:181b:80fa:ffff:68f0:181b:80fa:ffff 0       CLOSED  2836    BitTorrent.exe  -
0x7e0a8b90      TCPv4   192.168.202.131 50341   72.55.154.81    80     CLOSED   3880    WebCompanionIn  N/A
0x7e0d6180      TCPv4   192.168.202.131 50349   196.250.217.22  32815  CLOSED   2836    BitTorrent.exe  -
0x7e108100      TCPv4   192.168.202.131 50360   174.0.234.77    31240  CLOSED   2836    BitTorrent.exe  -
0x7e124910      TCPv4   192.168.202.131 50366   89.78.106.196   51413  CLOSED   2836    BitTorrent.exe  -
0x7e12c1c0      UDPv4   0.0.0.0 0       *       0               3880   WebCompanionIn   2018-08-04 19:33:27.000000 
0x7e14dcf0      TCPv4   192.168.202.131 50363   122.62.218.159  11627  CLOSED   2836    BitTorrent.exe  N/A
0x7e163a40      UDPv4   0.0.0.0 0       *       0               3880   WebCompanionIn   2018-08-04 19:33:27.000000 
0x7e163a40      UDPv6   ::      0       *       0               3880   WebCompanionIn   2018-08-04 19:33:27.000000 
0x7e18bcf0      TCPv4   192.168.202.131 50333   191.177.124.34  21011  CLOSED   2836    BitTorrent.exe  -
0x7e1cf010      UDPv4   192.168.202.131 137     *       0              4System  2018-08-04 19:26:35.000000 
0x7e1da010      UDPv4   192.168.202.131 138     *       0              4System  2018-08-04 19:26:35.000000 
0x7e1f6010      TCPv4   0.0.0.0 135     0.0.0.0 0       LISTENING      712      svchost.exe     -
0x7e1f6010      TCPv6   ::      135     ::      0       LISTENING      712      svchost.exe     -
0x7e1f8ef0      TCPv4   0.0.0.0 135     0.0.0.0 0       LISTENING      712      svchost.exe     -
0x7e413a40      TCPv4   -       0       -       0       CLOSED  708    LunarMS.exe      -
0x7e415010      TCPv4   192.168.202.131 50346   89.64.10.176    10589  CLOSED   2836    BitTorrent.exe  -
0x7e4202d0      TCPv4   192.168.202.131 50217   104.18.21.226   80     CLOSED   3880    WebCompanionIn  N/A
0x7e45f110      TCPv4   192.168.202.131 50211   104.18.20.226   80     CLOSED   3880    WebCompanionIn  N/A
0x7e48d9c0      UDPv6   fe80::b06b:a531:ec88:457f       1900    *      0164     svchost.exe     2018-08-04 19:28:42.000000 
0x7e4ad870      UDPv4   127.0.0.1       1900    *       0              164      svchost.exe     2018-08-04 19:28:42.000000 
0x7e4cc910      TCPv4   192.168.202.131 50228   104.18.20.226   80     CLOSED   3880    WebCompanionIn  N/A
0x7e511bb0      UDPv4   0.0.0.0 60005   *       0               620    svchost.exe      2018-08-04 19:34:22.000000 
0x7e512950      TCPv4   192.168.202.131 50345   77.126.30.221   13905  CLOSED   2836    BitTorrent.exe  -
0x7e521b50      TCPv4   -       0       -       0       CLOSED  708    LunarMS.exe      -
0x7e5228d0      TCPv4   192.168.202.131 50075   70.65.116.120   52700  CLOSED   2836    BitTorrent.exe  -
0x7e52f010      TCPv4   192.168.202.131 50343   86.121.4.189    46392  CLOSED   2836    BitTorrent.exe  -
0x7e563860      TCPv4   192.168.202.131 50170   103.232.25.44   25384  CLOSED   2836    BitTorrent.exe  -
0x7e572cf0      TCPv4   192.168.202.131 50125   122.62.218.159  11627  CLOSED   2836    BitTorrent.exe  -
0x7e5d6cf0      TCPv4   192.168.202.131 50324   54.197.8.177    49420  CLOSED   2836    BitTorrent.exe  -
0x7e5dc3b0      UDPv6   fe80::b06b:a531:ec88:457f       546     *      0808     svchost.exe     2018-08-04 19:33:28.000000 
0x7e71b010      TCPv4   192.168.202.131 50344   70.27.98.75     6881   CLOSED   2836    BitTorrent.exe  -
0x7e71d010      TCPv4   192.168.202.131 50351   99.251.199.160  1045   CLOSED   2836    BitTorrent.exe  -
0x7e7469c0      UDPv4   0.0.0.0 50878   *       0               4076   chrome.exe       2018-08-04 19:30:39.000000 
0x7e7469c0      UDPv6   ::      50878   *       0               4076   chrome.exe       2018-08-04 19:30:39.000000 
0x7e74b010      TCPv4   192.168.202.131 50385   209.236.6.89    56500  CLOSED   2836    BitTorrent.exe  -
0x7e77cb00      UDPv4   0.0.0.0 50748   *       0               4076   chrome.exe       2018-08-04 19:30:07.000000 
0x7e77cb00      UDPv6   ::      50748   *       0               4076   chrome.exe       2018-08-04 19:30:07.000000 
0x7e78b7f0      TCPv4   192.168.202.131 50238   72.55.154.82    80     CLOSED   3880    WebCompanionIn  N/A
0x7e79f3f0      UDPv4   0.0.0.0 5353    *       0               4076   chrome.exe       2018-08-04 19:29:35.000000 
0x7e7a0ec0      UDPv4   0.0.0.0 5353    *       0               4076   chrome.exe       2018-08-04 19:29:35.000000 
0x7e7a0ec0      UDPv6   ::      5353    *       0               4076   chrome.exe       2018-08-04 19:29:35.000000 
0x7e7a3960      UDPv4   0.0.0.0 0       *       0               3880   WebCompanionIn   2018-08-04 19:33:30.000000 
0x7e7ae380      TCPv4   192.168.202.131 50361   5.34.21.181     8999   CLOSED   2836    BitTorrent.exe  -
0x7e7b0380      TCPv6   -       0       4847:d418:80fa:ffff:4847:d418:80fa:ffff 0       CLOSED  2836    BitTorrent.exe  N/A
0x7e7b9010      TCPv4   192.168.202.131 50334   188.129.94.129  25128  CLOSED   2836    BitTorrent.exe  N/A
0x7e7dd010      UDPv6   ::1     58340   *       0               164    svchost.exe      2018-08-04 19:28:42.000000 
0x7e94b010      TCPv4   192.168.202.131 50356   77.126.30.221   13905  CLOSED   2836    BitTorrent.exe  -
0x7e9ad840      TCPv4   192.168.202.131 50380   84.52.144.29    56299  CLOSED   2836    BitTorrent.exe  -
0x7e9bacf0      TCPv4   192.168.202.131 50350   77.253.242.0    5000   CLOSED   2836    BitTorrent.exe  -
0x7eaac5e0      TCPv4   192.168.202.131 50387   93.184.220.29   80     CLOSED   3856    WebCompanion.e  -
0x7eab4cf0      TCPv4   -       0       56.219.196.26   0       CLOSED 2836     BitTorrent.exe  N/A
0x7fb9cec0      UDPv4   192.168.202.131 1900    *       0              164      svchost.exe     2018-08-04 19:28:42.000000 
0x7fb9d430      UDPv4   127.0.0.1       58341   *       0              164      svchost.exe     2018-08-04 19:28:42.000000
```

### IP ADDRESS:  CTF{192.168.202.131}

## QUESTION 3 - Play Time
Rick loves to play old videogames.  Which game is he playing and what's the IP address of the server?

pstree provides a list of processes that were running

```
─$ python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem windows.pstree.PsTree               
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        Audit   Cmd     Path

4       0       System          0xfa8018d44740  95      411     N/A     False  2018-08-04 19:26:03.000000       N/A     -       -       -
* 260   4       smss.exe        0xfa801947e4d0  2       30      N/A    False    2018-08-04 19:26:03.000000      N/A     \Device\HarddiskVolume1\Windows\System32\smss.exe       \SystemRoot\System32\smss.exe   \SystemRoot\System32\smss.exe
348     336     csrss.exe       0xfa801a0c8380  9       563     0      False    2018-08-04 19:26:10.000000      N/A     \Device\HarddiskVolume1\Windows\System32\csrss.exe      %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16      C:\Windows\system32\csrss.exe
* 2420  348     conhost.exe     0xfa801a6643d0  0       30      0      False    2018-08-04 19:34:22.000000      2018-08-04 19:34:22.000000     \Device\HarddiskVolume1\Windows\System32\conhost.exe     \??\C:\Windows\system32\conhost.exe     C:\Windows\system32\conhost.exe
388     380     csrss.exe       0xfa80198d3b30  11      460     1      False    2018-08-04 19:26:11.000000      N/A     \Device\HarddiskVolume1\Windows\System32\csrss.exe      %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16      C:\Windows\system32\csrss.exe
396     336     wininit.exe     0xfa801a2ed060  3       78      0      False    2018-08-04 19:26:11.000000      N/A     \Device\HarddiskVolume1\Windows\System32\wininit.exe    wininit.exe     C:\Windows\system32\wininit.exe
* 508   396     lsm.exe         0xfa801ab461a0  10      148     0       False  2018-08-04 19:26:12.000000       N/A     \Device\HarddiskVolume1\Windows\System32\lsm.exe        C:\Windows\system32\lsm.exe     C:\Windows\system32\lsm.exe
* 492   396     services.exe    0xfa801ab377c0  11      242     0      False    2018-08-04 19:26:12.000000      N/A     \Device\HarddiskVolume1\Windows\System32\services.exe   C:\Windows\system32\services.exe       C:\Windows\system32\services.exe
** 1164 492     svchost.exe     0xfa801ad718a0  18      312     0      False    2018-08-04 19:26:23.000000      N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork        C:\Windows\system32\svchost.exe
** 1428 492     vmtoolsd.exe    0xfa801ae92920  9       313     0      False    2018-08-04 19:26:27.000000      N/A     \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\vmtoolsd.exe  "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"     C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
*** 3916        1428    cmd.exe 0xfa801a572b30  0       -       0      False    2018-08-04 19:34:22.000000      2018-08-04 19:34:22.000000     \Device\HarddiskVolume1\Windows\System32\cmd.exe -       -
** 1948 492     svchost.exe     0xfa801afe7800  6       96      0      False    2018-08-04 19:26:42.000000      N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k bthsvcs      C:\Windows\system32\svchost.exe
** 1436 492     msdtc.exe       0xfa801aff3b30  14      155     0      False    2018-08-04 19:26:43.000000      N/A     \Device\HarddiskVolume1\Windows\System32\msdtc.exe      C:\Windows\System32\msdtc.exe   C:\Windows\System32\msdtc.exe
** 668  492     vmacthlp.exe    0xfa801abbdb30  3       56      0      False    2018-08-04 19:26:16.000000      N/A     \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\vmacthlp.exe  "C:\Program Files\VMware\VMware Tools\vmacthlp.exe"     C:\Program Files\VMware\VMware Tools\vmacthlp.exe
** 412  492     mscorsvw.exe    0xfa801b603610  7       86      0      True     2018-08-04 19:28:42.000000      N/A     \Device\HarddiskVolume1\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe      C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe
** 164  492     svchost.exe     0xfa801a6af9f0  12      147     0      False    2018-08-04 19:28:42.000000      N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation       C:\Windows\system32\svchost.exe
** 808  492     svchost.exe     0xfa801ac2e9e0  22      508     0      False    2018-08-04 19:26:18.000000      N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted        C:\Windows\System32\svchost.exe
*** 960 808     audiodg.exe     0xfa801ac753a0  7       151     0      False    2018-08-04 19:26:19.000000      N/A     \Device\HarddiskVolume1\Windows\System32\audiodg.exe    C:\Windows\system32\AUDIODG.EXE 0x2fc  C:\Windows\system32\AUDIODG.EXE
** 2344 492     taskhost.exe    0xfa801b1e9b30  8       193     1      False    2018-08-04 19:26:57.000000      N/A     \Device\HarddiskVolume1\Windows\System32\taskhost.exe   "taskhost.exe"  C:\Windows\system32\taskhost.exe
** 3496 492     Lavasoft.WCAss  0xfa801aad1060  14      473     0      False    2018-08-04 19:33:49.000000      N/A     \Device\HarddiskVolume1\Program Files (x86)\Lavasoft\Web Companion\Application\Lavasoft.WCAssistant.WinService.exe      "C:\Program Files (x86)\Lavasoft\Web Companion\Application\Lavasoft.WCAssistant.WinService.exe" C:\Program Files (x86)\Lavasoft\Web Companion\Application\Lavasoft.WCAssistant.WinService.exe
** 1324 492     dllhost.exe     0xfa801ae7f630  15      207     0      False    2018-08-04 19:26:42.000000      N/A     \Device\HarddiskVolume1\Windows\System32\dllhost.exe    C:\Windows\system32\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}       C:\Windows\system32\dllhost.exe
** 3124 492     mscorsvw.exe    0xfa801a6c2700  7       77      0      False    2018-08-04 19:28:43.000000      N/A     \Device\HarddiskVolume1\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsvw.exe       C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsvw.exe    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsvw.exe
** 2500 492     sppsvc.exe      0xfa801b232060  4       149     0      False    2018-08-04 19:26:58.000000      N/A     \Device\HarddiskVolume1\Windows\System32\sppsvc.exe     C:\Windows\system32\sppsvc.exe  C:\Windows\system32\sppsvc.exe
** 712  492     svchost.exe     0xfa801abebb30  8       301     0      False    2018-08-04 19:26:17.000000      N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k RPCSSC:\Windows\system32\svchost.exe
** 844  492     svchost.exe     0xfa801ac31b30  17      396     0      False    2018-08-04 19:26:18.000000      N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted C:\Windows\System32\svchost.exe
*** 2704        844     dwm.exe 0xfa801b1fab30  4       97      1      False    2018-08-04 19:27:04.000000      N/A     \Device\HarddiskVolume1\Windows\System32\dwm.exe        "C:\Windows\system32\Dwm.exe"   C:\Windows\system32\Dwm.exe
** 1356 492     VGAuthService.  0xfa801ae0f630  3       85      0      False    2018-08-04 19:26:25.000000      N/A     \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe      "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"  C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe
** 724  492     PresentationFo  0xfa801988c2d0  6       148     0      False    2018-08-04 19:27:52.000000      N/A     \Device\HarddiskVolume1\Windows\Microsoft.NET\Framework64\v3.0\WPF\PresentationFontCache.exe   C:\Windows\Microsoft.Net\Framework64\v3.0\WPF\PresentationFontCache.exe C:\Windows\Microsoft.Net\Framework64\v3.0\WPF\PresentationFontCache.exe
** 604  492     svchost.exe     0xfa8018e3c890  11      376     0      False    2018-08-04 19:26:16.000000      N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k DcomLaunch   C:\Windows\system32\svchost.exe
*** 1800        604     WmiPrvSE.exe    0xfa8019124b30  9       222    0False   2018-08-04 19:26:39.000000      N/A     \Device\HarddiskVolume1\Windows\System32\wbem\WmiPrvSE.exe      C:\Windows\system32\wbem\wmiprvse.exe   C:\Windows\system32\wbem\wmiprvse.exe
*** 2136        604     WmiPrvSE.exe    0xfa801b112060  12      324    0False   2018-08-04 19:26:51.000000      N/A     \Device\HarddiskVolume1\Windows\System32\wbem\WmiPrvSE.exe      C:\Windows\system32\wbem\wmiprvse.exe   C:\Windows\system32\wbem\wmiprvse.exe
** 1120 492     spoolsv.exe     0xfa801ad5ab30  14      346     0      False    2018-08-04 19:26:22.000000      N/A     \Device\HarddiskVolume1\Windows\System32\spoolsv.exe    C:\Windows\System32\spoolsv.exe C:\Windows\System32\spoolsv.exe
** 868  492     svchost.exe     0xfa801ac4db30  45      1114    0      False    2018-08-04 19:26:18.000000      N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k netsvcs      C:\Windows\system32\svchost.exe
** 620  492     svchost.exe     0xfa801acd37e0  19      415     0      False    2018-08-04 19:26:21.000000      N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k NetworkService       C:\Windows\system32\svchost.exe
** 1012 492     svchost.exe     0xfa801ac97060  12      554     0      False    2018-08-04 19:26:20.000000      N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalService C:\Windows\system32\svchost.exe
** 3064 492     SearchIndexer.  0xfa801b3aab30  11      610     0      False    2018-08-04 19:27:14.000000      N/A     \Device\HarddiskVolume1\Windows\System32\SearchIndexer.exe      C:\Windows\system32\SearchIndexer.exe /Embedding        C:\Windows\system32\SearchIndexer.exe
** 3196 492     svchost.exe     0xfa801a6e4b30  14      352     0      False    2018-08-04 19:28:44.000000      N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k secsvcs      C:\Windows\System32\svchost.exe
* 500   396     lsass.exe       0xfa801ab3f060  7       610     0      False    2018-08-04 19:26:12.000000      N/A     \Device\HarddiskVolume1\Windows\System32\lsass.exe      C:\Windows\system32\lsass.exe   C:\Windows\system32\lsass.exe
432     380     winlogon.exe    0xfa801aaf4060  3       113     1      False    2018-08-04 19:26:11.000000      N/A     \Device\HarddiskVolume1\Windows\System32\winlogon.exe   winlogon.exe    C:\Windows\system32\winlogon.exe
2728    2696    explorer.exe    0xfa801b27e060  33      854     1      False    2018-08-04 19:27:04.000000      N/A     \Device\HarddiskVolume1\Windows\explorer.exe    C:\Windows\Explorer.EXE C:\Windows\Explorer.EXE

* 708   2728    LunarMS.exe     0xfa801b5cb740  18      346     1      True     2018-08-04 19:27:39.000000      N/A     \Device\HarddiskVolume1\Nexon\MapleStory\LunarMS.exe    "C:\Nexon\MapleStory\LunarMS.exe"      C:\Nexon\MapleStory\LunarMS.exe

* 4076  2728    chrome.exe      0xfa801a4e3870  44      1160    1      False    2018-08-04 19:29:30.000000      N/A     \Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe        "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"   C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
** 576  4076    chrome.exe      0xfa801a502b30  2       58      1      False    2018-08-04 19:29:31.000000      N/A     \Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe        "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=watcher --main-thread-id=4080 --on-initialized-event-handle=304 --parent-handle=308 /prefetch:6    C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
** 3648 4076    chrome.exe      0xfa801a635240  16      207     1      False    2018-08-04 19:33:38.000000      N/A     \Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe        "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=renderer --field-trial-handle=984,15358569600588498425,3475374789430647391,131072 --service-pipe-token=66BB0CC3FE10242BC701AB87A5940738 --lang=en-US --enable-offline-auto-reload --enable-offline-auto-reload-visible-only --device-scale-factor=1 --num-raster-threads=1 --service-request-channel-token=66BB0CC3FE10242BC701AB87A5940738 --renderer-client-id=30 --mojo-platform-channel-handle=4516 /prefetch:1        C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
** 1796 4076    chrome.exe      0xfa801a5ef1f0  15      170     1      False    2018-08-04 19:33:41.000000      N/A     \Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe        "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=renderer --field-trial-handle=984,15358569600588498425,3475374789430647391,131072 --service-pipe-token=86C637812F74263DD98834CC0FE01CE7 --lang=en-US --enable-offline-auto-reload --enable-offline-auto-reload-visible-only --device-scale-factor=1 --num-raster-threads=1 --service-request-channel-token=86C637812F74263DD98834CC0FE01CE7 --renderer-client-id=31 --mojo-platform-channel-handle=4412 /prefetch:1        C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
** 1808 4076    chrome.exe      0xfa801a4f7b30  13      229     1      False    2018-08-04 19:29:32.000000      N/A     \Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe        "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=gpu-process --field-trial-handle=984,15358569600588498425,3475374789430647391,131072 --gpu-preferences=KAAAAAAAAACAAwBAAQAAAAAAAAAAAGAAEAAAAAAAAAAAAAAAAAAAACgAAAAEAAAAIAAAAAAAAAAoAAAAAAAAADAAAAAAAAAAOAAAAAAAAAAQAAAAAAAAAAAAAAAKAAAAEAAAAAAAAAAAAAAACwAAABAAAAAAAAAAAQAAAAoAAAAQAAAAAAAAAAEAAAALAAAA --service-request-channel-token=4939AD179421E7F7FF934CA7C25FCD34 --mojo-platform-channel-handle=1004 --ignored=" --type=renderer " /prefetch:2    C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
** 4084 4076    chrome.exe      0xfa801a4eab30  8       86      1      False    2018-08-04 19:29:30.000000      N/A     \Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe        "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=crashpad-handler "--user-data-dir=C:\Users\Rick\AppData\Local\Google\Chrome\User Data" /prefetch:7 --monitor-self-annotation=ptype=crashpad-handler "--database=C:\Users\Rick\AppData\Local\Google\Chrome\User Data\Crashpad" "--metrics-dir=C:\Users\Rick\AppData\Local\Google\Chrome\User Data" --url=https://clients2.google.com/cr/report --annotation=channel= --annotation=plat=Win64 --annotation=prod=Chrome --annotation=ver=68.0.3440.84 --initial-client-data=0x7c,0x80,0x84,0x78,0x88,0x7feeb3324d0,0x7feeb3324e0,0x7feeb3324f0        C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
** 3924 4076    chrome.exe      0xfa801aa00a90  16      228     1      False    2018-08-04 19:29:51.000000      N/A     \Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe        "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=renderer --field-trial-handle=984,15358569600588498425,3475374789430647391,131072 --service-pipe-token=BB216EAECD5332095D1836CB17604E02 --lang=en-US --enable-offline-auto-reload --enable-offline-auto-reload-visible-only --device-scale-factor=1 --num-raster-threads=1 --service-request-channel-token=BB216EAECD5332095D1836CB17604E02 --renderer-client-id=9 --mojo-platform-channel-handle=2440 /prefetch:1 C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
** 2748 4076    chrome.exe      0xfa801a7f98f0  15      181     1      False    2018-08-04 19:31:15.000000      N/A     \Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe        "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=renderer --field-trial-handle=984,15358569600588498425,3475374789430647391,131072 --service-pipe-token=5B96B12CED256E93CD66ABC8626426FB --lang=en-US --enable-offline-auto-reload --enable-offline-auto-reload-visible-only --device-scale-factor=1 --num-raster-threads=1 --service-request-channel-token=5B96B12CED256E93CD66ABC8626426FB --renderer-client-id=22 --mojo-platform-channel-handle=2104 /prefetch:1        C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
* 3820  2728    Rick And Morty  0xfa801b486b30  4       185     1      True     2018-08-04 19:32:55.000000      N/A     \Device\HarddiskVolume1\Torrents\Rick And Morty season 1 download.exe   "C:\Torrents\Rick And Morty season 1 download.exe"      C:\Torrents\Rick And Morty season 1 download.exe
** 3720 3820    vmware-tray.ex  0xfa801a4c5b30  8       147     1      True     2018-08-04 19:33:02.000000      N/A     \Device\HarddiskVolume1\Users\Rick\AppData\Local\Temp\RarSFX0\vmware-tray.exe   "C:\Users\Rick\AppData\Local\Temp\RarSFX0\vmware-tray.exe"      C:\Users\Rick\AppData\Local\Temp\RarSFX0\vmware-tray.exe
* 2804  2728    vmtoolsd.exe    0xfa801b1cdb30  6       190     1      False    2018-08-04 19:27:06.000000      N/A     \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\vmtoolsd.exe  "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr    C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
* 2836  2728    BitTorrent.exe  0xfa801b290b30  24      471     1      True     2018-08-04 19:27:07.000000      N/A     \Device\HarddiskVolume1\Users\Rick\AppData\Roaming\BitTorrent\BitTorrent.exe    "C:\Users\Rick\AppData\Roaming\BitTorrent\BitTorrent.exe"  /MINIMIZED   C:\Users\Rick\AppData\Roaming\BitTorrent\BitTorrent.exe
** 2624 2836    bittorrentie.e  0xfa801b4c9b30  13      316     1      True     2018-08-04 19:27:21.000000      N/A     \Device\HarddiskVolume1\Users\Rick\AppData\Roaming\BitTorrent\updates\7.10.3_44495\bittorrentie.exe     "C:\Users\Rick\AppData\Roaming\BitTorrent\updates\7.10.3_44495\bittorrentie.exe" BitTorrent_2836_00313978_1933444659 BT4823DF041B09 BitTorrent  C:\Users\Rick\AppData\Roaming\BitTorrent\updates\7.10.3_44495\bittorrentie.exe
** 2308 2836    bittorrentie.e  0xfa801b4a7b30  15      337     1      True     2018-08-04 19:27:19.000000      N/A     \Device\HarddiskVolume1\Users\Rick\AppData\Roaming\BitTorrent\updates\7.10.3_44495\bittorrentie.exe     "C:\Users\Rick\AppData\Roaming\BitTorrent\updates\7.10.3_44495\bittorrentie.exe" BitTorrent_2836_00313D08_590648902 BT4823DF041B09 BitTorrent   C:\Users\Rick\AppData\Roaming\BitTorrent\updates\7.10.3_44495\bittorrentie.exe
* 2844  2728    WebCompanion.e  0xfa801b2f02e0  0       -       1      False    2018-08-04 19:27:07.000000      2018-08-04 19:33:33.000000     \Device\HarddiskVolume1\Program Files (x86)\Lavasoft\Web Companion\Application\WebCompanion.exe  -       -
3880    1484    WebCompanionIn  0xfa801b18f060  15      522     0      True     2018-08-04 19:33:07.000000      N/A     \Device\HarddiskVolume1\Program Files (x86)\Lavasoft\Web Companion\Application\WebCompanionInstaller.exe        "C:\Program Files (x86)\Lavasoft\Web Companion\Application\WebCompanionInstaller.exe" --update --prod --partner=BT170701 --version=4.3.1908.3686        C:\Program Files (x86)\Lavasoft\Web Companion\Application\WebCompanionInstaller.exe
* 452   3880    sc.exe  0xfa801aeb6890  0       -       0       False  2018-08-04 19:33:48.000000       2018-08-04 19:33:48.000000      \Device\HarddiskVolume1\Windows\SysWOW64\sc.exe -       -
* 3208  3880    sc.exe  0xfa801b08f060  0       -       0       False  2018-08-04 19:33:47.000000       2018-08-04 19:33:48.000000      \Device\HarddiskVolume1\Windows\SysWOW64\sc.exe -       -
* 2028  3880    sc.exe  0xfa801ac01060  0       -       0       False  2018-08-04 19:33:49.000000       2018-08-04 19:34:03.000000      \Device\HarddiskVolume1\Windows\SysWOW64\sc.exe -       -
* 3856  3880    WebCompanion.e  0xfa801a6268b0  15      386     0      True     2018-08-04 19:34:05.000000      N/A     \Device\HarddiskVolume1\Program Files (x86)\Lavasoft\Web Companion\Application\WebCompanion.exe"C:\Program Files (x86)\Lavasoft\Web Companion\Application\WebCompanion.exe" --silent --update   C:\Program Files (x86)\Lavasoft\Web Companion\Application\WebCompanion.exe
* 3504  3880    sc.exe  0xfa801aa72b30  0       -       0       False  2018-08-04 19:33:48.000000       2018-08-04 19:33:48.000000      \Device\HarddiskVolume1\Windows\SysWOW64\sc.exe -       -
3304    3132    notepad.exe     0xfa801b1fd960  2       79      1      False    2018-08-04 19:34:10.000000      N/A     \Device\HarddiskVolume1\Windows\System32\notepad.exe    "C:\Windows\system32\NOTEPAD.EXE" C:\Users\Rick\Desktop\Flag.txt.WINDOWS        C:\Windows\system32\NOTEPAD.EXE
```
LunarMS.exe is the name of an old videogame.
### CTF{LunarMS}

To find the IP address of the server, I used grep to search for LunarMS in the netscan:

```
python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem netscan | grep "LunarMS"

0x7d6124d0      TCPv4   192.168.202.131 49530   77.102.199.102  7575   CLOSED   708     LunarMS.exe     -
0x7e413a40      TCPv4   -       0       -       0       CLOSED  708    LunarMS.exe      -
0x7e521b50      TCPv4   -       0       -       0       CLOSED  708    LunarMS.exe
```
### CTF{77.102.199.102}

## QUESTION 4 - Name Game
We know that the account was logged into a channel called Lunar-3.  What is the account name?

The account name will be in the process memory.  I used windows.memmap with --dump and the process id --pid 708.

```
python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem windows.memmap --dump --pid 708
```

This created a file named, pid.708.dmp.  I used the strings and grep commands to find 10 lines above and below "Lunar-3".
Here's a partial list.  Given the references to otters in this challenge, 0tt3r8r33z3, seems likely to be the flag.
                 
```
─$ strings pid.708.dmp | grep -C 10 "Lunar-3"  
{qv1
...
Lunar-3
0tt3r8r33z3
Sound/UI.img/
BtMouseClick
Lunar-4
Lunar-1
Lunar-2
ScrollUp
Title
RollDown
WorldSelect
```
### CTF{0tt3r8r33z3}

## QUESTION 5 - Name Game 2
The username of the logged on character is always after this signature: 0x64 0x??{6-8} 0x40 0x06 0x??{18} 0x5a 0x0c 0x00{2}
What is rick's character's name?

I used ssd to display bytes and grep to search for the end of the target signature:

```
─$ xxd pid.708.dmp| grep "5a0c 0000"  
...
0c33a4a0: 9a23 3223 0b00 0001 5a0c 0000 4d30 7274  .#2#....Z...M0rt
0e85cba0: 1000 0000 0035 c150 0000 0000 5a0c 0000  .....5.P....Z...
0ecfa5c0: 0035 c150 0000 0000 5a0c 0000 b460 9047  .5.P....Z....`.G
0ecfad80: 0000 0000 5a0c 0000 40f3 9047 1000 0000  ....Z...@..G....
0ed06370: 1000 0000 0035 c150 b033 b046 5a0c 0000  .....5.P.3.FZ...
0ed25c60: 1000 0000 0035 c150 0000 0000 5a0c 0000  .....5.P....Z...
107ee770: 1000 0000 0035 c150 0000 0000 5a0c 0000  .....5.P....Z...
109397e0: 5a0c 0000 3100 3000 3500 3200 3000 3000  Z...1.0.5.2.0.0.
10b3ca20: 5a0c 0000 2000 0000 0000 0000 40a0 cd49  Z... .......@..I
10f27d50: 0000 0000 5a0c 0000 50a9 df48 1000 0000  ....Z...P..H....
111e3e60: 5a0c 0000 6d00 6100 7000 2f00 6f00 6200  Z...m.a.p./.o.b.
122f9a00: 5a0c 0000 5300 7400 7200 6900 6e00 6700  Z...S.t.r.i.n.g.
12cf83d0: 5a0c 0000 5300 6800 6100 7000 6500 3200  Z...S.h.a.p.e.2.
12d183d0: 5a0c 0000 4500 7400 6300 2f00 4300 6f00  Z...E.t.c./.C.o.
12d383d0: 5a0c 0000 5300 6800 6100 7000 6500 3200  Z...S.h.a.p.e.2.
12d786f0: 5a0c 0000 4500 7400 6300 2f00 4300 6f00  Z...E.t.c./.C.o.
12f38650: 5a0c 0000 7400 7200 6100 6400 6500 4100  Z...t.r.a.d.e.A.
131582d0: 5a0c 0000 4500 7400 6300 2f00 4300 6f00  Z...E.t.c./.C.o.
133c9870: 174c c31e 0000 0080 5a0c 0000 4500 7400  .L......Z...E.t.
20b05fc0: b0e5 af00 5a0c 0000 4d30 7274 794c 304c  ....Z...M0rtyL0L
...
```

The line with address 0c33a4a0 contains some readable text, M0rt.  I used xxd with -s start at this address: 0x0c33a4aC and stopped after 16 octets as indicated by -l 16

```
xxd -s 0x0c33a4aC -l 16 pid.708.dmp
0c33a4ac: 4d30 7274 794c 304c 0000 0000 0000 0021  M0rtyL0L.......!
```
### CTF{M0rtyL0L}
 
## QUESTION 6 - Silly Rick
Rick always forgets his email password and uses a Stored Password SErvice online to store
his password.  He always copy-paste the password.  What is Rick's email password?

The clipboard plugin has not been ported to Volatility 3.

### TODO:  Find another solution 

## QUESTION 7 - Hide and Seek
Rick's PC memory dump contains malware.  Find the name of the malware including the extension.

The pstree command lists the processes.  There are quite a few, so I listed them to a text file that I can open in a text editor.

```
$ python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem windows.pstree.PsTree > exp_pstree.txt
``` 

I reviewed the processes and found some interesting possibilities:

```
* 3820	2728	Rick And Morty	0xfa801b486b30	4	185	1	True	2018-08-04 19:32:55.000000 	N/A	\Device\HarddiskVolume1\Torrents\Rick And Morty season 1 download.exe	"C:\Torrents\Rick And Morty season 1 download.exe" 	C:\Torrents\Rick And Morty season 1 download.exe
** 3720	3820	vmware-tray.ex	0xfa801a4c5b30	8	147	1	True	2018-08-04 19:33:02.000000 	N/A	\Device\HarddiskVolume1\Users\Rick\AppData\Local\Temp\RarSFX0\vmware-tray.exe	"C:\Users\Rick\AppData\Local\Temp\RarSFX0\vmware-tray.exe" 	C:\Users\Rick\AppData\Local\Temp\RarSFX0\vmware-tray.exe

3304	3132	notepad.exe	0xfa801b1fd960	2	79	1	False	2018-08-04 19:34:10.000000 	N/A	\Device\HarddiskVolume1\Windows\System32\notepad.exe	"C:\Windows\system32\NOTEPAD.EXE" C:\Users\Rick\Desktop\Flag.txt.WINDOWS	C:\Windows\system32\NOTEPAD.EXE
```

The plugin cmdline shows the full command line associated with a process.

```
$ python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem windows.cmdline.CmdLine --pid 3820

PID     Process Args

3820    Rick And Morty  "C:\Torrents\Rick And Morty season 1 download.exe" 
```

```
python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem windows.cmdline.CmdLine --pid 3720

PID     Process Args

3720    vmware-tray.ex  "C:\Users\Rick\AppData\Local\Temp\RarSFX0\vmware-tray.exe" 
``` 

```
$ python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem windows.cmdline.CmdLine --pid 3304

PID     Process Args

3304    notepad.exe     "C:\Windows\system32\NOTEPAD.EXE" C:\Users\Rick\Desktop\Flag.txt.WINDOWS
```

An application running from a users \AppData\Local\Temp\ folder is odd.  This is likely to be the name of the malware. 

### CTF{vmware-tray.exe}

## QUESTION 8 - Path to Glory
How did the malware get installed?  It must be because of one of Rick's bad habits.

Previously, I found file pathes indicating the Bittorrent was involved.
What is the torrent file associated with the vmware-tray.exe?  I searched for "rick and morty"

```
$ python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem filescan | grep -i "rick and morty"

0x7d63dbc0 100.0\Torrents\Rick And Morty season 1 download.exe  216
0x7d6b3a10      \Torrents\Rick and Morty - Season 3 (2017) [1080p]\Rick.and.Morty.S03E07.The.Ricklantis.Mixup.1080p.Amazon.WEB-DL.x264-Rapta.mkv       216
0x7d7adb50      \Torrents\Rick and Morty - Season 3 (2017) [1080p]\Rick.and.Morty.S03E06.Rest.and.Ricklaxation.1080p.Amazon.WEB-DL.x264-Rapta.mkv      216

0x7d8813c0      \Users\Rick\Downloads\Rick And Morty season 1 download.exe.torrent    216

0x7da56240      \Torrents\Rick And Morty season 1 download.exe  216
0x7dae9350      \Users\Rick\AppData\Roaming\BitTorrent\Rick And Morty season 1 download.exe.1.torrent  216

0x7dcbf6f0      \Users\Rick\AppData\Roaming\BitTorrent\Rick And Morty season 1 download.exe.1.torrent  216
0x7e5f5d10      \Torrents\Rick and Morty Season 2 [WEBRIP] [1080p] [HEVC]\[pseudo] Rick and Morty S02E03 Auto Erotic Assimilation [1080p] [h.265].mkv  216
0x7e710070      \Torrents\Rick And Morty season 1 download.exe  216
0x7e7ae700      \Torrents\Rick and Morty Season 2 [WEBRIP] [1080p] [HEVC]\Sample\Screenshot 08.png     216
``` 

I extracted the files from memory

```
$ python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem dumpfiles --physaddr 0x7d8813c0

Cache   FileObject      FileName        Result
DataSectionObject       0x7d8813c0      Rick And Morty season 1 download.exe.torrent  file.0x7d8813c0.0xfa801af10010.DataSectionObject.Rick And Morty season 1 download.exe.torrent.dat
                 
$ python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem dumpfiles --physaddr 0x7dae9350

Cache   FileObject      FileName        Result
DataSectionObject       0x7dae9350      Rick And Morty season 1 download.exe.1.torrentfile.0x7dae9350.0xfa801b42c9e0.DataSectionObject.Rick And Morty season 1 download.exe.1.torrent.dat
```

```
└─$ strings file.0x7d8813c0.0xfa801af10010.DataSectionObject.Rick\ And\ Morty\ season\ 1\ download.exe.torrent.dat 
[ZoneTransfer]
ZoneId=3
                                                                                       
└─$ strings file.0x7dae9350.0xfa801b42c9e0.DataSectionObject.Rick\ And\ Morty\ season\ 1\ download.exe.1.torrent.dat 
d8:announce44:udp://tracker.openbittorrent.com:80/announce13:announce-listll44:udp://tracker.openbittorrent.com:80/announceel42:udp://tracker.opentrackr.org:1337/announceee10:created by17:BitTorrent/7.10.313:creation datei1533150595e8:encoding5:UTF-84:infod6:lengthi456670e4:name36:Rick And Morty season 1 download.exe12:piece lengthi16384e6:pieces560:\I
!PC<^X
B.k_Rk
0<;O87o
!4^"
3hq,
&iW1|
K68:o
w~Q~YT
$$o9p
bwF:u
e7:website19:M3an_T0rren7_4_R!cke
```
### CTF{M3an_T0rren7_4_R!cke}

## QUESTION 9 - Path to Glory 2
Continue the search to find the way the malware got in

The ZoneID=3 extracted in the last question indicates that the torrent was downloaded from the internet.  chrome.exe appears frequently in the pstree output.

```
* 4076	2728	chrome.exe	0xfa801a4e3870	44	1160	1	False	2018-08-04 19:29:30.000000 	N/A	\Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe	"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" 	C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
** 576	4076	chrome.exe	0xfa801a502b30	2	58	1	False	2018-08-04 19:29:31.000000 	N/A	\Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe	"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=watcher --main-thread-id=4080 --on-initialized-event-handle=304 --parent-handle=308 /prefetch:6	C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
** 3648	4076	chrome.exe	0xfa801a635240	16	207	1	False	2018-08-04 19:33:38.000000 	N/A	\Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe	"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=renderer --field-trial-handle=984,15358569600588498425,3475374789430647391,131072 --service-pipe-token=66BB0CC3FE10242BC701AB87A5940738 --lang=en-US --enable-offline-auto-reload --enable-offline-auto-reload-visible-only --device-scale-factor=1 --num-raster-threads=1 --service-request-channel-token=66BB0CC3FE10242BC701AB87A5940738 --renderer-client-id=30 --mojo-platform-channel-handle=4516 /prefetch:1	C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
** 1796	4076	chrome.exe	0xfa801a5ef1f0	15	170	1	False	2018-08-04 19:33:41.000000 	N/A	\Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe	"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=renderer --field-trial-handle=984,15358569600588498425,3475374789430647391,131072 --service-pipe-token=86C637812F74263DD98834CC0FE01CE7 --lang=en-US --enable-offline-auto-reload --enable-offline-auto-reload-visible-only --device-scale-factor=1 --num-raster-threads=1 --service-request-channel-token=86C637812F74263DD98834CC0FE01CE7 --renderer-client-id=31 --mojo-platform-channel-handle=4412 /prefetch:1	C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
** 1808	4076	chrome.exe	0xfa801a4f7b30	13	229	1	False	2018-08-04 19:29:32.000000 	N/A	\Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe	"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=gpu-process --field-trial-handle=984,15358569600588498425,3475374789430647391,131072 --gpu-preferences=KAAAAAAAAACAAwBAAQAAAAAAAAAAAGAAEAAAAAAAAAAAAAAAAAAAACgAAAAEAAAAIAAAAAAAAAAoAAAAAAAAADAAAAAAAAAAOAAAAAAAAAAQAAAAAAAAAAAAAAAKAAAAEAAAAAAAAAAAAAAACwAAABAAAAAAAAAAAQAAAAoAAAAQAAAAAAAAAAEAAAALAAAA --service-request-channel-token=4939AD179421E7F7FF934CA7C25FCD34 --mojo-platform-channel-handle=1004 --ignored=" --type=renderer " /prefetch:2	C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
** 4084	4076	chrome.exe	0xfa801a4eab30	8	86	1	False	2018-08-04 19:29:30.000000 	N/A	\Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe	"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=crashpad-handler "--user-data-dir=C:\Users\Rick\AppData\Local\Google\Chrome\User Data" /prefetch:7 --monitor-self-annotation=ptype=crashpad-handler "--database=C:\Users\Rick\AppData\Local\Google\Chrome\User Data\Crashpad" "--metrics-dir=C:\Users\Rick\AppData\Local\Google\Chrome\User Data" --url=https://clients2.google.com/cr/report --annotation=channel= --annotation=plat=Win64 --annotation=prod=Chrome --annotation=ver=68.0.3440.84 --initial-client-data=0x7c,0x80,0x84,0x78,0x88,0x7feeb3324d0,0x7feeb3324e0,0x7feeb3324f0	C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
** 3924	4076	chrome.exe	0xfa801aa00a90	16	228	1	False	2018-08-04 19:29:51.000000 	N/A	\Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe	"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=renderer --field-trial-handle=984,15358569600588498425,3475374789430647391,131072 --service-pipe-token=BB216EAECD5332095D1836CB17604E02 --lang=en-US --enable-offline-auto-reload --enable-offline-auto-reload-visible-only --device-scale-factor=1 --num-raster-threads=1 --service-request-channel-token=BB216EAECD5332095D1836CB17604E02 --renderer-client-id=9 --mojo-platform-channel-handle=2440 /prefetch:1	C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
** 2748	4076	chrome.exe	0xfa801a7f98f0	15	181	1	False	2018-08-04 19:31:15.000000 	N/A	\Device\HarddiskVolume1\Program Files (x86)\Google\Chrome\Application\chrome.exe	"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=renderer --field-trial-handle=984,15358569600588498425,3475374789430647391,131072 --service-pipe-token=5B96B12CED256E93CD66ABC8626426FB --lang=en-US --enable-offline-auto-reload --enable-offline-auto-reload-visible-only --device-scale-factor=1 --num-raster-threads=1 --service-request-channel-token=5B96B12CED256E93CD66ABC8626426FB --renderer-client-id=22 --mojo-platform-channel-handle=2104 /prefetch:1	C:\Program Files (x86)\Google\Chrome\Application\chrome.exe

```
Google Chrome may be the primary browser.  I found the Chrome history database and renamed it as a sqlite file, chrome-history.sqlite.  Then, I used sqlite3 to query it.

```
python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem filescan | grep -i "history"
0x7d45dcc0 100.0\Users\Rick\AppData\Local\Google\Chrome\User Data\Default\History       216

python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem dumpfiles --physaddr 0x7d45dcc0
Cache   FileObject      FileName        Result
DataSectionObject       0x7d45dcc0      History file.0x7d45dcc0.0xfa801a5193d0.DataSectionObject.History.dat
SharedCacheMap  0x7d45dcc0      History Error dumping file


└─$ mv file.0x7d45dcc0.0xfa801a5193d0.DataSectionObject.History.dat chrome-history.sqlite


└─$ sqlite3 chrome-history.sqlite
SQLite version 3.44.0 2023-11-01 11:23:50
Enter ".help" for usage hints.
sqlite> select current_path, site_url from downloads;
C:\Users\Rick\Downloads\BitTorrent.exe|https://bittorrent.com/
C:\Users\Rick\Downloads\MSSetupv83.exe|https://mega.nz/
C:\Users\Rick\Downloads\Lunar Client & WZ.zip|https://mega.nz/

C:\Users\Rick\Downloads\Rick And Morty season 1 download.torrent|https://mail.com/
C:\Users\Rick\Downloads\Rick And Morty season 1 download.torrent|https://mail.com/
C:\Users\Rick\Downloads\Rick And Morty season 1 download.exe.torrent|https://mail.com/

C:\Users\Rick\Downloads\NDP40-KB2468871-v2-x64.exe|https://microsoft.com/
C:\Users\Rick\Downloads\dotNetFx40_Full_x86_x64.exe|https://microsoft.com/

C:\Users\Rick\Downloads\Rick And Morty season 1 download.exe.torrent|https://mail.com/
```                 

I copied the strings in OtterCTF.vmem to a file then searched this file for "@mail.com"

```
└─$ strings /home/kali/13_memory/OtterCTF.vmem > exp_OtterCTF.strings
                                                                                                
└─$ grep "@mail.com" exp_OtterCTF.strings 
...
J{"hashedUasAccountId":"3b5111bbdcbf2e135643a87a37fb6abc","age":26,"firstName":"Rick","sex":"MALE","zipcode":"","country":"IL","city":" ","email":"RickoPicko@mail.com","locale":"en_US","userlevel":0,"activeTheme":"intenseblue","region":"IL","ua":{"platform":"Windows","browser":"Chrome","version":"68.0","deviceclass":"desktop"}}0
n"rickopicko@mail.com" <rickopicko@mail.com>
...

$ grep -A 20 "@mail.com" exp_OtterCTF.strings
...
n"rickopicko@mail.com" <rickopicko@mail.com>
button transparent normal closeconfirmboxsm
jSpecial Offer: 20% off your first order!jss
jhttps://sb.scorecardresearch.com/beacon.js'
digitalmars-d-announce-request@puremagic.com
font-family: Verdana;font-size: 12.0px;.pnge
JLAST CHANCE: 20% off your first order.com
navigation-collapse toggle-resolution.comsQ=
M8.81 5h2.4l-.18 7H8.98l-.17-7zM9 14h2v2H9z=
simple-icon_mail-classification-feedbackmKw=
form-composite-switchable-content_condition
form-composite-addresschooser_textfieldc.com
SPnvideo-label video-title trc_ellipsis  ]"sAE=
display:inline;width:56px;height:200px;m>

Hum@n_I5_Th3_Weak3s7_Link_In_Th3_Ch@inYear

//sec-s.uicdn.com/nav-cdn/home/preloader.gif
simple-icon_toolbar-change-view-horizontal
 nnx-track-sec-click-communication-inboxic.com
nx-track-sec-click-dashboard-hide_smileyable
Nftd-box stem-north big fullsize js-focusable
js-box-flex need-overlay js-componentone
...

```                                                 

### CTF{Hum@n_I5_Th3_Weak3s7_Link_In_Th3_Ch@in}

## QUESTION 10 - Bit 4 Bit
The malware on this machine is ransomware.  Find the attacker's bitcoin address.

Attackers usually post a ransomware note on the Desktop.
```
python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem filescan | grep -i "Desktop"    
0x7d660500 100.0\Users\Rick\Desktop\READ_IT.txt 216
0x7e410890      \Users\Rick\Desktop\Flag.txt    216
```           

Two files look interesting, READ_IT.txt and Flag.txt

```
─$ cat file.0x7d660500.0xfa801b2def10.DataSectionObject.READ_IT.txt.dat 
Your files have been encrypted.
Read the Program for more information
read program for more information.
```

```
$ hexdump file.0x7e410890.0xfa801b0532e0.DataSectionObject.Flag.txt.dat 
0000000 e67b 5624 5c9e ef0f 438e f728 c5e4 ff83
0000010 316c e6d7 da1c 54ea 72cf d6dd 7eec 7bb0
0000020 8dc6 a8d0 c2cc 6ece ee3e 4703 0bc1 e8b3
0000030 0000 0000 0000 0000 0000 0000 0000 0000
*
0001000
```
I tried using CyberChef to decode flag.txt but no luck.

The ransomware message says to read program for more information.  I found the PID for the ransomware in Question 7 so I can dump the process memory, then run strings with the -e l argument to search for Unicode strings that may contain the bitcoin address.

```
python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem windows.memmap --pid 3720 --dump

$ strings -e l pid.3720.dmp | grep -i -A 5 "ransom"

This is Ransomware. It locks your files until you pay for them. Before you ask, Yes we will
give you your files back once you pay and our server confrim that you pay.
Send 0.16 to the address below.

I paid, Now give me back my files.
1MmpEmebJkqXG8nQv4cjJSmxZQFVmFo63M
```

### CTF{1MmpEmebJkqXG8nQv4cjJSmxZQFVmFo63M}

## QUESTION 11 - Graphics for the Weak

There's something fishy in the malware's graphics

windows.psscan.PsScan - Scans for processes present in a particular windows memory image.

```
python3 vol.py -f /home/kali/13_memory/OtterCTF.vmem windows.psscan.PsScan --pid 3720 --dump

PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime File output
3720    3820    vmware-tray.ex  0x7e6c5b30      8       147     1       True    2018-08-04 19:33:02.000000      N/A       3720.vmware-tray.ex.0xec0000.dmp

$ binwalk 3720.vmware-tray.ex.0xec0000.dmp

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Microsoft executable, portable (PE)
16858         0x41DA          Copyright string: "CopyrightAttribute"
123968        0x1E440         PNG image, 4800 x 1454, 8-bit/color RGBA, non-interlaced
124096        0x1E4C0         Zlib compressed data, compressed
351778        0x55E22         PNG image, 800 x 600, 8-bit colormap, non-interlaced
352191        0x55FBF         Zlib compressed data, best compression
434911        0x6A2DF         XML document, version: "1.0"

$ foremost -t png 3720.vmware-tray.ex.0xec0000.dmp
Processing: 3720.vmware-tray.ex.0xec0000.dmp
|*|
```

I opened the .png file in /output/png to view the flag

[Flag image](S0_Just_M0v3_Socy.png)

### CTF{S0_Just_M0v3_Socy}

## QUESTION 12 - Recovery
Rick's files were recovered.  What is the random password used to encrypt the files?

I extracted the unicode encoding using the -e option to specify the encoding method with l for little-endian UTF-16 encoding.

```
─$ strings -e l /home/kali/13_memory/OtterCTF.vmem > exp_unicode.txt
```

Then, I followed the original instructions and experimented with various strings.  Grepping the computer name resulted in finding the password.

```
─$ grep "WIN-LO6FAF3DTFE" exp_unicode.txt | sort | uniq
...
\\WIN-LO6FAF3DTFE\print$\x64\3\XPSSVCS.DLL
WIN-LO6FAF3DTFE\Ri
WIN-LO6FAF3DTFE\Ric
WIN-LO6FAF3DTFE\Rick
WIN-LO6FAF3DTFERick
WIN-LO6FAF3DTFE-Rick aDOBofVYUNVnmp7
...
```
### CTF{aDOBofVYUNVnmp7}

## QUESTION 13 - Closure
Using this password, can you decrypt Rick's files?

I extracted the malware executable in question 11 and stored it in a file called, 3720.vmware-tray.ex.0xec0000.dmp

I computed the SHA1 hash and checked whether it was posted on VirusTotal.  Unfortunately, the SHA1 that I computed did not match the SHA1 computed in the original writeup.  This is likely because the original writeup used procdump from Volatility 2 and I used psscan from Volatility 3.

```
$ sha1sum 3720.vmware-tray.ex.0xec0000.dmp  
509c42cd05662491c3066a71f444e6d4a471df39  3720.vmware-tray.ex.0xec0000.dmp
```

```
xxd file.0x7e410890.0xfa801b0532e0.DataSectionObject.Flag.txt.dat
00000000: 7be6 2456 9e5c 0fef 8e43 28f7 e4c5 83ff  {.$V.\...C(.....
00000010: 6c31 d7e6 1cda ea54 cf72 ddd6 ec7e b07b  l1.....T.r...~.{
00000020: c68d d0a8 ccc2 ce6e 3eee 0347 c10b b3e8  .......n>..G....
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
(more padding)
00000ff0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

I extracted the meaningful bytes into a new file, flag.txt

```
$ dd bs=1 count=48 if=file.0x7e410890.0xfa801b0532e0.DataSectionObject.Flag.txt.dat of=flag.txt
48+0 records in
48+0 records out
48 bytes copied, 0.000173807 s, 276 kB/s
                                                                           
└─$ xxd flag.txt                                                     
00000000: 7be6 2456 9e5c 0fef 8e43 28f7 e4c5 83ff  {.$V.\...C(.....
00000010: 6c31 d7e6 1cda ea54 cf72 ddd6 ec7e b07b  l1.....T.r...~.{
00000020: c68d d0a8 ccc2 ce6e 3eee 0347 c10b b3e8  .......n>..G....
```

The original writeup explains how to decrypt this password using a Windows 7 VM.



