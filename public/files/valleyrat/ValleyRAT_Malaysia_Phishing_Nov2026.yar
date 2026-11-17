/*
    ValleyRAT / Winos 4.0 - Multi-stage phishing campaign targeting Malaysia
    Author    : Fadhil (fj4rr)
    Date      : 2026-11-07
    Reference : https://github.com/fj4rr/malware-analysis (folder "Phising Malware Targetting Malaysia")
    Analysis  : 1-6 Nov 2026 (static + two dynamic runs, Windows 10 and Windows 11)

    STATUS: compile-checked only. NOT yet validated against a clean corpus or
    VirusTotal retrohunt. Test for false positives before production use.

    Scope per rule:
      - *_Hashes          : exact sample IOCs (files carved from the PCAP / disk)
      - *_Stage1_Shellcode: decoded Stage 1 shellcode (memory dump / sandbox dump)
      - *_Stager          : Stage 2 embedded DLL (Online Module, 上线模块.dll)
      - *_LoginModule     : RAT client (Login Module, 登录模块.dll) and its cache blob
      - *_Plugin_KillAV   : KILL杀毒.dll and its dropped cache.exe
      - *_Plugin_Persist  : 启动项.dll
      - *_Driver_*        : abused vulnerable drivers (hunting, legitimate signed drivers)
      - *_Module_Blob     : 0xA44-header module blob as stored in HKCU\CC\0 / HKCU\Console\0
*/

import "pe"
import "hash"

rule MAL_ValleyRAT_Malaysia_Hashes
{
    meta:
        description = "Exact hashes of carved samples from the ValleyRAT campaign targeting Malaysia (Nov 2026)"
        author      = "Fadhil (fj4rr)"
        date        = "2026-11-07"
        status      = "not validated"
        note        = "view.exe / OP01.exe / svchostsr.exe (CEF host, SHA-256 78fc25ed...0736) is intentionally excluded"
    condition:
        filesize > 30KB and filesize < 12MB and
        (
        hash.sha256(0, filesize) == "2c68a6e7cf46f791164e9b708af47faf2654ba6569522309ee037c39d24cdc22"  // libcef.dll
        or hash.sha256(0, filesize) == "8a1ef3f3b9606deea8bfa50419acd2ea583a42298ed301a5d7533c855e95e65c"  // Stage 2 raw
        or hash.sha256(0, filesize) == "89ecf3e82d8ed7834244a6837523bc3fe1eb5cb4ad9cb81ee935628116ab74c5"  // Stage 2 decoded
        or hash.sha256(0, filesize) == "607599486156203946451be3c239f72f7090b0f63a214a38c48e504c41f99f05"  // stager DLL
        or hash.sha256(0, filesize) == "8947818d801513f303b92091e6302a520593944615b1e8b51d77722374d364a2"  // login_module_cache.bin
        or hash.sha256(0, filesize) == "fe057e29571b291c44ee2f7fc5d7302132f4ace65d361b629858dd00fda7fe2c"  // login module PE
        or hash.sha256(0, filesize) == "70bcec00c215fe52779700f74e9bd669ff836f594df92381cbfb7ee0568e7a8b"  // Safetica driver as dropped
        or hash.sha256(0, filesize) == "ff5dbdcf6d7ae5d97b6f3ef412df0b977ba4a844c45b30ca78c0eeb2653d69a8"  // kvckiller.sys (wsftprm.sys)
        or hash.sha256(0, filesize) == "46f65f7089e8bf0468a096247243d513f4667a964c239ea00334431122f1a544"  // cache.exe
        or hash.sha256(0, filesize) == "ce1b8e12bd470c5da0475d6a92e5e2769b08aa1d52903b83d8a1d07ba54d82c5"  // KILL plugin blob
        or hash.sha256(0, filesize) == "a31ca2ab16e6667f8bd99a67929d446b7f739ffe41e65e01d4fbf85b585ee3d1"  // KILL plugin blob (_bin)
        or hash.sha256(0, filesize) == "0a45c00d0942d28044f5c16bf40cbb62abcbb8492053c50ad1dcf4abda0f68d7"  // KILL plugin PE
        or hash.sha256(0, filesize) == "8086dd3c153096c68bf65ae4c4b16a6e234ff17f676924054ca9f2679005da97"  // Persist plugin blob
        or hash.sha256(0, filesize) == "549a0238fe3c1fbc38c51743fe6aa2ac497c91a375d125196dd779b5f4268224"  // Persist plugin blob (_bin)
        or hash.sha256(0, filesize) == "03f0d1bed58a1c88ed963c60e5d72b2ab21203f369b81a636bd7e0e5f652ebb3"  // Persist plugin PE
    )
}

rule MAL_ValleyRAT_Malaysia_Stage1_Shellcode
{
    meta:
        description = "Decoded Stage 1 x86 shellcode: PEB walk with 0x83 API hashing, 'codemark' config marker (memory / sandbox dump)"
        author      = "Fadhil (fj4rr)"
        date        = "2026-11-07"
        status      = "not validated"
    strings:
        $marker = "codemark" ascii

        // API hashes (little-endian immediates) used by sub_70B
        $h_kernel32 = { E6 9C CA 1C }   // 0x1CCA9CE6 KERNEL32.DLL
        $h_getproc  = { 54 B8 B9 1A }   // 0x1AB9B854 GetProcAddress
        $h_loadlib  = { 78 1F 20 7F }   // 0x7F201F78 LoadLibraryA
        $h_valloc   = { 62 34 89 5E }   // 0x5E893462 VirtualAlloc
        $h_wsastart = { 34 26 52 33 }   // 0x33522634 WSAStartup
        $h_connect  = { DA 50 2B 09 }   // 0x092B50DA connect
        $h_send     = { DC 87 83 0F }   // 0x0F8387DC send
        $h_recv     = { B2 34 61 0F }   // 0x0F6134B2 recv
    condition:
        filesize < 200KB and
        6 of ($h_*) and
        $marker
}

rule MAL_ValleyRAT_Malaysia_Stage1_Config_Reversed
{
    meta:
        description = "Stage 1 embedded configuration, stored as reversed UTF-16LE text (C2 186.241.116.135, group/version/build keys)"
        author      = "Fadhil (fj4rr)"
        date        = "2026-11-07"
        status      = "not validated"
        note        = "Matches this build's C2 IP; the key layout (p1/o1/t1 ... bz) is the reusable part"
    strings:
        // reversed "p1:186.241.116.135"
        $ip_rev   = "531.611.142.681:1p" wide
        // reversed "bz:2026.10.26"
        $bz_rev   = "62.01.6202:zb" wide
        // reversed "fz:默认" is not reliable; the key suffixes below are
        $k_rev1   = "|1:1t|" wide
        $k_rev2   = "|0:db|" wide
    condition:
        $ip_rev or ($bz_rev and 1 of ($k_rev*))
}

rule MAL_ValleyRAT_Malaysia_Stager_OnlineModule
{
    meta:
        description = "Stage 2 embedded DLL (上线模块.dll / Online Module): exports CCTG, load, run plus config parser and cache strings"
        author      = "Fadhil (fj4rr)"
        date        = "2026-11-07"
        status      = "not validated"
    strings:
        $marker   = "denglupeizhi" ascii
        $cache1   = "R32f351a4aeea5e608853d1a56661059" ascii wide
        $cache2   = "IpDate" ascii wide
        $tracer   = "tracerpt.exe" ascii wide nocase
        $kcp      = "CArqSessionT" ascii
    condition:
        uint16(0) == 0x5A4D and
        pe.is_dll() and
        pe.exports("CCTG") and pe.exports("load") and pe.exports("run") and
        ( $marker or $cache1 ) and
        1 of ($cache2, $tracer, $kcp)
}

rule MAL_ValleyRAT_Malaysia_LoginModule
{
    meta:
        description = "ValleyRAT Login Module (登录模块.dll) RAT client: marker strings, single-instance mutex, plugin loader markers, Safetica driver service"
        author      = "Fadhil (fj4rr)"
        date        = "2026-11-07"
        status      = "not validated"
    strings:
        $m1 = "denglupeizhi" ascii
        $m2 = "plugmark" ascii
        $m3 = "onlyloadinmyself" ascii
        $m4 = "Global\\MyUniqueApp_SingleInstance" wide ascii
        $d1 = "STProcessMonitorDriver" wide ascii
        $d2 = "EmbeddedDriverService" wide ascii
        $r1 = "IpDatespecial" wide ascii
        $r2 = "R32f351a4aeea5e608853d1a56661059" wide ascii
        $cmstp = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" wide ascii nocase
    condition:
        2 of ($m*) or
        (1 of ($m*) and 2 of ($d*, $r*, $cmstp)) or
        ($cmstp and $d2 and $r1)
}

rule MAL_ValleyRAT_Malaysia_Plugin_KillAV
{
    meta:
        description = "KILL杀毒.dll plugin and its dropped cache.exe: wsftprm.sys (CVE-2023-52271) driver loader with IFEO hive-snapshot hijack of Defender"
        author      = "Fadhil (fj4rr)"
        date        = "2026-11-07"
        status      = "not validated"
    strings:
        $dev   = "\\\\.\\Warsaw_PM" ascii wide
        $svc   = "wsftprm" ascii wide
        $ifeo  = "TempIFEO" ascii wide
        $hive  = "Ifeo.hiv" ascii wide
        $sys   = "kvckiller.sys" ascii wide
        $dbg   = "systray.exe" ascii wide
        $s1    = "WinDefCtl.exe" ascii wide
        $s2    = "Adding IFEO block for MsMpEng.exe" ascii
        $s3    = "IDR_DRIVER resource not found" ascii
        $priv  = "SeLoadDriverPrivilege" ascii wide
        $exp   = "Project1.dll" ascii
    condition:
        (any of ($s*)) and ($ifeo or $hive) and 2 of ($dev, $svc, $sys, $dbg, $priv, $exp)
}

rule MAL_ValleyRAT_Malaysia_Plugin_Persistence
{
    meta:
        description = "启动项.dll plugin (export name 'Scheduled Task.dll'): copies the loader folder to C:\\Users\\Public as svchostsr.exe and sets Run key RunApp"
        author      = "Fadhil (fj4rr)"
        date        = "2026-11-07"
        status      = "not validated"
    strings:
        $exp   = "Scheduled Task.dll" ascii
        $name  = "svchostsr.exe" ascii wide
        $run   = "RunApp" ascii wide
        $pub   = "C:\\Users\\Public" ascii wide nocase
        $cef   = "libcef.dll" ascii wide
        $cpl   = "wmiclntui.cpl" ascii wide
        $left  = "新版本32" wide
    condition:
        ($exp and 1 of ($name, $run)) or
        ($name and $run and $pub and ($cef or $cpl)) or
        ($left and 1 of ($name, $run))
}

rule MAL_ValleyRAT_Malaysia_Module_Blob
{
    meta:
        description = "Module blob with the 0xA44-byte header as cached in HKCU\\CC\\0 or HKCU\\Console\\0 (or carved from the C2 stream)"
        author      = "Fadhil (fj4rr)"
        date        = "2026-11-07"
        status      = "not validated"
        note        = "Header: payload size at +0x208, 32-char UTF-16LE module identifier (MD5 of body) at +0x20C, PE at +0xA44 (.dll) or +0x1004 (.dll_bin / login cache: 0x1003)"
    condition:
        filesize > 300KB and filesize < 600KB and
        uint32(0x208) == filesize - 0xA44 and
        for all i in (0..31) : (
            (uint16(0x20C + i * 2) >= 0x30 and uint16(0x20C + i * 2) <= 0x39) or
            (uint16(0x20C + i * 2) >= 0x61 and uint16(0x20C + i * 2) <= 0x66)
        ) and
        (uint16(0xA44) == 0x5A4D or uint16(0x1003) == 0x5A4D or uint16(0x1004) == 0x5A4D)
}

rule HUNT_ValleyRAT_Malaysia_Driver_Safetica_ProcessMonitor
{
    meta:
        description = "Hunting: Safetica stprocessmonitor.sys (LOLDrivers 0712c54c-69fd-41f2-950a-da678ac51246) abused for process termination (IOCTL 0xB822200C)"
        author      = "Fadhil (fj4rr)"
        date        = "2026-11-07"
        status      = "not validated"
        note        = "Legitimate signed driver. A hit alone is not malicious; look for it dropped in %TEMP% as EmbeddedDriverService.sys"
    strings:
        $pdb = "ProcessMonitorDriver.pdb" ascii
        $dev = "\\Device\\STProcessMonitorDriver" wide ascii
        $dos = "\\DosDevices\\STProcessMonitorDriver" wide ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 200KB and
        pe.is_64bit() and ($pdb or $dev or $dos)
}

rule HUNT_ValleyRAT_Malaysia_Driver_wsftprm
{
    meta:
        description = "Hunting: Topaz Antifraud wsftprm.sys (CVE-2023-52271, LOLDrivers 30e8d598-2c60-49e4-953b-a6f620da1371) abused to kill PPL processes"
        author      = "Fadhil (fj4rr)"
        date        = "2026-11-07"
        status      = "not validated"
        note        = "Legitimate signed driver. Dropped here as kvckiller.sys into System32\\drivers"
    strings:
        $dev = "Warsaw_PM" wide ascii
        $sig = "TPZ SOLUCOES DIGITAIS LTDA" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 200KB and
        pe.is_64bit() and $dev and $sig
}
