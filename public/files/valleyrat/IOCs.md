## Network

| Indicator | Notes |
| --- | --- |
| `186.241.116[.]135:558/TCP` | C2 for Stage 1 / Stage 2 / RAT (hardcoded, no DNS) |
| `hxxps://nexmoke[.]com/download/PDF1024701.zip` | Initial download URL (VirusTotal Relations, 2026-10-26, HTTP 200). Host recorded in ScanMalware hunt #312 |
| `127.0.0.1:80` | `p3` placeholder in config (not a real IOC) |
| `6666` | Default port in the login module template (overridden at runtime) |
| Handshake `39 39 00` | Start of the Stage 1 connection (client → server) |
| Hello `04 00`, heartbeat `0xC9` / `C9 00`, ack `0xCA` / `0xCB` | Protocol patterns |
| Header token `?? ?? ?? ?? 00 00 00 00 ca 00` (offset +4), payload XOR `0x44` | Framing pattern |

**Hunt #312 kit domains (context, not all proven related to the sample):** `hasilgov-my[.]shop`, `hasil-gov-my[.]shop`, `hasilgov-my[.]my[.]id`, `mhftee[.]my[.]id`, `wwcvda[.]my[.]id`, `mida[.]cam`, `midaoity[.]my`, `satgob-mx[.]shop`, `dagavb[.]com`, `welovetheherbs[.]com`, `homescapestaging[.]com`, `goezbar[.]com`, `cartesproduction[.]com`, `bridgecitylawncare[.]com`. Operator server IPs listed in the hunt: `101.32.164[.]111`, `103.97.131[.]121`, `43.128.218[.]147`, `43.134.121[.]203`.

## Files and hashes

| Object | Size | SHA-256 | MD5 |
| --- | --- | --- | --- |
| `view.exe` = `OP01.exe` = `svchostsr.exe` | | `78fc25ed9a673f26eadf03dd5472dc112155138410cd5c81f8b89ccef5bf0736` | `c663ac03855f3e7ff9fde06bd6e24aec` |
| `libcef.dll` | 10,896,384 | `2c68a6e7cf46f791164e9b708af47faf2654ba6569522309ee037c39d24cdc22` | `de1923be3a91ac12cd416ef5b6eeb717` |
| Stage 2 raw | 307,214 | `8a1ef3f3b9606deea8bfa50419acd2ea583a42298ed301a5d7533c855e95e65c` | |
| Stage 2 decoded | 307,214 | `89ecf3e82d8ed7834244a6837523bc3fe1eb5cb4ad9cb81ee935628116ab74c5` | |
| `上线模块.dll` (stager) | 115,712 | `607599486156203946451be3c239f72f7090b0f63a214a38c48e504c41f99f05` | `543d8b746d0f38bd42a8c83502cc7f92` |
| `login_module_cache.bin` | 393,731 | `8947818d801513f303b92091e6302a520593944615b1e8b51d77722374d364a2` | `c8bd5c8f16064b3397035d6a71304e46` |
| `登录模块.dll` (embedded PE) | 389,632 | `fe057e29571b291c44ee2f7fc5d7302132f4ace65d361b629858dd00fda7fe2c` | `4bdaa6ac414b156c0983370b88d2956c` |
| Safetica driver `EmbeddedDriverService.sys` | 35,400 | `70bcec00c215fe52779700f74e9bd669ff836f594df92381cbfb7ee0568e7a8b` | `485a04675df7cf40a8865706e003eb25` |
| `kvckiller.sys` (`wsftprm.sys`) | 38,816 | `ff5dbdcf6d7ae5d97b6f3ef412df0b977ba4a844c45b30ca78c0eeb2653d69a8` | `2f4b5a0d98bc4e5616f2dd04337ae674` |
| `cache.exe` (x64, AV killer) | 357,888 | `46f65f7089e8bf0468a096247243d513f4667a964c239ea00334431122f1a544` | `89733460266ebe94928157c96023e27c` |
| Plugin `KILL杀毒.dll` (blob) | 448,068 | `ce1b8e12bd470c5da0475d6a92e5e2769b08aa1d52903b83d8a1d07ba54d82c5` | |
| Plugin `KILL杀毒.dll_bin` (blob) | 449,539 | `a31ca2ab16e6667f8bd99a67929d446b7f739ffe41e65e01d4fbf85b585ee3d1` | |
| `KILL杀毒` PE (`Project1.dll`) | 445,440 | `0a45c00d0942d28044f5c16bf40cbb62abcbb8492053c50ad1dcf4abda0f68d7` | `c07205ae8232c18bc41c710239c00fdb` |
| Plugin `启动项.dll` (blob) | 386,116 | `8086dd3c153096c68bf65ae4c4b16a6e234ff17f676924054ca9f2679005da97` | |
| Plugin `启动项.dll_bin` (blob) | 387,587 | `549a0238fe3c1fbc38c51743fe6aa2ac497c91a375d125196dd779b5f4268224` | |
| `启动项` PE (`Scheduled Task.dll`) | 383,488 | `03f0d1bed58a1c88ed963c60e5d72b2ab21203f369b81a636bd7e0e5f652ebb3` | `6121ab74fd0d437ac7060f5b9c8ad230` |

Module identifiers (`+0x20C`, = MD5 of the body): `fe3bb0c20a7d3dd74e6807ed1fd4859e` (`登录模块.dll_bin`), `c07205ae8232c18bc41c710239c00fdb` (`KILL杀毒.dll`), `b0ac50e8ff67fbea16bc9ad65432176b` (`KILL杀毒.dll_bin`), `6121ab74fd0d437ac7060f5b9c8ad230` (`启动项.dll`), `12b621547b04ab9a78e99de1139872da` (`启动项.dll_bin`).

Full hashes of `wmiclntui.cpl`, `PDF1024701.zip`, and `PDF1024701.img` were not recorded (prefixes only, see [§3.2](#32-archive-contents-and-reputation)). The carved samples above are available in the archive `samples_051126_infected.zip` (AES-256, password `infected`).

## Host artifacts

**Registry:**

| Key / value | Description |
| --- | --- |
| `HKCU\CC\0\R32f351a4aeea5e608853d1a56661059` | Cache of `登录模块.dll_bin` (REG_BINARY 393,731 B) |
| `HKCU\CC\IpDate` | Read by the stager (C2 override, absent in both runs) |
| `HKCU\Console\0\aa996919f197f1cf0b69b5800cd6db52`, `…\ebfdc592c71ab782daa2b7dc0b4fefe9` | Plugin `KILL杀毒` (two variants) |
| `HKCU\Console\0\32c639b4cb5bb8a322b559fecb1504d9`, `…\d1d1f1a7b4bf5ba671488dc317d8c954` | Plugin `启动项` (two variants) |
| `HKCU\Console\IpDatespecial` | Gating, checked on every heartbeat (absent in both runs) |
| `HKCU\Console\IpDate` | C2 config (written by opcode `0x12`, STATIC ONLY) |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\RunApp` | `C:\Users\Public\svchostsr.exe` |
| `HKLM\SYSTEM\CurrentControlSet\Services\EmbeddedDriverService` | Safetica driver service |
| `HKLM\SYSTEM\CurrentControlSet\Services\wsftprm` | Temporary service (created then deleted) |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{MsMpEng.exe, SecurityHealthService.exe, SecurityHealthSystray.exe}\Debugger = systray.exe` | IFEO hijack (persists across reboot) |
| `HKLM\TempIFEO` | Temporary hive (the only place Sysmon sees the `Debugger` write) |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` (+ `\Real-Time Protection`) | Policy written by the login module (code only, never seen in either run) |

**Files:**
- `%LOCALAPPDATA%\Temp\EmbeddedDriverService.sys` (35,400 B), signer "Microsoft Windows Hardware Compatibility Publisher"
- `C:\Windows\System32\drivers\kvckiller.sys` (38,816 B), signer "TPZ SOLUCOES DIGITAIS LTDA"
- `C:\Users\Public\cache.exe` (deleted after running)
- `C:\Users\Public\svchostsr.exe`, `libcef.dll`, `wmiclntui.cpl`, and possibly `PDF1024701.img` (timestamp 01/01/1601 on Windows 10; Hidden + ReadOnly attributes on `libcef.dll` and `wmiclntui.cpl`)
- `%LOCALAPPDATA%\Temp\Ifeo.hiv*` (temporary)
- `C:\Windows\Temp\UDD4AD5.tmp` (PcaSvc side artifact, not reliable as an IOC)

**Other objects and strings:**
- Mutex `Global\MyUniqueApp_SingleInstance` (STATIC ONLY). Devices `\\.\STProcessMonitorDriver` and `\\.\Warsaw_PM`. IOCTL `0xB822200C`.
- Strings: `codemark`, `denglupeizhi`, `plugmark`, `onlyloadinmyself`, module identifier `fe3bb0c20a7d3dd74e6807ed1fd4859e`, names `上线模块.dll`, `登录模块.dll`, `登录模块.dll_bin`, `KILL杀毒.dll`, `启动项.dll`; announce-struct remnant `sktop\新版本32\新版本32`.
- Process: `DllHost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` as the parent of `view.exe` / `svchostsr.exe`; `cache.exe` from `C:\Users\Public\`; `systray.exe` launched with `SecurityHealthSystray.exe` as its argument.
- Defender ThreatIDs allowed by the analyst in run 2 (detection names not mapped): `2147814523`, `2147814524`; `2147965211` was already present before the run.
