# greenapples
iOS-encrypted binaries dumper powered by frida

## requirements
- a brain
- a jailbroken iOS device with frida server
- python & frida installed on your pc
- the encrypted binary which you want to dump (pull it from the `.ipa`)

## example usage
the device should be connected to the pc via usb (verify it with `frida-ps -U`)
```bash
% ls
BS_encrypted    greenapples.py  main.py         README.md

% python3 main.py com.supercell.laser "Brawl Stars" BS_encrypted -v
[VERBOSE] Dumped! Downloading from device...
Dump size: 17235968 bytes
Fixing dump for Brawl Stars
[VERBOSE] FAT binary, searching for arm64
[VERBOSE] arm64 part found at offset 21725184, size 23753808
[VERBOSE] LC_ENCRYPTION_INFO_64 offset:16384 size=17219584
Brawl Stars dump saved to BrawlStars_fixed.

% file BrawlStars_fixed
BrawlStars_fixed: Mach-O 64-bit executable arm64
```
where:
- `com.supercell.laser`: target app's bundle identifier
- `"Brawl Stars"`: name of the main executable inside the app (check in `Info.plist`)
- `BS_encrypted`: path to original encrypted executable (should be on your pc)
- `-v`: (optional) verbose mode

see `python3 main.py -h` for other optional arguments

## notes
the script doesn't produce a full IPA for now, so if you want it - you need to dump each encrypted binary manually (e.g. those in Frameworks if they're encrypted) and replace them in the IPA

## why i made this script
- i couldn't dump old version of an app (JB detection which is bypassable with `Choicy` tweak, but makes it impossible to use `bfdecrypt` and others. frida seems to be the only available option in this case)
- [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) is outdated and broken with latest Frida
- for fun

## todo
- pull encrypted executables & get their names automatically
- full IPA generator with single command
- use `lief` or other tool to manipulate the binary (feel free to implement it)
