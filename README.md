# NTbuster

Next-Generation Password Audit Tool for Windows Machines

NTbuster is designed to connect to Windows machines and dump password hashes. It then generates a custom wordlist based on the dumped usernames and performs a rainbow table attack to crack the passwords.

## Installation
```bash
git clone https://github.com/ch1nghz/NTbuster
cd NTbuster
git submodule init
git submodule update
sudo apt-get update && sudo apt-get install -y libhiredis-dev
make
```

## System Requirements
At least 8GB free memory and 4 CPU cores

## Running NTbuster
```
./bin/NTbuster --target-ip 172.16.57.2 -u testuser -p 123456
    _   __________               __           
   / | / /_  __/ /_  __  _______/ /____  _____
  /  |/ / / / / __ \/ / / / ___/ __/ _ \/ ___/
 / /|  / / / / /_/ / /_/ (__  ) /_/  __/ /    
/_/ |_/ /_/ /_.___/\__,_/____/\__/\___/_/     

[*] Dumping hashes...
[+] Hashes dumped!
[*] Parsing dumped hashes...
[*] The password of 'client' is cracking...
[+] Cracked: ['client':'client1993!@#']
[*] The password of 'sysadmin' is cracking...
[+] Cracked: ['sysadmin':'sysadmin12345']
[*] The password of 'hacker1337' is cracking...
```
