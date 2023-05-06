[![Build Status](https://img.shields.io/badge/C%2B%2B-passing-brightgreen)](https://github.com/your-username/NTbuster)
# NTbuster

Next-Generation Password Audit Tool for Windows Machines

NTbuster is designed to connect to Windows machines and dump password hashes. It then generates a custom wordlist based on the dumped usernames and performs a rainbow table attack to crack the passwords.

## Installation
```bash
git clone https://github.com/ch1nghz/NTbuster
cd NTbuster
make
```

## System Requirements
A system with a minimum of 8GB of available memory and a CPU containing at least 4 cores is recommended.

## Running NTbuster
```
./bin/NTbuster -t 172.16.57.2 -u testuser -p 123456 -m 2
    _   __________               __           
   / | / /_  __/ /_  __  _______/ /____  _____
  /  |/ / / / / __ \/ / / / ___/ __/ _ \/ ___/
 / /|  / / / / /_/ / /_/ (__  ) /_/  __/ /    
/_/ |_/ /_/ /_.___/\__,_/____/\__/\___/_/     

[*] Dumping hashes...
[*] Parsing dumped hashes...
[*] The password of 'client' is cracking...
[*] The password of 'netadmin' is cracking...
[+] Cracked: ['netadmin':'net*******']
[*] The password of 'sysadmin' is cracking...
[+] Cracked: ['client':'cli**********']
```
The NTbuster wordlist generator also supports custom word input to create a user-defined wordlist.
```bash
cat /tmp/seed_words.txt 
orangejuice
applejuice
```
```
./bin/NTbuster -t 172.16.57.2 -u testuser -p 123456 -m 2 -w /tmp/seed_words.txt 
    _   __________               __           
   / | / /_  __/ /_  __  _______/ /____  _____
  /  |/ / / / / __ \/ / / / ___/ __/ _ \/ ___/
 / /|  / / / / /_/ / /_/ (__  ) /_/  __/ /    
/_/ |_/ /_/ /_.___/\__,_/____/\__/\___/_/     

[*] Dumping hashes...
[*] Parsing dumped hashes...
[*] The password of 'devops' is cracking...
[+] Cracked: ['devops':'Ora*********!']
```