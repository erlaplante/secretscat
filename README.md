### secretscat

Runs secretsdump, attempts to crack dumped hashes with hashcat, then formats output in \<User\>:\<Password/Hash\> format. Credit to The Cyber Mentor's "Automated Password Hacking" video where he walks through the code. This is simply an implementation of that to test it, practice, and added some additional options.

#### Parameters
Required:\
`-d` Domain Name
`-u` Username
`-p` Password
`-dc` Domain Controller IP

Optional:\
`-h` Show help message
`-w` Wordlist location (defaults to: /usr/share/wordlists/rockyou.txt)
`-r` Rules for hashcat
`-O` Optimized mode for hashcat
`-P` Proxychains prepended to secretsdump command

##### References
https://www.youtube.com/watch?v=WGewfvluu_8
