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

##  1/3

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


