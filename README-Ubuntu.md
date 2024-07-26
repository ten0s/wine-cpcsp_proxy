## Минимальные шаги для работы в Ubuntu

### Установка  Wine

Установить Wine как описано здесь https://wiki.winehq.org/Ubuntu

Пример минимально необходимой установки для Ubuntu 22.04

```
$ sudo dpkg --add-architecture i386
```

```
$ sudo mkdir -p -m755 /etc/apt/keyrings
$ sudo wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key
$ sudo wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/jammy/winehq-jammy.sources
```

```
$ sudo apt update
$ sudo apt install --install-recommends winehq-stable
```

Проверить:

```
$ wine --version
wine-9.0
```

Создать HOME для Wine (по умолчании ~/.wine):

```
$ winecfg /v win10
```

### Установка средств разработки для Wine

Дополнительно доставить средства разработки для Wine, включая заголовочные файлы, либы и компилятор:

```
$ sudo apt install wine-stable wine-stable-dev
```

Проверить:

```
$ ls -l /opt/wine-stable/include/wine/windows/wincrypt.h
-rw-r--r-- 1 root root 205489 Jan 17 03:20 /opt/wine-stable/include/wine/windows/wincrypt.h
```

```
$ winegcc --version
gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
...
```

### Установка КриптоПро

Скачать сертифицированную версию КриптоПро CSP 5.0 R2<br>
https://cryptopro.ru/sites/default/files/private/csp/50/12000/linux-amd64_deb.tgz

```
$ tar xf linux-amd64_deb.tgz
$ cd linux-amd64_deb/
```

```
$ sudo ./install_gui.sh
```

Установить следующие обязательные компоненты:

```
[*] KC1 Cryptographic Service Provider
[*] GUI dialogs component
[*] cptools, GUI application for various tasks
```

Проверить:

```
$ /opt/cprocsp/bin/amd64/cryptcp -help | head -1
CryptCP 5.0 (c) "Crypto-Pro", 2002-2021.
```

```
$ ls -l /opt/cprocsp/lib/amd64/*.so | wc -l
19
```

### Сборка wine-cpcsp_proxy

```
$ git clone https://github.com/ten0s/wine-cpcsp_proxy
$ cd wine-cpcsp_proxy
$ cd cpcsp_proxy
$ make
winegcc  -g -O2 -fPIC -Wall -D__WINESRC__ -c cpcsp_proxy.c -o cpcsp_proxy.o
winegcc  -g -O2 -fPIC -Wall -D__WINESRC__ -shared cpcsp_proxy.o cpcsp_proxy.spec -lkernel32 -lntdll -ldl -o cpcsp_proxy.dll.so
$ cd ..
$ cd cpcsp_proxy_setup
$ make
winegcc  -g -fPIC -O2 -Wall -D__WINESRC__ -c cpcsp_proxy_setup.c -o cpcsp_proxy_setup.o
winegcc  -g -fPIC -O2 -Wall -D__WINESRC__ cpcsp_proxy_setup.o -mconsole -municode -ladvapi32 -lcrypt32 -lkernel32 -lntdll -ldl -o cpcsp_proxy_setup.exe
$ cd ..
```

### Установка wine-cpcsp_proxy в Wine

```
$ cp cpcsp_proxy/*.dll.so ~/.wine/drive_c/windows/system32/
```

### Регистрация провайдера в Wine

```
$ cpcsp_proxy_setup/cpcsp_proxy_setup.exe
Adding: provider Crypto-Pro GOST R 34.10-2001 KC1 CSP, type 75
Adding: provider Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider, type 75
Adding: provider Crypto-Pro GOST R 34.10-2012 KC1 CSP, type 80
Adding: provider Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider, type 80
...
Saving certificate L"CryptoPro GOST Root CA" to Root store
Saving certificates to My store
```
