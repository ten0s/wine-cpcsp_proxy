WINEARCH =
WINEGCC  = winegcc $(WINEARCH)
CFLAGS	 = -g -fPIC -O0 -Wall -D__WINESRC__
IMPORTS	 = advapi32 crypt32 kernel32 ntdll shlwapi
LIBS	 = $(IMPORTS:%=-l%) -ldl
DEPS	 = Makefile

all: cpcsp_proxy_setup.exe

cpcsp_proxy_setup.exe: cpcsp_proxy_setup.c ../lib/cpcapi.c ../lib/cpconv.c
	$(WINEGCC) $(CFLAGS) $^ -mconsole $(LIBS) -o $@

install: all
	./cpcsp_proxy_setup.exe -P -O

clean:
	rm -f *.o *.exe *.exe.so
