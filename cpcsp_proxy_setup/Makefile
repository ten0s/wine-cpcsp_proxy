WINEARCH =
WINEGCC  = winegcc $(WINEARCH)
CFLAGS	 = -g -fPIC -O2 -Wall -D__WINESRC__
IMPORTS	 = advapi32 crypt32 kernel32 ntdll
LIBS	 = $(IMPORTS:%=-l%) -ldl
OBJ	     = cpcsp_proxy_setup.o
DEPS	 = Makefile

%.o: %.c $(DEPS)
	$(WINEGCC) $(CFLAGS) -c $< -o $@

all: cpcsp_proxy_setup.exe

cpcsp_proxy_setup.exe: $(OBJ)
	$(WINEGCC) $(CFLAGS) $^ -mconsole -municode $(LIBS) -o $@

install: cpcsp_proxy_setup.exe
	./cpcsp_proxy_setup.exe

clean:
	rm -f *.o *.exe *.exe.so
