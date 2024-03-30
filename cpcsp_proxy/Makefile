WINEARCH =
WINEGCC  = winegcc $(WINEARCH)
CFLAGS   = -g -O2 -fPIC -Wall -D__WINESRC__
IMPORTS  = kernel32 ntdll
LIBS     = $(IMPORTS:%=-l%) -ldl
DEPS     = Makefile cpcsp_proxy.spec
OBJ      = cpcsp_proxy.o
WINEPREFIX ?= ~/.wine

%.o: %.c $(DEPS)
	$(WINEGCC) $(CFLAGS) -c $< -o $@

all: cpcsp_proxy.dll.so

cpcsp_proxy.dll.so: $(OBJ) cpcsp_proxy.spec
	$(WINEGCC) $(CFLAGS) -shared $^ $(LIBS) -o $@

install: cpcsp_proxy.dll.so
	cp -f cpcsp_proxy.dll.so $(WINEPREFIX)/drive_c/windows/system32/cpcsp_proxy.dll.so

clean:
	rm -f *.o *.dll *.dll.so
