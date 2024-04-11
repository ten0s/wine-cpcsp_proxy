WINEARCH =
WINEGCC  = winegcc $(WINEARCH)
CFLAGS   = -g -O0 -fPIC -Wall -D__WINESRC__
IMPORTS  = kernel32 ntdll
LIBS     = $(IMPORTS:%=-l%) -ldl
WINEPREFIX ?= ~/.wine

all: cpcsp_proxy.dll.so cpsspi_proxy.dll.so cpcapi_proxy.dll.so

cpcsp_proxy.dll.so: cpcsp_proxy.c cpcsp_proxy.spec
	$(WINEGCC) $(CFLAGS) -shared $^ $(LIBS) -o $@

cpsspi_proxy.dll.so: cpsspi_proxy.c cpsspi_proxy.spec proxy_util.c
	$(WINEGCC) $(CFLAGS) -shared $^ $(LIBS) -o $@

cpcapi_proxy.dll.so: cpcapi_proxy.c cpcapi_proxy.spec proxy_util.c
	$(WINEGCC) $(CFLAGS) -shared $^ $(LIBS) -o $@

install: cpcsp_proxy.dll.so
	cp -f cpcsp_proxy.dll.so  $(WINEPREFIX)/drive_c/windows/system32/
	cp -f cpsspi_proxy.dll.so $(WINEPREFIX)/drive_c/windows/system32/
	cp -f cpcapi_proxy.dll.so $(WINEPREFIX)/drive_c/windows/system32/

clean:
	rm -f *.o *.dll *.dll.so
