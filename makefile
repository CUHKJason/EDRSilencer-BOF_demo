CC_X64 := x86_64-w64-mingw32-gcc


CFLAGS  := -Os -fno-asynchronous-unwind-tables
CFLAGS  += -fno-exceptions -fPIC 
CFLAGS  += -DPERSISTENT

#CFLAGS  := $(CFLAGS) -Os -fno-asynchronous-unwind-tables -fno-exceptions -fPIC 
LFLAGS := $(LFLAGS) -Wl,-s,--no-seh,--enable-stdcall-fixup
LDFLAGS := --no-seh --enable-stdcall-fixup -r -S

default:
	$(CC_X64) -c EDRSilencer_demo.c $(CFLAGS) -DBOF $(LFLAGS) -lfwpuclnt -Wall -o EDRSilencer_demo.x64.o

exe:
	$(CC_X64) EDRSilencer_demo.c -o EDRSilencer_demo.exe -Wall -lfwpuclnt
