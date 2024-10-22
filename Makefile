#############################################################################
#   Copyright 2024 Aon plc
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#############################################################################


CC_X64 := x86_64-w64-mingw32-gcc

CFLAGS  := $(CFLAGS) -Os -fno-asynchronous-unwind-tables -fno-exceptions -fPIC 
LFLAGS := $(LFLAGS) -Wl,-s,--no-seh,--enable-stdcall-fixup
LDFLAGS := --no-seh --enable-stdcall-fixup -r -S

default:
	$(CC_X64) -c edrsilencer.c $(CFLAGS) -DBOF $(LFLAGS) -lfwpuclnt -Wall -o edrsilencer.x64.o

exe:
	$(CC_X64) edrsilencer.c -o edrsilencer.exe -Wall -lfwpuclnt