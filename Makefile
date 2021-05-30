
define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

TOOL_PREFIX=
CC=$(TOOL_PREFIX)gcc
LD=$(TOOL_PREFIX)ld

ifdef TOOL_PREFIX
$(call allow-override,CC,$(CC))
$(call allow-override,LD,$(LD))
endif

OBJCOPY_FORMAT_SUFFIX=64-x86-64
BINARY_ARCH=i386

CDEBUG=-g
CFLAGS=-g -fPIC
SHELLCODE_CFLAGS=-fPIC -static -Os -fdata-sections -ffunction-sections -nostdlib --entry=_start -Wl,-Tlinkerscript.ld

BINARY=injector

.PHONY: all clean tests


%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

all: clean $(BINARY)


initial_injection.o: initial_injection.c
	$(CC) $(SHELLCODE_CFLAGS) -c -o $@ $<

initial_injection.elf: initial_injection.o
	$(CC) $(SHELLCODE_CFLAGS) -o $@ $^

raw_shellcode.bin: initial_injection.elf
	objcopy -j raw_shellcode -O binary $^ $@

shellcode.o: raw_shellcode.bin
	objcopy -I binary -O elf$(OBJCOPY_FORMAT_SUFFIX) -B $(BINARY_ARCH) $^ $@

$(BINARY): injector.o shellcode.o
	$(CC) $(CFLAGS) -o $@ $^

clean:
	find . -type d \( -path include \) -prune -false -o -iname '*.o' -o -iname '*.so' -o -iname '*.elf' -o -iname '*.bin' | xargs rm -f
	rm -f $(BINARY) 2>/dev/null
