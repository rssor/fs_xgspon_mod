CC := mipsel-linux-gnu-gcc-10
CCFLAGS := -fPIC -std=c11 -L./shim/deps/ -Ishim/ -ldl-2.23 -lc-2.23 -nostdlib -Os -s -msoft-float -mips1

.PHONY: clean

fs_xgspon_mod_release.tgz: payload/payload.tgz fs_xgspon_mod.py README.md
	tar --owner==- --group=0 --numeric-owner -cvzf $@ payload/ fs_xgspon_mod.py README.md

payload/payload.tgz: rwdir/payload/libvos_shim.so rwdir/dangerous_payload.sh rwdir/stage0.sh Makefile
	tar --owner=0 --group=0 --numeric-owner -cvzf $@ -C rwdir/ payload/ dangerous_payload.sh stage0.sh

rwdir/payload/libvos_shim.so: shim/shim.c shim/deps/libstub.so
	$(CC) -shared -o $@ $< $(CCFLAGS) -Wl,--no-as-needed -lstub

shim/deps/libstub.so: shim/stub.c
	$(CC) -shared -o $@ $< $(CCFLAGS) -Wl,-soname=/tmp/payload/libvos.so

clean:
	rm payload/payload.tgz
	rm shim/deps/libstub.so
	rm rwdir/payload/libvos_shim.so
	rm fs_xgspon_mod_release.tgz
