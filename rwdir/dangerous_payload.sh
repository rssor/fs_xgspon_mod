#!/bin/sh

mkdir -p /tmp/payload/
touch /tmp/payload/libvos.so

mount -o bind /usr/lib/libvos.so /tmp/payload/libvos.so
mount -o bind /mnt/rwdir/payload/libvos_shim.so /usr/lib/libvos.so
