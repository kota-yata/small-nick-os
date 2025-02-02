#!/bin/bash
set -xue
QEMU=qemu-system-riscv32
CC=clang

CFLAGS="-std=c11 -O2 -g3 -Wall -Wextra --target=riscv32 -ffreestanding -nostdlib"

OBJCOPY=/usr/bin/llvm-objcopy

# building shell
$CC $CFLAGS -Wl,-Tuser.ld -Wl,-Map=shell.map -o shell.elf shell.c user.c common.c
# elf to bin with meory layout
$OBJCOPY --set-section-flags .bss=alloc,contents -O binary shell.elf shell.bin
$OBJCOPY -Ibinary -Oelf32-littleriscv shell.bin shell.bin.o

# building kernel
$CC $CFLAGS -Wl,-Tkernel.ld -Wl,-Map=kernel.map -o kernel.elf \
    kernel.c common.c net/*.c shell.bin.o

$QEMU -machine virt -bios default -nographic -serial mon:stdio --no-reboot \
  -d unimp,guest_errors -trace virtio_* -D qemu.log \
  -netdev bridge,id=net0,br=qemubr0,helper=/usr/lib/qemu/qemu-bridge-helper\
  -device virtio-net-device,netdev=net0,bus=virtio-mmio-bus.0,mac=52:54:00:12:34:56 \
  -drive id=drive0,file=lorem.txt,format=raw,if=none \
  -device virtio-blk-device,drive=drive0,bus=virtio-mmio-bus.1 \
  -object filter-dump,id=f1,netdev=net0,file=virtio-net-kota.pcap\
  -global virtio-mmio.force-legacy=true\
  -kernel kernel.elf\

# -netdev tap,id=net0,ifname=tap0,script=no,downscript=no\
# -global virtio-mmio.force-legacy=false
# -netdev tap,id=net0,ifname=tap0,script=no,downscript=no\
# -nic tap,model=virtio-net-device\

# -drive id=drive0,file=lorem.txt,format=raw,if=none \
# -device virtio-blk-device,drive=drive0,bus=virtio-mmio-bus.0 \
