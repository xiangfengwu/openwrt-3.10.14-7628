#!/bin/sh
#set -x

sudo echo "Starting..."
MKSQSHFS4='/media/plinux/openwrt-bb/mtk/openwrt-3.10.14-wim/staging_dir/host/bin/mksquashfs4'
PADJFFS2='/media/plinux/openwrt-bb/mtk/openwrt-3.10.14-wim/staging_dir/host/bin/padjffs2'
#KERNEL=kernel10.bin
#KERNEL=kernel10-0414.bin
#KERNEL=kernel10-0804.bin

KERNEL=kernel10-0812-video.bin
#KERNEL=test.bin

#ROOTFS=cs-yang

#ROOTFS=tongzhou
#ROOTFS=rootfs-video
#ROOTFS=ye-l2tp
#ROOTFS=rootfs-openwrtbb-wifidog
#ROOTFS=rootfs-openwrtbb-multi-wan
#ROOTFS=rootfs-openwrtbb-wifidog-php-mysql
#ROOTFS=rootfsbb-7620std-180324

#ROOTFS=rootfsbb-7620std-181025

#KERNEL=kernel10-170904-ipsec.bin
#ROOTFS=rootfs-openwrtbb-170909-vpnipsec

#ROOTFS=wowo4

#ROOTFS=rootfsbb-7620nanling-190123

#ROOTFS=zhiyi

#ROOTFS=rootfsbb-7620cd-181124

#ROOTFS=rootfsbb-7620std-181220
#ROOTFS=rootfsbb-7620std-190109
#ROOTFS=shoupa-190323
#ROOTFS=simple-190630
#ROOTFS=python-191212
#ROOTFS=python-200408A
#ROOTFS=python-200516

#ROOTFS=telecom-191012
#ROOTFS=gps-190808

#ROOTFS=std-190323
#ROOTFS=std-200408
#ROOTFS=std-200516

#ROOTFS=putian-190419

#ROOTFS=datang-A1-190408
#ROOTFS=datang-A2-190408
ROOTFS=qiu-200622


case "$1" in
	'extract'|'e')
		offset1=`grep -oba hsqs $2 | grep -oP '[0-9]*(?=:hsqs)'`
		offset2=`wc -c $2 | grep -oP '[0-9]*(?= )'`
		size2=`expr $offset2 - $offset1`
		#echo $offset1 " " $offset2 " " $size2
		dd if=$2 of=$KERNEL bs=1 ibs=1 count=$offset1
		dd if=$2 of=secondchunk.bin bs=1 ibs=1 count=$size2 skip=$offset1
		sudo rm -rf squashfs-root 2>&1
		sudo unsquashfs -d $ROOTFS secondchunk.bin
		rm secondchunk.bin
		;;
	'create'|'c')
		#sudo $MKSQSHFS4 ./$ROOTFS ./newsecondchunk.bin -nopad -noappend -root-owned -comp xz -Xpreset 9 -Xe -Xlc 0 -Xlp 2 -Xpb 2 -b 256k -processors 1
		$MKSQSHFS4 ./$ROOTFS ./newsecondchunk.bin -nopad -noappend -root-owned -comp xz -Xpreset 9 -Xe -Xlc 0 -Xlp 2 -Xpb 2  -b 256k -p '/dev d 755 0 0' -p '/dev/console c 600 0 0 5 1' -processors 1
		sudo chown $USER ./newsecondchunk.bin
		cat $KERNEL newsecondchunk.bin > $2
		$PADJFFS2 $2
		rm newsecondchunk.bin
		;;
	*)
		echo 'run
		"modify-firmware.sh extract firmware.bin"
		You will find file "kernel.bin" and folder "squashfs-root".
		Modify "squashfs-root" as you like,after everything is done,run
		"modify-firmware.sh create newfirmware.bin"
		And you will get a modified firmware named newfirmware.bin.
		'
		;;
esac
