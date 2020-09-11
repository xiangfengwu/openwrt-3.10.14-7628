#!/bin/sh

YJIMEI=$1
offset=1024
echo -en "$YJIMEI" | dd of=/dev/mtdblock3 bs=1 seek=${offset} conv=notrunc
hwver=`hexdump /dev/mtd3 -C -s 1024 -n 16 |head -1 |awk  -F "|" '{print $2}' |tr -d "."`
echo "SerialNo.  of this device is $hwver"  > /dev/console
rm -rf /opt/bin/xfwusecret


YJMAC=$2
echo $YJMAC  > /dev/console
YJMAC2=`echo  $YJMAC | sed 's/:/\\\x/g' |sed -e 's/^/\\\x/'`
echo $YJMAC2   > /dev/console
echo -en $YJMAC2 |  dd of=/dev/mtdblock3 bs=1 seek=4 conv=notrunc
hwmac=`hexdump /dev/mtd3 -C -s 4 -n 6 |head -1 |awk  -F  " " '{print $2$3$4$5$6$7}'`
echo "xfwu---------------macaddr:$YJMAC" > /dev/console

