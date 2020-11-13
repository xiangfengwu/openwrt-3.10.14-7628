#!/bin/sh

. /opt/bin/iot_common.sh

ACTION="$1"

YJIMEI=`hexdump /dev/mtd3 -C -s 1024 -n 16 |head -1 |awk  -F "|" '{print $2}' |tr -d "."` 

productKey="a1Y72Hurhna"
device_name=${YJIMEI}

report_prname() {
	local topic="/${productKey}/${device_name}/user/auth"
	local payloadfile="/tmp/iot/printername.json"
	local printername="$1"
	local seqno
	seqno=`get_seqno`

cat <<_ACEOF > $payloadfile
{"cmd":12,"imei":"$device_name","seqno":$seqno,"data":{"printer_model":"$printername"}}
_ACEOF

	cunix_send "$topic" "$payloadfile"
	
}

get_prname() {
	local prname
	prname=`/usr/sbin/lpinfo -l -v |grep -A 3 "class = direct" |grep "make-and-model" |awk -F "= " '{ print $2 }' |tr " " "_"`
	echo "$prname"
}


case $ACTION in
	add)
		echo "xfwu---`date`---usb connect----" >> /tmp/iot/$YJIMEI.txt
		#get printer
		echo 1 > /tmp/state/xfwuPrinterledstate
		printername=`get_prname`
		printeruri=`get_pruri`
		if [ -n "$printername" ]; then
			echo "xfwu--------ppppppppppppppppppppppppppp" > /dev/console
			echo "xfwu---`date`---report prname:${printername}----" >> /tmp/iot/$YJIMEI.txt
			report_prname "$printername"
			lpadmin -p ${printername} -E -m raw -v ${printeruri}
			uci -q set aliyun.iot.printername="$printername"
			lpoptions -d "$printername"
		fi
		echo "`date` Printer[$printername] added" >> /tmp/usbevent.dbg
		;;
	remove)
		echo "`date` Printer removed" >> /tmp/usbevent.dbg
		echo "xfwu---`date`---usb removed----" >> /tmp/iot/$YJIMEI.txt
		echo "xfwu--------qqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" > /dev/console
		#get printer
		echo 3 > /tmp/state/xfwuPrinterledstate
		echo "xfwu---`date`---report prname $printername----" >> /tmp/iot/$YJIMEI.txt
		printername="none"
		report_prname "$printername"
		;;

esac


