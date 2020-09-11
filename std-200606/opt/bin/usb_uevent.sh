#!/bin/sh

. /opt/bin/iot_common.sh

ACTION="$1"

productKey="a2Wl5a1kUzm"
device_name="8000000240159904"

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


case $ACTION in
	add)
		#get printer
		printername=`get_prname`
		if [ -n "$printername" ]; then
			report_prname "$printername"
			uci -q set aliyun.iot.printername="$printername"
			lpoptions -d "$printername"
		fi
		echo "`date` Printer[$printername] added" >> /tmp/usbevent.dbg
		;;
	remove)
		echo "`date` Printer removed" >> /tmp/usbevent.dbg
		#get printer
		printername="none"
		report_prname "$printername"
		;;

esac


