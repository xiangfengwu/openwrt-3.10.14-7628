#!/bin/sh

. /opt/bin/iot_common.sh

echo "$@" >> /tmp/iot/iotrcv.dbg
action="$1"

productKey="a2Wl5a1kUzm"
device_name="8000000240159904"

hnd_connected() {
	local topic="/${productKey}/${device_name}/user/auth"
	local payloadfile="/tmp/iot/connected.json"
	local seqno
	seqno=`get_seqno`

cat <<_ACEOF > $payloadfile
{"cmd":10,"imei":"$device_name","seqno":$seqno,"data":{"version_code":18}}
_ACEOF

	cunix_send "$topic" "$payloadfile"
	
}

report_prname() {
	local topic="/${productKey}/${device_name}/user/auth"
	local payloadfile="/tmp/iot/prname.json"
	local printername="$1"
	local seqno
	seqno=`get_seqno`

cat <<_ACEOF > $payloadfile
{"cmd":12,"imei":"$device_name","seqno":$seqno,"data":{"printer_model":"$printername"}}
_ACEOF

	cunix_send "$topic" "$payloadfile"
	
}

report_prstatus() {
	local topic="/${productKey}/${device_name}/user/doc"
	local payloadfile="/tmp/iot/prstatus.json"
	local seqno="$1"
	local printid="$2"

cat <<_ACEOF > $payloadfile
{"cmd":31,"imei":"$device_name","seqno":$seqno,"data":{"print_id":$printid,"no":1,"print_status":6,"doc_printer_status":""}}
_ACEOF

	cunix_send "$topic" "$payloadfile"
	
}

report_prtask() {
	local topic="/${productKey}/${device_name}/user/doc"
	local payloadfile="/tmp/iot/prtask.json"
	local seqno="$1"
	local printid="$2"

cat <<_ACEOF > $payloadfile
{"cmd":30,"imei":"$device_name","seqno":$seqno,"data":{"print_id":$printid}}
_ACEOF

	cunix_send "$topic" "$payloadfile"
	
}

report_reboot() {
	local topic="/${productKey}/${device_name}/user/system"
	local payloadfile="/tmp/iot/reboot.json"
	local seqno="$1"

cat <<_ACEOF > $payloadfile
{"cmd":91,"imei":"$device_name","seqno":$seqno} 
_ACEOF

	cunix_send "$topic" "$payloadfile"
	
}

hnd_recvpub() {
	local topicfile="$1"
	local payloadfile="$2"
	local cmd

	if [ ! -f "$payloadfile" ]; then
		mydebug "have no file $payloadfile exist"
		return
	fi

	cmd=`/opt/bin/cjson -f "$payloadfile" -r "cmd"`
	case $cmd in
		10)  #print_auth
			print_auth=`/opt/bin/cjson -f "$payloadfile" -r "data:print_auth"`
			uci -q set aliyun.iot.print_auth=$print_auth
			;;
		30)  #print task
			seqno=`/opt/bin/cjson -f "$payloadfile" -r "seqno"`
			print_id=`/opt/bin/cjson -f "$payloadfile" -r "data:print_id"`
			doc_url=`/opt/bin/cjson -f "$payloadfile" -r "data:doc_url"`
			color_print=`/opt/bin/cjson -f "$payloadfile" -r "data:color_print"`
			uci -q set aliyun.iot.seqno=$seqno
			#reply to aiot cloud
			report_prtask "$seqno" "$print_id"
			#download page, then print it, finally report print status
			print_auth=`uci -q get aliyun.iot.print_auth`
			if [ "z$print_auth" != "z0" ]; then
				for var1 in 1 2 3; do
					curl --silent --max-time 3 -o /tmp/iot/pr.pdf "$doc_url"
					if [ -f /tmp/iot/pr.pdf ]; then
						lp /tmp/iot/pr.pdf &
						sleep 1
						report_prstatus "$seqno" "$print_id"
						break
					fi
				done
			fi
			;;
		91)  #reboot
			seqno=`/opt/bin/cjson -f "$payloadfile" -r "seqno"`
			report_reboot "$seqno"
			sleep 2
			reboot -f
			;;
		*)
			mydebug "cmd=$cmd Not supported"
			;;
	esac

}

case $action in
	connected|reconnect)
		hnd_connected
		sleep 1
		#get printer
		printername=`uci -q get aliyun.iot.printername`
		if [ -n "$printername" ]; then
			report_prname "$printername"
		fi
		;;
	disconnect)
		;;
	recvpub)  # do some recv process
		hnd_recvpub "$2" "$3"
		;;
	*)
		mydebug "action=$action Not supported"
		;;
esac


