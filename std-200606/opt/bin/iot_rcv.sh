#!/bin/sh

. /opt/bin/iot_common.sh

echo "$@" >> /tmp/iot/iotrcv.dbg
action="$1"

YJIMEI=`hexdump /dev/mtd3 -C -s 1024 -n 16 |head -1 |awk  -F "|" '{print $2}' |tr -d "."`

productKey="a1Y72Hurhna"
device_name=${YJIMEI}

FirmwareVersion=`cat /etc/openwrt_release | grep DISTRIB_REVISION |awk -F '"' '{print $2}' | awk -F '-' '{print $2}'`

report_prwifi() {
        local topic="/${productKey}/${device_name}/user/auth"
        local payloadfile="/tmp/iot/prwifi.json"
        local printWifi="$1"

cat <<_ACEOF > $payloadfile
{"cmd":14,"imei":"$device_name","data":{"print_wifi":$printWifi}}
_ACEOF

        cunix_send "$topic" "$payloadfile"

}

hnd_connected() {
	local topic="/${productKey}/${device_name}/user/auth"
	local payloadfile="/tmp/iot/connected.json"
	local seqno
	seqno=`get_seqno`

cat <<_ACEOF > $payloadfile
{"cmd":10,"imei":"$device_name","seqno":$seqno,"data":{"version_code":$FirmwareVersion}}
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
	local xfwuPrintId
	if [ ! -f "$payloadfile" ]; then
		mydebug "have no file $payloadfile exist"
		return
	fi

	cmd=`/opt/bin/cjson -f "$payloadfile" -r "cmd"`
	case $cmd in
		10)  #print_auth
			print_auth=`/opt/bin/cjson -f "$payloadfile" -r "data:print_auth"`
			uci -q set aliyun.iot.print_auth=$print_auth
			firmware_md5=`/opt/bin/cjson -f "$payloadfile" -r "data:md5"`
			firmware_url=`/opt/bin/cjson -f "$payloadfile" -r "data:apk_url"`
			
			echo "xfwu----------$firmware_md5---------------$firmware_url------" > /dev/console
			
			   if [ "$firmware_url" != "" ]; then
						curl  -o /tmp/iot/YJ_MTK.bin "$firmware_url"
						#curl  -o /tmp/iot/YJ_MTK.bin "http://software.tuyaji.cn/YJ_MTK.bin"
						if [ -f /tmp/iot/YJ_MTK.bin ]; then
							xfwuFIRMMD5=`md5sum /tmp/iot/YJ_MTK.bin |awk -F ' ' '{print $1}'`
							echo "xfwu--------$xfwuFIRMMD5-------$firmware_md5" > /dev/console
							if [ "$xfwuFIRMMD5" = "$firmware_md5" ]; then
								echo "xfwu----6666666666-------start update" > /dev/console
								sysupgrade /tmp/iot/YJ_MTK.bin
								#sleep 1
								#report_prstatus "$seqno" "$print_id"
								#break
							fi
						fi
			
			     fi
			;;
		30)  #print task
			xfwuPrintId=`cat /tmp/iot/yjprintid`

			print_id=`/opt/bin/cjson -f "$payloadfile" -r "data:print_id"`
			echo "xfwu-------$xfwuPrintId-----333333333333-------$print_id" > /dev/console
			if [ "$xfwuPrintId" != "$print_id" ]; then
			   seqno=`/opt/bin/cjson -f "$payloadfile" -r "seqno"`
			   doc_url=`/opt/bin/cjson -f "$payloadfile" -r "data:doc_url"`
			   #doc_md5=`/opt/bin/cjson -f "$payloadfile" -f "data:md5"`
			   doc_md5=`/opt/bin/cjson -f "$payloadfile" -r "data:md5"`
			   color_print=`/opt/bin/cjson -f "$payloadfile" -r "data:color_print"`
			   uci -q set aliyun.iot.seqno=$seqno
			   #reply to aiot cloud
			   report_prtask "$seqno" "$print_id"
			   #download page, then print it, finally report print status
			   print_auth=`uci -q get aliyun.iot.print_auth`
			   
			   echo ${print_id} > /tmp/iot/yjprintid
			   if [ "z$print_auth" != "z0" ]; then
				#for var1 in 1 2 3; do
				xfwuVar=0
				#while [ true ]
				#do
				        let xfwuVar=$xfwuVar+1
					
                                   #while [ true ]
                                   #do
                                        curl  -o /tmp/iot/pr.pdf "$doc_url"
                                        echo "xfwu----------$xfwuVar" > /dev/console
                                        #curl --silent --max-time 3 -o /tmp/iot/pr.pdf "$doc_url"
                                        #wget -c  "$doc_url"  -O /tmp/iot/pr.pdf
                                        if [ -f /tmp/iot/pr.pdf ]; then
                                            xfwuMD5=`md5sum /tmp/iot/pr.pdf |awk -F ' ' '{print $1}'`
                                            echo "xfwu--------$xfwuMD5-------$doc_md5" > /dev/console
                                            if [ "$xfwuMD5" = "$doc_md5" ]; then
                                                        echo "xfwu------------print pr.pdf" > /dev/console
                                                        lp /tmp/iot/pr.pdf &
                                                        sleep 1
                                                        report_prstatus "$seqno" "$print_id"
                                                        break
                                            fi
                                         fi
                                   #done
                                #done
                             fi
                          else
                                echo "xfwu--------22222222222222------temp printid" > /dev/console
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
        printWifi=$(iwconfig apcli0|grep ESSID | awk -F ':' '{print $2}')
        echo "xfwu-----------printWifi:$printWifi" > /dev/console
        report_prwifi "$printWifi"
		#get printer
		#printername=`uci -q get aliyun.iot.printername`
		printername=`get_prname`
		printeruri=`get_pruri`
		if [ -n "$printername" ]; then
			report_prname "$printername"
			lpadmin -p ${printername} -E -m raw -v ${printeruri}
			uci -q set aliyun.iot.printername="$printername"
			lpoptions -d "$printername"
		else
			report_prname "none"
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


