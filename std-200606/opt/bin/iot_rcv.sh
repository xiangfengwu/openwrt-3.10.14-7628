#!/bin/sh

. /opt/bin/iot_common.sh

echo "$@" >> /tmp/iot/iotrcv.dbg
action="$1"

YJIMEI=`hexdump /dev/mtd3 -C -s 1024 -n 16 |head -1 |awk  -F "|" '{print $2}' |tr -d "."`

#productKey="a1Y72Hurhna"
#device_name=${YJIMEI}

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

report_heartstatus() {
        local topic="/sys/${productKey}/${device_name}/rrpc/response/$1"
        local payloadfile="/tmp/iot/pubpayload.json"
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
	
	xfwuIOT=`cat /tmp/iot/pubtopic.json |grep request |awk -F '/' '{print $6}'`
	xfwuIOTID=`cat /tmp/iot/pubtopic.json  |awk -F '/' '{print $7}'`

	if [ "$xfwuIOT" = "request" ]; then
		sed -i "s/request/response/g" $topicfile
		report_heartstatus "$xfwuIOTID"
		echo "xfwu---`date`---report_heartstatus new iotalyun----" >> /tmp/iot/$device_name.txt 

	fi

	cmd=`/opt/bin/cjson -f "$payloadfile" -r "cmd"`
	echo "xfwu---`date`---111111111111-----hnd_recvpub----CMD:$cmd----" >> /tmp/iot/$device_name.txt 

	xfwuPrintId=`cat /tmp/iot/yjprintid`
	print_id=`/opt/bin/cjson -f "$payloadfile" -r "data:print_id"` 
	seqno=`/opt/bin/cjson -f "$payloadfile" -r "seqno"`
	 if [ "$cmd" == "30" ]; then
	 #echo "xfwu-------aaaaaaaaaaaaaaaaaaaaaa" > /dev/console
	 report_prtask "$seqno" "$print_id" 
	 fi

	case $cmd in
		10)  #print_auth
			echo "xfwu---`date`---receiver CMD:$cmd-------------" >> /tmp/iot/$device_name.txt
			print_auth=`/opt/bin/cjson -f "$payloadfile" -r "data:print_auth"`
			uci -q set aliyun.iot.print_auth=$print_auth
			firmware_md5=`/opt/bin/cjson -f "$payloadfile" -r "data:md5"`
			firmware_url=`/opt/bin/cjson -f "$payloadfile" -r "data:apk_url"`
			
			#echo "xfwu----------$firmware_md5---------------$firmware_url------" > /dev/console
			
			   if [ "$firmware_url" != "" ]; then
						echo "xfwu---`date`---receiver cmd:$cmd to start download fimrware:$firmware_url -------------" >> /tmp/iot/$device_name.txt
						curl  -o /tmp/iot/YJ_MTK.bin "$firmware_url"
						#curl  -o /tmp/iot/YJ_MTK.bin "http://software.tuyaji.cn/YJ_MTK.bin"
						if [ -f /tmp/iot/YJ_MTK.bin ]; then
							xfwuFIRMMD5=`md5sum /tmp/iot/YJ_MTK.bin |awk -F ' ' '{print $1}'`
							echo "xfwu--------$xfwuFIRMMD5-------$firmware_md5" > /dev/console
							if [ "$xfwuFIRMMD5" = "$firmware_md5" ]; then
								#echo "xfwu----6666666666-------start update" > /dev/console
								echo "xfwu---`date`---receiver CMD:$cmd--update fimrware -------------" >> /tmp/iot/$device_name.txt
								rm -rf /opt/bin/xfwusecret
								sysupgrade /tmp/iot/YJ_MTK.bin
								#sleep 1
								#report_prstatus "$seqno" "$print_id"
								#break
							fi
						fi
			
			     fi
			;;
		30)  #print task
			#xfwuPrintId=`cat /tmp/iot/yjprintid`

			#print_id=`/opt/bin/cjson -f "$payloadfile" -r "data:print_id"`
			#seqno=`/opt/bin/cjson -f "$payloadfile" -r "seqno"`
			#report_prtask "$seqno" "$print_id"
			#echo "xfwu-------$xfwuPrintId-----333333333333-------$print_id" > /dev/console
			echo "xfwu---`date`---receiver cmd30 -------------" >> /tmp/iot/$device_name.txt 
			if [ "$xfwuPrintId" != "$print_id" ]; then
			   doc_url=`/opt/bin/cjson -f "$payloadfile" -r "data:doc_url"`
			   #doc_md5=`/opt/bin/cjson -f "$payloadfile" -f "data:md5"`
			   doc_md5=`/opt/bin/cjson -f "$payloadfile" -r "data:md5"`
			   color_print=`/opt/bin/cjson -f "$payloadfile" -r "data:color_print"`
			   uci -q set aliyun.iot.seqno=$seqno
			   #reply to aiot cloud
			    echo "xfwu---`date`---report_prtask--responed cmd:$cmd to iot----" >> /tmp/iot/$device_name.txt 
			   
			   #download page, then print it, finally report print status
			   print_auth=`uci -q get aliyun.iot.print_auth`
			   xfwuVar=0
			   echo ${print_id} > /tmp/iot/yjprintid
			   if [ "z$print_auth" != "z0" ]; then
				for xfwuVar in 1 2 3; do
				
				#while [ true ]
				#do
				        
					
                                   #while [ true ]
                                   #do
										 echo "xfwu---`date`---cmd30 to start download pr.pdf-doc_url:$doc_url---" >> /tmp/iot/$device_name.txt
                                        curl  -o /tmp/iot/pr.pdf "$doc_url"
                                        #echo "xfwu----------$xfwuVar" > /dev/console
                                        #curl --silent --max-time 3 -o /tmp/iot/pr.pdf "$doc_url"
                                        #wget -c  "$doc_url"  -O /tmp/iot/pr.pdf
                                        if [ -f /tmp/iot/pr.pdf ]; then
                                            xfwuMD5=`md5sum /tmp/iot/pr.pdf |awk -F ' ' '{print $1}'`
											echo "xfwu---`date`---cmd30 to start compare  pr.pdf---$xfwuMD5----$doc_md5---" >> /tmp/iot/$device_name.txt
                                            #echo "xfwu--------$xfwuMD5-------$doc_md5" > /dev/console
                                            if [ "$xfwuMD5" = "$doc_md5" ]; then
														report_prstatus "$seqno" "$print_id"
														echo "xfwu---`date`---CMD:$cmd to print pr.pdf finished----" >> /tmp/iot/$device_name.txt
                                                        #echo "xfwu------------print pr.pdf" > /dev/console
                                                        lp /tmp/iot/pr.pdf &
                                                        sleep 1
                                                        
                                                        break
											else
														echo "xfwu---`date`---CMD:$cmd download failed retry---xfwuVar:$xfwuVar----" >> /tmp/iot/$device_name.txt
                                                        #echo "xfwu-------xfwuVar:$xfwuVar-----download failed retry" > /dev/console
                                            fi
                                         fi
					let xfwuVar=$xfwuVar+1
					
										 
                                   done
                                #done
                             fi
                          else
								echo "xfwu---`date`---cmd30 to printerid same----" >> /tmp/iot/$device_name.txt
                                echo "xfwu--------22222222222222------temp printid" > /dev/console
                          fi
                        ;;
        91)  #reboot
				echo "xfwu---`date`---cmd91 TO reboot robot----" >> /tmp/iot/$device_name.txt
                        seqno=`/opt/bin/cjson -f "$payloadfile" -r "seqno"`
                        report_reboot "$seqno"
                        sleep 2
                        reboot -f
                ;;
        92)  #log
                xfwu_token=`/opt/bin/cjson -f "$payloadfile" -r "data:qiniu_token"`
                xfwuDate=`date +%s`
                echo "xfwu---`date`---CMD:$cmd get log--key=$xfwu_token----token=`date +%s`$device_name.txt--------" >> /tmp/iot/$device_name.txt
                curl -F "key=${device_name}${xfwuDate}.txt" -F "token=${xfwu_token}" -F "file=@/tmp/iot/${device_name}.txt" http://upload-z2.qiniup.com
                #curl -F "key=${xfwuDate}${device_name}.txt" -F "token=${xfwu_token}" -F "file=@/tmp/iot/${device_name}.txt" http://upload-z2.qiniup.com
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
		echo "xfwu---`date`---report printwifiname:$printWifi-------" >> /tmp/iot/$device_name.txt
        #echo "xfwu-----------printWifi:$printWifi" > /dev/console
        report_prwifi "$printWifi"
		#get printer
		#printername=`uci -q get aliyun.iot.printername`
		printername=`get_prname`
		printeruri=`get_pruri`
		if [ -n "$printername" ]; then
			echo "xfwu---`date`---report $printername----" >> /tmp/iot/$device_name.txt
			report_prname "$printername"
			lpadmin -p ${printername} -E -m raw -v ${printeruri}
			uci -q set aliyun.iot.printername="$printername"
			lpoptions -d "$printername"
		else
			echo "xfwu---`date`---report prname none----" >> /tmp/iot/$device_name.txt
			report_prname "none"
		fi
		;;
	disconnect)
		;;
	recvpub)  # do some recv process
		echo "xfwu---`date`--recvpub cmd----" >> /tmp/iot/$device_name.txt
		hnd_recvpub "$2" "$3"
		;;
	*)
		mydebug "action=$action Not supported"
		;;
esac


