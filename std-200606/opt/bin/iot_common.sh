#!/bin/sh

YJIMEI=`hexdump /dev/mtd3 -C -s 1024 -n 16 |head -1 |awk  -F "|" '{print $2}' |tr -d "."`

#productKey="g1mumCzFX3Z"
productKey="g1muOMP4uiS"
device_name=${YJIMEI}
productUrl="iot-cn-oew1vzsj40v.mqtt.iothub.aliyuncs.com"

mydebug() {  #bytian
	echo "$1" >> /tmp/iot/iotrcv.dbg
	#echo $1
	# :
}

get_prname() {
	local prname
	prname=`/usr/sbin/lpinfo -l -v |grep -A 3 "class = direct" |grep "make-and-model" |awk -F "= " '{ print $2 }' |tr " " "_"`
	echo "$prname"
}

get_pruri() {
        local pruri
        pruri=`/usr/sbin/lpinfo -l -v |grep -C 3  "class = direct" |grep "uri" |awk -F "= " '{ print $2 }' |tr " " "_"`
        echo "$pruri"
}

cunix_send() {
	local topic="$1"
	local payloadfile="$2"
	/opt/bin/cunix "$topic@${payloadfile}"
}

get_seqno() {
	random=`date +%s |cut -c4-10`
	echo "$random"
}

