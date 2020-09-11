#!/bin/sh

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

cunix_send() {
	local topic="$1"
	local payloadfile="$2"
	/opt/bin/cunix "$topic@${payloadfile}"
}

get_seqno() {
	random=`date +%s |cut -c4-10`
	echo "$random"
}

