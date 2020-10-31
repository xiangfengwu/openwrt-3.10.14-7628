#!/bin/sh
append DRIVERS "mt7628"

. /lib/wifi/ralink_common.sh

prepare_mt7628() {
	prepare_ralink_wifi mt7628
}

scan_mt7628() {
	scan_ralink_wifi mt7628 mt7628
}


disable_mt7628() {
	disable_ralink_wifi mt7628
}

enable_mt7628() {
	enable_ralink_wifi mt7628 mt7628
	/opt/bin/wifirelay.sh
}

detect_mt7628() {
#       detect_ralink_wifi mt7628 mt7628
        YJIMEI2=`hexdump /dev/mtd3 -C -s 1024 -n 16 |head -1 |awk  -F "|" '{print $2}' |cut -c 10-15|tr -d "."`
            if [ "$YJIMEI2" != "" ]; then
                        rm /etc/config/wireless
                        ssid=PeriPage-PG1-${YJIMEI2}
						echo ${ssid} > /www/luci-static/wifiname.txt
            else
                        ssid=PeriPage-PG1-`ifconfig eth0 | grep HWaddr | cut -c 51- | sed 's/://g'`
			fi
        cd /sys/module/
        [ -d $module ] || return
         cat <<EOF
config wifi-device      mt7628
        option type     mt7628
        option vendor   ralink
        option band     2.4G
        option channel  0
        option auotch   2

config wifi-iface
        option device   mt7628
        option ifname   ra0
        option network  lan
        option mode     ap
        option ssid     $ssid
        option encryption psk2
        option key      12345678

EOF


}


