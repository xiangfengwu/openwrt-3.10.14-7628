#!/bin/sh
#bytian
set -x

ACTION=$1
[ "$ACTION" = "" ] && ACTION=connect
logger -t wifirelay 'wifirelay.sh is called'

do_apcli_scan() {
	#using global variable: ssid;  will seting global variable: AuthMode EncrypType channel
	#will scan the ssid then return 1; otherwise return 0
	local found=0
	#do scan first
	iwpriv ra0 set SiteSurvey=1
	sleep 5
	#wifilist=`iwpriv ra0 get_site_survey | sed -n '3,$p'`
	iwpriv ra0 get_site_survey | sed -n '3,$p' > /tmp/wifirelay
	#then get correct encrytype and channel
	#echo $wifilist | while read Ch SSID BSSID Security Signal OTHER ; do
	while read Ch SSID BSSID Security Signal OTHER ; do
		if [ "$ssid" = "$SSID" ]; then
			case "$Security" in
				*WPA2PSK*AES)
					AuthMode=WPA2PSK
					EncrypType=AES
					encryption="wpa2"
				;;
				*WPA2PSK*TKIP)
					AuthMode=WPA2PSK
					EncrypType=TKIP
					encryption="psk2+tkip"
				;;
				*NONE*)
					AuthMode=OPEN
					EncrypType=NONE
					encryption="none"
				;;
			esac
			channel=$Ch
			[ -z "$channel" ] && channel="$_channel"
			found=1
		fi
	done < /tmp/wifirelay
	
	if [ "$found" -eq 1 ]; then
		return 1
	else
		echo "Can not scan the specified SSID[$ssid]"
		return 0
	fi
}

do_apcli_connect() {
	##using global variable: ssid AuthMode EncrypType channel passwd
	local oldchannel
	oldchannel=`uci -q get wireless.mt7620.channel`
	if [ "$oldchannel" != "$channel" ]; then
		uci -q set wireless.mt7620.channel="$channel"
		uci commit
		sync
	fi

	iwpriv $cliif set ApCliEnable=0
	iwpriv $cliif set ApCliSsid="$ssid"
	iwpriv $cliif set ApCliAuthMode=$AuthMode
	iwpriv $cliif set ApCliEncrypType=$EncrypType
	iwpriv $cliif set ApCliWPAPSK="$passwd"
	#iwpriv $cliif set Channel="$channel"
	iwpriv ra0 set Channel="$channel"
	iwpriv $cliif set ApCliEnable=1

}

allsid="wifirelay2g wifirelay5g"

for sid in $allsid; do
	AuthMode=""
	EncrypType=""
	ssid=""
	passwd=""
	enabled=`uci -q get wifirelay.${sid}.enabled`
	if [ "z$enabled" = "z1" ]; then
		ssid=`uci -q get wifirelay.${sid}.ssid`
		passwd=`uci -q get wifirelay.${sid}.key`
		AuthMode=`uci -q get wifirelay.${sid}.AuthMode`
		EncrypType=`uci -q get wifirelay.${sid}.EncrypType`
		notscan=`uci -q get wifirelay.${sid}.notscan`
		case "$sid" in
			wifirelay2g)
				cliif=apcli0
				;;
			wifirelay5g)
				cliif=apcli50
				;;
		esac

		case $ACTION in
			scan)
				do_apcli_scan
				exit $?
				;;
			connect)
				if [ "z$notscan" = "z1" ]; then
					wifi reload_legacy  #not do scan; connect upper ap directly after reload_legacy
					sleep 5
				else
					do_apcli_scan   #do can; then resetting the parameter: channel, AuthMode, EncrypType, key
				fi
				if [ $? -eq 1 ]; then
					ifconfig $cliif down
					do_apcli_connect
					ifconfig $cliif up
				fi
				;;
		esac
	else
		echo "${sid} disabled!"
		continue
	fi
done




