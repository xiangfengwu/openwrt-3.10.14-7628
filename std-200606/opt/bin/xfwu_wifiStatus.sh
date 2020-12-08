#!/bin/sh

. /opt/bin/iot_common.sh

num=1
knum=1
touch /tmp/state/xfwuPrinterledstate
touch /tmp/state/xfwuNetledstate
pnum=1
npnum=1
devmem 0x10000060 32 0x55144450
gpio l 2 0 0 5 0 4000 > /dev/null
gpio l 1 0 0 5 0 4000 > /dev/null
kkkp=3

xfwuUSB=$(ls -R /dev/bus/usb|wc -w)


if [ "$xfwuUSB" != "7" ]; then 
        	gpio l 2 4000 0 0 0 0 > /dev/null
fi



if [ ! -f "/opt/bin/xfwusecret" ];then
     touch /opt/bin/xfwusecret
fi

YJIMEI=`hexdump /dev/mtd3 -C -s 1024 -n 16 |head -1 |awk  -F "|" '{print $2}' |tr -d "."` 

#/opt/bin/xfwu_led_uevent.sh &

/opt/bin/xfwu_Net_uevent.sh &

#iwpriv ra0 set SiteSurvey=2
#sleep 1
#iwpriv ra0 get_site_survey > /www/luci-static/xfwuWifiList2.txt
#cat /www/luci-static/xfwuWifiList2.txt|awk '{print $2}' > /www/luci-static/xfwuWifiList.txt

echo "" > /www/luci-static/xfwuWifiList.txt

while [ true ]
do
	#echo "xfwu-----------main pthread" > /dev/console
	result=$(iwconfig apcli0|grep ESSID | awk -F ':' '{print $2}')
        echo ${#result} > /tmp/state/xfwuWifistate
        LENX=$(cat /tmp/state/xfwuWifistate)
	YJSECRET=$(cat /opt/bin/xfwusecret|sed 's/"//g')
   	   
    if [ $kkkp -ne 0 ]; then
        let kkkp=$kkkp-1
#        iwpriv ra0 set SiteSurvey=2
#        sleep 2
#        iwpriv ra0 get_site_survey|awk '{if (NR>2){print $2}}' >> /www/luci-static/xfwuWifiList2.txt
        #cat /www/luci-static/xfwuWifiList2.txt|awk '{print $2}' >> /www/luci-static/xfwuWifiList.txt
iwpriv ra0 set SiteSurvey=2&& sleep 1 &&iwpriv ra0 get_site_survey|awk '{if (NR>2){print $2}}' >> /www/luci-static/xfwuWifiList.txt
		#cat /tmp/wifirelay > /www/luci-static/xfwuWifiList.txt
    fi           
	if [ "$LENX" != "4" ]; then
			iwconfig apcli0|grep ESSID | awk -F ':' '{print $2}' > /www/luci-static/wifiConnectApName.txt
      	      if [ "$YJIMEI" != "" ]; then
                 if [ "$YJSECRET" != "" ]; then
				echo "xfwu---`date`---start mqtt to iot--${productUrl}---${productKey}---${YJIMEI}----${YJSECRET}--" >> /tmp/iot/$YJIMEI.txt 
		     #echo "xfwu----------mqtt to start" > /dev/console 
	             #/opt/bin/mqtt-basic-demo -u iot-cn-oew1vzsj40v.mqtt.iothub.aliyuncs.com -p a1Y72Hurhna  -d ${YJIMEI} -s ${YJSECRET} > /tmp/iot/xfwuMqtt.log
				 /opt/bin/mqtt-basic-demo -u ${productUrl}  -p ${productKey}  -d ${YJIMEI} -s ${YJSECRET}
	             sleep 3
                 fi
              fi
	fi

done
