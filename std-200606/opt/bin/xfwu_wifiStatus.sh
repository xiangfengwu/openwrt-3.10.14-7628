#!/bin/sh

num=1
knum=1
touch /tmp/state/xfwuPrinterledstate
touch /tmp/state/xfwuNetledstate
pnum=1
npnum=1
echo 3 > /tmp/state/xfwuPrinterledstate
echo 3 > /tmp/state/xfwuNetledstate
kkkp=3

xfwuUSB=$(ls -R /dev/bus/usb|wc -w)


if [ "$xfwuUSB" != "7" ]; then 
        	echo 1 > /tmp/state/xfwuPrinterledstate
fi



if [ ! -f "/opt/bin/xfwusecret" ];then
     touch /opt/bin/xfwusecret
fi

YJIMEI=`hexdump /dev/mtd3 -C -s 1024 -n 16 |head -1 |awk  -F "|" '{print $2}' |tr -d "."` 

/opt/bin/xfwu_led_uevent.sh &

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

    fi           
	if [ "$LENX" != "4" ]; then
      	      if [ "$YJIMEI" != "" ]; then
                 if [ "$YJSECRET" != "" ]; then
		     echo "xfwu----------mqtt to start" > /dev/console 
	             /opt/bin/mqtt-basic-demo -p a1Y72Hurhna  -d ${YJIMEI} -s ${YJSECRET} > /tmp/iot/xfwuMqtt.log
	             sleep 3
                 fi
              fi
	fi

done
