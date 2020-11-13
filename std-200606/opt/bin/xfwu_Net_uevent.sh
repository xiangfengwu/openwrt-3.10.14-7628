#!/bin/sh

pnum=1
npum=1
knum2=1

while [ true ]
do
	YJIMEI=`hexdump /dev/mtd3 -C -s 1024 -n 16 |head -1 |awk  -F "|" '{print $2}' |tr -d "."`
        result=$(iwconfig apcli0|grep ESSID | awk -F ':' '{print $2}')
        mqttPID=`ps | grep mqtt-basic-demo |grep opt |head -1 |awk  -F  " " '{print $1}'`
	#echo "iot mask and wifi state--------xfwu" > /dev/console
        echo ${#result} > /tmp/state/xfwuWifistate
        LENX=$(cat /tmp/state/xfwuWifistate)
	YJSECRET=$(cat /opt/bin/xfwusecret|sed 's/"//g')	
        if [ "$LENX" != "4" ]; then
            
	    if [ "$pnum" = "1" ]; then
                echo 1 > /tmp/state/xfwuNetledstate
                pnum=0
                npnum=1
				echo "xfwu---`date`---enjoy shopping internet----" >> /tmp/iot/$YJIMEI.txt
            fi
            if [ "$knum2" = "1" ]; then
                if [ "$YJIMEI" != "" ]; then 
                       # YJSECRET=$(cat /opt/bin/xfwusecret|sed 's/"//g')
                       # rm /opt/bin/xfwusecret
                        #curl --connect-timeout 3 --max-time 3 --retry 5 -G http://192.168.0.200:8081/v3/common/sec2?itg=${YJIMEI} -o /opt/bin/xfwusecret
                      if [ "$YJSECRET" = "" ]; then 
					  echo "xfwu---`date`---GET THE YJSECRET:$YJSECRET----by YJIMEI:$YJIMEI-------" >> /tmp/iot/$YJIMEI.txt
			curl --connect-timeout 3 --max-time 3 --retry 5 -k -G https://www.tuyaji.com.cn/cloudprintv2-wxapplet-box/v3/common/sec2?itg=${YJIMEI} -o /opt/bin/xfwusecret
			#knum2=0
                        echo "xfwu-----YJSECRET:$YJSECRET" > /dev/console
                        echo "xfwu-----YJIMEI:$YJIMEI" > /dev/console
			sleep 3
		      fi
                fi
            fi				
	else
                echo "xfwu------no internet connect" > /dev/console
                if [ "$npnum" = "1" ]; then
                        echo 3 > /tmp/state/xfwuNetledstate
                        npnum=0
                        pnum=1
						echo "xfwu---`date`---NO shopping internet----" >> /tmp/iot/$YJIMEI.txt
                fi
				kill ${mqttPID}
                sleep 2
				/opt/bin/wifirelay.sh
				sleep 8
        fi


done
