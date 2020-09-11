#!/bin/sh

xfwupm=0
xfwunm=0
if [ "$ACTION2" == "" ]; then
        devmem 0x10000060 32 0x55144450
fi

while [ true ]
do
	ACTION1=$(cat /tmp/state/xfwuPrinterledstate)
	ACTION2=$(cat /tmp/state/xfwuNetledstate)
	#/opt/bin/led_uevent.sh printer on/off to control printerled
	#/opt/bin/led_uevent.sh net on/off to control netled
	#control printerled                                         
	if [ "$ACTION1" == "1" ]; then
		if [ "$xfwupm" != "1" ]; then 
    		gpio l 2 4000 0 0 0 0
			xfwupm=1
		fi
	elif [ "$ACTION1" == "2" ]; then 
		if [ "$xfwupm" != "2" ]; then 
    		gpio l 2 0 4000 0 0 0 
			xfwupm=2
		fi    		                                  
	elif [ "$ACTION1" == "3" ]; then                            
        	sleep 1                                             
        	gpio l 2 0 4000 0 0 0                               
        	sleep 1                                             
        	gpio l 2 4000 0 0 0 0                               
	fi	

	if [ "$ACTION2" == "1" ]; then 
		if [ "$xfwunm" != "4" ]; then 
    		gpio l 2 4000 0 0 0 0  
			xfwunm=4
		fi	     
	elif [ "$ACTION2" == "2" ]; then
		if [ "$xfwunm" != "5" ]; then 
    		gpio l 2 0 4000 0 0 0  
			xfwunm=5
		fi	       
	elif [ "$ACTION2" == "3" ]; then
        	sleep 1                 
        	gpio l 1 0 4000 0 0 0   
        	sleep 1                 
        	gpio l 1 4000 0 0 0 0   
	fi
	#cat /tmp/state/xfwu*
done
