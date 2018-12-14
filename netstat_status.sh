#!/bin/bash

let i=0
while [ $i -lt 1000 ]
do
#	netstat | wc -l	
	netstat | grep CLOSE_WAIT	
	echo "---------------"	
	
	sleep 1
	let i=$i+1
done
