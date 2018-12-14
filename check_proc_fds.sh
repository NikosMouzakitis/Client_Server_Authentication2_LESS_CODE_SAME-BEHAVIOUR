#!/bin/bash
let i=0
while [ $i -lt 10000 ]
do
	ls /proc/"$1"/fd
	echo "---------------"	
	
	sleep .1
	let i=$i+1
done
