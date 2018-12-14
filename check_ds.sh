#!/bin/bash
##script to inspect the number of file descriptors every second.
let i=0
while [ $i -lt 1000 ]
do
	cat /proc/sys/fs/file-nr
	sleep 1
	let i=$i+1
done
