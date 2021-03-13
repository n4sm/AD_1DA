#!/bin/zsh

typeset nbr

nbr=0

while true
do
	let "nbr+=1"
	echo "$nbr md5 : \c"
	md5sum $1
	./$1 > /dev/null
done
