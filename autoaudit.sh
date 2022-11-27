#!/bin/bash

# Welcome to autoaudit, a log tampering detection tool

LOG_FILES=(
	/var/run/utmp
	/var/log/wtmp
	/var/log/btmp
)
###################
#####Functions#####
###################

function testall() {
#Checks first column for 0 or not 1-9
	for i in "${LOG_FILES[@]}"
	do
		all_check=$(utmpdump $i | grep -E '^\[.[0-9]+\]|^\[0\]')
		printf "Check it out:\n ${all_check}\n"
	done
}

function brute_users() {
	#pulls btmp users via utmpdump into variable "log_users"
	log_users=$(utmpdump /var/log/btmp | cut -d [ -f-3,5- | sed 's/[][]//g' | awk '{ print $3}')
	i=0
	#while loop to define /etc/passwd users as arr_pusers
	while IFS=: read -r p_user x x x x x x
	do
		arr_pusers[$i]=$p_user
		#echo "${arr_pusers[i]}"
		i=$(($i + 1))
	done </etc/passwd
	i=0
	#outside for loop takes log_users and establishes array arr_users
	#inside for loop compares a single log_user with each individual arr_user
	#variable badguy is set to true at the start of each log_user loop (outside loop), assuming bad. in inside loop, variable match is set to true, assuming good. if two users do not match, then match is set to false and then reset to true at the beginning of loop. if a match occurs then match does not change and badguy is set to false (since a match exists). at the end of the outside loop, badguy is checked for true or false. if true (ie a match never occurred) then it alerts
	for user in ${log_users}; do
		badguy=true
		echo "${user}"
		arr_users=(${arr_users[@]} ${user})
		for p_user in ${arr_pusers[@]}; do
			match=true
			#echo "${user}"
			#echo "${p_user}"
			if [ "$user" != ${p_user} ]; then
				match=false
			fi
			if [ "$match" == true ]; then
				badguy=false
			fi
		done
		#i=$(($i + 1));
		if [ "$badguy" == true ]; then
			echo "Potential bruteforce identified with username: ${user}"
		fi 
	done
}

#Function that will check for zeroed out logs by entry level and dates
#Add function that will check all usernames in btmp dump and compare them to usernames in /etc/password - could show bruteforcing of common creds
	#if login is by tty1 - that means physical access and could suggest insider threat
#Add function that will search for bruteforce attempts in btmp by times (10 or more within 5 minutes)


#Execution

RUNNING=true
option=CHECK_ROOT
while $RUNNING; do
 case $option in
  CHECK_ROOT)
   if [[ "$EUID" -ne 0 ]]; then
	echo "You must be root to use autoaudit."
	option=none
   else
	option=SELECTION 
   fi
  ;;
  SELECTION)
   echo "Which logs? 1=btmp 2=utmp 3=wtmp 4=all of the above"; read -t 10 choice
   echo "choice: ${choice}"
   if [[ "$choice" -eq 1 ]];
   then
	option=BTMP
   elif [[ choice -eq 2 ]];
   then
	option=UTMP
   elif [[ choice -eq 3 ]];
   then
	option=WTMP
   elif [[ choice -eq 4 ]];
   then
	option=ALL
   else
	echo "Please select an appropriate option next time."
   fi
  ;;
  BTMP)
   echo "btmp"
   option=none
   brute_users
  ;;
  UTMP)
   echo "utmp"
   option=SELECTION
  ;;
  WTMP)
   echo "wtmp"
   option=SELECTION
  ;;
  ALL)
   echo "ALL of them"
   testall
   option=SELECTION
  ;;
  *)
   echo "default case reached"
   sleep 5  
  ;;
 esac
done
testlogs
