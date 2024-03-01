#!/bin/bash

# Welcome to autoaudit, a log tampering detection tool

LOG_FILES=(
	/var/run/utmp
	/var/log/wtmp2
	/var/log/btmp2
)


###################
#####Functions#####
###################

###Tampering Detection###

function tamper_zeroing() {
	output+=("**Detecting tampering by checking for abnormal record type**")
	#Checks first column for 0 or not 1-9
	for i in "${LOG_FILES[@]}"
	do
		dump=$(utmpdump $i)
		IFS=$'\n'
		# for loop to process each line in "dump"
		for line in $dump; do
			# FIX THIS REGEX. DOENS'T MATCH ON DOUBLE DIGITS
			first_check=$(echo "$line" | sed 's/[][]//g' | awk '{ print $1}' | grep -E '[^1-9]')
			second_check=$(echo "$line" | sed 's/[][]//g' | awk '{ print $1}' | grep -E '.{2,}')
			if [[ -n "$first_check" || -n "$second_check" ]]; then
				# echo "The following logs may have been modified:"
				# echo "$line"
				output+=("The following logs in ${i} may have been modified (suspicious record type value):")
				output+=("$line")
				output+=("")
			fi
		done
	done
}

function tamper_erasure() {
	output+=("**Detecting tampering by checking for erasures in logs**")
	#Checks for more than 3 blank entries within a line in the tmp logs (3 or less can be normal)
	#this value can be adjusted below:
	erasure_sensitivity_num=3
	for i in "${LOG_FILES[@]}"
	do
		dump=$(utmpdump $i)
		IFS=$'\n'
		#process each line in "dump"
		for line in $dump
		do
			num_erased=$(echo "$line" | grep -Eo '\[\s*\]' | wc -l)
			if [[ $num_erased -gt $erasure_sensitivity_num ]]
			then
				# echo "The following logs may have been modified:"
				# echo "$line"
				output+=("The following logs in ${i} may have been modified (suspicious number of blank entries - $num_erased):")
				output+=("$line")
				output+=("")
			fi
		done
	done
}

function tamper_time() {
	output+=("**Detecting tampering by comparing file modification and last entry times**")
	#Checks for discrepancies between the last entry time and the file modification time
	for i in "${LOG_FILES[@]}"; do
		#get most recent times, convert to seconds since epoch
		file_mod_time=$(stat -c %Y $i)
		last_entry_time=$(utmpdump $i | tail -1 | cut -d [ -f-3,5- | sed 's/[][]//g' | awk '{ print $NF }')
		last_entry_time=$(date -d "${last_entry_time}" +%s)
		#now compare the two times
		if [[ $file_mod_time -ne $last_entry_time ]]; then
			# echo "The following logs may have been modified:"
			# echo "$i"
			output+=("The log ${i} may have been modified (last entry time and file modification time do not match):")
			output+=("Most recent entry time: $(date -d @${last_entry_time})")
			output+=("File modification time: $(date -d @${file_mod_time})")
			output+=("")
		fi
	done
}

function tamper_datetimes() {
	output+=("**Detecting tampering by comparing datetimes of log entries**")
	#Checks for inconsistencies with datetimes of previous log entries (out of order in time)
	for i in "${LOG_FILES[@]}"; do
		dump=$(utmpdump $i)
		IFS=$'\n'
		previous_time=""
		current_time=""
		for line in $dump
		do
			current_time=$(echo "$line" | awk '{print $NF }' | sed 's/[][[:space:]]//g')
			if [[ "$previous_time" != "" && "$current_time" < "$previous_time" ]]
			then
				output+=("The following log in ${i} may have been modified (out of order entry times):")
				output+=("$line")
				output+=("Previous log time: $previous_time")
				output+=("Current log time: $current_time")
				output+=("")
			fi
			if [[ $(date -d $"$current_time" +%s) = 0 ]]; then
				output+=("The following log in ${i} may have been modified (reset timestamp):")
				output+=("$line")
				output+=("")
			fi			
			previous_time=$current_time
		done
	done
}

###Identity Attacks###

function brute_users() {
	# echo "**Detecting bruteforce attempts by comparing /etc/passwd and /var/log/btmp**"
	output+=(**"Detecting bruteforce attempts by comparing /etc/passwd and /var/log/btmp**")
	#this function compares users in /etc/passwd with users in /var/log/btmp - if a username has attempted to login multiple times but is not in /etc/passwd, this will alert
	#pulls btmp users via utmpdump into variable "log_users"
	log_users=$(utmpdump /var/log/btmp | awk -F ']' '{ print $4 }' | sed 's/[][[:space:]]//g')
	#while loop to define /etc/passwd users as arr_pusers
	while IFS=: read -r p_user x x x x x x
	do
		arr_pusers[$i]=$p_user
		i=$(($i + 1))
	done </etc/passwd
	#outside for loop takes log_users and establishes array arr_users
	#inside for loop compares a single log_user with each individual arr_user
	#variable badguy is set to true at the start of each log_user loop and will only be set to false if a match is found
	declare -a reported_users
	for user in ${log_users}; do
		badguy=true
		arr_users=(${arr_users[@]} ${user})
		for p_user in "${arr_pusers[@]}"; do
			if [[ "$user" == "$p_user" ]]; then
				badguy=false
				break
			fi
		done
		#badguy variable will be true if no match between a user in btmp and /etc/passwd is found; the second if statement will only continue if the btmp user is not in the reported_users array (ie has not been reported/printed yet)
		if [ "$badguy" == true ]; then
			if [[ ! " ${reported_users[@]} " =~ " ${user} " ]]; then
				count=$(utmpdump /var/log/btmp | awk -F ']' '{ print $4 }' | sed 's/[][[:space:]]//g' | grep ${user} | wc -l)
				if [ $count -gt 0 ]; then
					# echo "Username ${user} is not a registered user, but has attempted to login ${count} times."
					output+=("Username ${user} is not a registered user, but has attempted to login ${count} times.")
				fi
				reported_users+=("${user}")
			fi
		fi
	done
}

function brute_by_time() {
	# echo "**Detecting bruteforce attempts by time analysis**"
	output+=("**Detecting bruteforce attempts by time analysis**")
	#this function will identify bruteforce attempts in btmp by number of occurences within 10 minutes
	#associative array in bash explantion: https://linuxhint.com/associative_array_bash/
	#log_users is a list of all usernames logged in btmp
	log_users=$(utmpdump /var/log/btmp | awk -F ']' '{ print $4 }' | sed 's/[][[:space:]]//g')
	#uniqueUsers is an associative array of the following structure: key=unique username found in btmp / value=number of times that user attempted to login
	declare -A uniqueUsers
	for user in ${log_users}; do
		if [ ${uniqueUsers[${user}]+_} ]; then
			uniqueUsers[${user}]=$((${uniqueUsers[${user}]}+1))
			# echo "match found. new value for ${user} is ${uniqueUsers[${user}]}"
		else
			uniqueUsers[${user}]=1
			# echo "array key added for ${user}"
		fi
	done
	#conduct time analysis within this for loop
	# a ! in front of an associative array returns the keys of the array
	for uUser in "${!uniqueUsers[@]}"; do
		#get timestamps of failed login attempts for the uUser in the for loop
        timestamps=( $(utmpdump /var/log/btmp | grep ${uUser} | awk '{ print $NF }' | sed 's/[][[:space:]]//g' | while IFS= read -r line; do
            if [ "$line" != "Utmp dump of /var/log/btmp" ]; then
				echo $line
            fi
        done) )

        # look for brute force 
		# set sensitivity number (sens_num) to the number of failed attempts within a certain time frame (sens_time) in seconds
		sens_num=3
		sens_time=120
		# for loop to iterate over timestamp array - note, the # in front of timestamps[@] returns the length of the array
		for ((i=0; i<${#timestamps[@]}-(${sens_num}-1); i++)); do
			start_time=$(date -d"${timestamps[$i]}" +%s)
			end_time=$(date -d"${timestamps[$i+(${sens_num}-1)]}" +%s)

			# if the time difference is less than or equal to sens_num, print the identified attack
			if (( end_time - start_time <= ${sens_time} )); then
				# echo "Brute force attempt detected: User ${uUser} had at least ${sens_num} failed login attempts within $((sens_time/60)) minutes."
				# echo "The failed logins were attempted between ${timestamps[$i]} and ${timestamps[$i+(${sens_num}-1)]}"
				output+=("Brute force attempt detected: User ${uUser} had at least ${sens_num} failed login attempts within $((sens_time/60)) minutes.")
				output+=("The failed logins were attempted between ${timestamps[$i]} and ${timestamps[$i+(${sens_num}-1)]}")
				break
			fi
		done
	done
}

###################
#####Execution#####
###################

RUNNING=true
option=CHECK_ROOT
while $RUNNING; do
 case $option in
  CHECK_ROOT)
	#ensure user is root or running sudo
   if [[ "$EUID" -ne 0 ]]; then
	echo "You must be root to use autoaudit."
	option=none
   else
	option=SELECTION 
   fi
  ;;
  SELECTION)
   output=()
   echo "Which logs? 1=Identity Attacks 2=Log Tampering Attacks 3=utmp 4=wtmp"; read -t 10 choice
   if [[ "$choice" -eq 1 ]];
   then
	option=IDENTITY
   elif [[ choice -eq 2 ]];
   then
	option=TAMPER
   elif [[ choice -eq 3 ]];
   then
	option=UTMP
   elif [[ choice -eq 4 ]];
   then
	option=WTMP
   else
	echo "Please select an appropriate option next time."
   fi
  ;;
  IDENTITY)
   brute_users
   brute_by_time
   output=("****Analyzing Logs for Identity Attacks****" "" "${output[@]}")
   option=RESULTS
  ;;
  UTMP)
   echo "utmp"
   option=SELECTION
  ;;
  WTMP)
   echo "wtmp"
   option=SELECTION
  ;;
  TAMPER)
   tamper_zeroing
   tamper_erasure
   tamper_time
   tamper_datetimes
   output=("****Analyzing Logs for Tampering and Manipulation****" "" "${output[@]}")
   option=RESULTS
   ;;
   RESULTS)
   echo ""
   echo "******************"
   echo "Autoaudit Results:"
   echo "******************"
   echo ""
    for line in "${output[@]}"; do
		echo "$line"
	done
	option=default
  ;;
  *)
   echo ""
   echo "Thanks for using Autoaudit!"
   sleep 5 
   exit 0 
  ;;
 esac
done
