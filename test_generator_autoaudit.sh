#!/bin/bash

usernames=("root" "kali" "test" "gleb" "hacker" "eragon" "aragorn" "geralt" "han_solo" "harry" "obiwan" "ender" "paul_atreides" "blackhat" "shadow_wolf") 

for user in {1..250}; do
    ran_index=$(($RANDOM % ${#usernames[@]}))
    echo "User: ${usernames[$ran_index]}"
    timeout 1s ssh ${usernames[$ran_index]}@127.0.0.1
    sleep 2
done

for idx in {1..6}; do
    timeout 1s ssh obiwan@127.0.0.1
    sleep 3
done