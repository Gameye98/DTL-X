#!/usr/bin/bash
banner=$(cat <<DOCUMENT
         _   _         _ _ _   
 ___ ___| | |_|___ ___| |_| |_ 
| .'|   |  _| |_ -| . | | |  _|
|__,|_|_|_| |_|___|  _|_|_|_|  
                  |_|          
[i] author: Gameye98
[i] Fri Nov 22 20:51:38 2024
[i] https://github.com/Gameye98/DTL-X
[!] remember, no whitespace in filename
DOCUMENT
)
printf "$banner\n\n"
if test -z "$1"; then
	echo -e "Usage: bash antisplit.sh <FILENAME>"
	exit 0
fi
if test ! -f "$1"; then
	echo -e "\x1b[1;41;93mantisplit: '$1': No such file exists\x1b[0m"
else
	java -jar apkeditor.jar m -i "$1"
fi
