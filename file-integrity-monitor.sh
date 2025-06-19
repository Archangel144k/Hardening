#!/bin/bash  
original_checksum=$(md5sum "$file" | awk '{print $1}')  
current_checksum=$(md5sum "$file" | awk '{print $1}')  
[ "$original_checksum" != "$current_checksum" ] && echo "ALERT: File tampered!"