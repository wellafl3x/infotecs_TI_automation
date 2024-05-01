#!/bin/bash
#============================
__hard_remove () {
   # remove rita

   # remove mongodb

   # remove zeek
   echo ""
}
__soft_remove () {
   # remove reports from web dir
   rm -rf /var/www/html/*
   # remove db data from rita
   rita delete -a -f
   # remove smb configs
   rm /etc/samba/smb.conf
   cp ../templates/smb/smb.conf /etc/samba/smb.conf
   systemctl restart smbd.service
   # remove nginx configs
   rm /etc/nginx/conf.d/rita.conf
}
#============================
__soft_remove
read -r -p "Hard? [y/N] " response
case "$response" in
    [yY][eE][sS]|[yY]) 
        __hard_remove
        ;;
    *)
        echo "Bye =)"
        ;;
esac