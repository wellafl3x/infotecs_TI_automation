#!/bin/bash

#======= Functions======

__smb_install () {
    apt install samba >> /dev/null
}
__start () {
    echo "What you wanna to do? "
    echo "1. Add directory to smb access-list. Will be create user."
    echo "2. Add user to existed smb directory."
    echo "3. Delete directory from smb."
    echo "4. Delete user."
    echo "5. Exit."
    echo "Type number: "
}
__smb_dir_add () {
    echo "diradd"
}
__smb_user_add () {
    echo "useradd"
}
__smb_dir_del () {
    echo "dirdel"
}
__smb_user_del () {
    echo "userdel"
}


#===========


__smb_install
__start
while true
do
    read -r action
    case $action in
        1)
            __smb_dir_add
            __start
            ;;
        2)
            __smb_user_add
            __start
            ;;
        3)
            __smb_dir_del
            __start
            ;;
        4)
            __smb_user_del
            __start
            ;;
        5)
            exit 1
            ;;
        *)
            echo "Try again...."
            ;;
    esac
done
