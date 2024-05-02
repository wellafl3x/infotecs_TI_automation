#!/bin/bash
# Automation solution for analyzing PCAP files with Zeek and RITA frameworks.
# Written by wellafl3x.
# TODO:
# 1. add case if rita doesnt analyze file so report dont attach to nginx


#========CONST_VARS========
if [[ ! -z ${PATH_TO} ]] && [ -d "$PATH_TO" ]; then # check if other path defined
    ROOTDIR="${PATH_TO}"
else
    ROOTDIR=$HOME
fi
#dirs and files
PCAP_DIR="$ROOTDIR"/PCAPS
ZEEK_DIR=/tmp/ZEEK
RITA_DIR="$ROOTDIR"/REPORTS
NGINX_DIR=/var/www/html
RITA_CONF_FILE=/etc/rita/config.yaml
#flags
INSTALL_ZEEK=true
INSTALL_MONGO=true
INSTALL_RITA=true
WHITELIST_GEN_FLAG=false
SMB_CONF=false
os=null
os_version=null
#==========================

#========FUNCTIONS========
# __help will show help message with -h flag
__help () {
    echo ""
    echo "Usage:"
    echo ""
    echo "This script provides automatic report generation from pcap files thru Zeek and RITA frameworks."
    echo "PCAPS and REPORTS directories will be created in HOME directory (by default, so /root)."
    echo "If you want to change default dirs location, define PATH_TO variable before start this script."
    echo "Define WHITELIST variable to choose whitelist file, DOMAINS variable to choose domains whitelist file."
    echo "For Ex.: PATH_TO=/home/user WHITELIST=/home/user/results.txt DOMAINS=/home/user/domains.txt ./this_script.sh"
    echo ""
    echo "Put your .pcap files into PCAP folder, then in REPORTS dir will generated RITA reports "
    echo "and your files moved. Do not delete PCAP and REPORTS dirs, it will ruin work of script."
    echo ""
    echo "WARNING: files must not contain one of this symbols:"
    echo '/ \ . " * < > : | ? $ or spaces and null characters.'
    echo ""
    echo "Options:"
    echo ""
    echo "-h --help         Display this message"
    echo ""
    echo "-g --generate     Generate whitelist (up to 15 min)"
    echo "-smb --samba      Use samba for access to PCAPS directory"
    echo "--disable-zeek    Run script without ZEEK installation"
    echo "--disable-rita    Run script without RITA installation"
    echo "--disable-mongo   Run script without Mongo installation"
    echo "--disable-all     Run script without any install processes"
    echo ""
}
# __check_for_root will check if file running with root priveleges
__check_for_root () {

    if [ "$EUID" -ne 0 ]
        then echo "[ERROR]: Couldn't start script. Are you root?"
        exit
    fi

}
# _hello will display graphic message with team name
__hello () {

    echo "
              ____  ____  _    ____  _   _ _____   ____  __  __ _ _____ __  __  ___  
             / ___||  _ \| |__/ ___|| | | |_   _| / ___||  \/  (_)  ___|  \/  |/ _ \ 
             \___ \| |_) | '_ \___ \| | | | | |   \___ \| |\/| | | |_  | |\/| | | | |
              ___) |  __/| |_) |__) | |_| | | |    ___) | |  | | |  _| | |  | | |_| |
    maked by |____/|_|   |_.__/____/ \___/  |_|   |____/|_|  |_|_|_|   |_|  |_|\___/  

    "
}
# __os_detection will detect which repo is system using
__os_detection () {
    if grep -qs "ubuntu" /etc/os-release; then
        os="ubuntu"
        os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    elif [[ -e /etc/debian_version ]]; then
        if grep -q kali /etc/debian_version; then
            os="kali"
            os_version=$(lsb_release -a | grep Release)
            os_version="${os_version:9}"
        else
            os="debian"
            os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
        fi
    else
        echo "This script running on an unsupported distro"
        echo "Supported distros are: Kali, Debian and Ubuntu"
        exit
    fi
    if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
        echo "Ubuntu 22.04 or higher is required to use this script"
        exit
    fi
    if [[ "$os" == "debian" ]]; then
        if grep -q '/sid' /etc/debian_version; then
            echo "Debian Testing and Debian Unstable are unsupported by this script"
            exit
        fi
        if [[ "$os_version" -lt 11 ]]; then
            echo "Debian 11 or higher is required to use this script"
            exit
        fi
    fi
    echo "This system is using $os distro and $os_version version"
    sleep 2
}
# __create_dirs will create dirs for pcap files analyzing, zeek and rita dirs, web files
__create_dirs () { 
    if [ ! -d "$PCAP_DIR" ]; then
        mkdir "$PCAP_DIR"
    fi
    if [ ! -d "$ZEEK_DIR" ]; then
        mkdir "$ZEEK_DIR"
    fi
    if [ ! -d "$RITA_DIR" ]; then
        mkdir "$RITA_DIR"
    fi
    if [ ! -d "$RITA_DIR/pcaps" ]; then
        mkdir "$RITA_DIR"/pcaps
    fi
    if [ -f $NGINX_DIR/index.html ]; then
        rm $NGINX_DIR/index.html
    fi
    touch $NGINX_DIR/index.html
    cat ./templates/web/index.html >> $NGINX_DIR/index.html
    if [ -f $NGINX_DIR/style.css ]; then
        rm $NGINX_DIR/style.css
    fi
    touch $NGINX_DIR/style.css
    cat ./templates/web/style.css >> $NGINX_DIR/style.css
}
# __dep_install will install dependencies
__dep_install () {
    echo "[INFO]: Installing dependencies..."
    apt-get update --fix-missing
    apt-get install -y git curl wget inotify-tools fortune \
    cmake make rsync gcc g++ flex libfl-dev cowsay \
    bison libpcap-dev libssl-dev python3 \
    nginx python3-dev swig sudo zlib1g-dev gnupg pip \
    >> /dev/null
    echo "[INFO]: Done."
}
# __smb_configure will install samba, create samba user and attach pcap_dir to samba
__smb_configure () {
    apt install -y samba >> /dev/null
    echo "[INFO]: Configuring smb..."
    echo "Enter username (it must be exists in OS!): "
    read -r smb_username
    c_c=0
    while [ $c_c != 1 ]; do
      echo "Enter password: "
      read -rs smb_password
      echo "Retype password: "
      read -rs smb_passw0rd
      if [ "$smb_password" == "$smb_passw0rd" ]; then
        c_c=1
      else
        echo "Try again!"
      fi
    done
    echo "Success!"
    sleep 1
    (echo "$smb_password"; sleep 1; echo "$smb_password" ) | sudo smbpasswd -s -a "$smb_username"
    smb_config_path=/etc/samba/smb.conf
    rm $smb_config_path
    cp ./templates/smb/smb.conf /etc/samba
    echo "
    "
    {
        echo -e "\n"
        echo "[pcaps]"
        echo "   path = $PCAP_DIR"
        echo "   read only = no"
        echo "   guest ok = no"
        echo "   valid user = $smb_username"
    } >> $smb_config_path
    systemctl enable smbd.service
    systemctl start smbd.service
}
# __zeek install will install zeek to the system
__zeek_install () {
    echo "[INFO]: Installing ZEEK..."
    if [ "$os" == "debian" ] || [ "$os" == "kali" ]; then
        # zeek installation for Debian
        echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
        curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
        apt update
        apt install -y zeek-6.0
    elif  [ "$os" == "ubuntu" ]; then
        # zeek installation for Ubuntu
        echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
        curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
        apt update
        apt install -y zeek-6.0
    fi
    echo "export PATH=$PATH:/opt/zeek/bin" >> $HOME/.bashrc
    echo "[INFO]: Done."
}
# __mongo_install will install mongoDB 4.2 to the system
__mongo_install () {
    echo "[INFO]: Installing MongoDB..."
    if [ "$os" == "debian" ] || [ "$os" == "kali" ]; then
        # mongodb installation for debian
        wget https://ftp.debian.org/debian/pool/main/o/openssl/libssl1.1_1.1.1w-0+deb11u1_amd64.deb
        sudo dpkg -i libssl1.1_1.1.1w-0+deb11u1_amd64.deb
        curl -fsSL https://pgp.mongodb.com/server-4.2.asc | \
        sudo gpg -o /usr/share/keyrings/mongodb-server-4.2.gpg \
        --dearmor
        echo "deb [ signed-by=/usr/share/keyrings/mongodb-server-4.2.gpg ] http://repo.mongodb.org/apt/debian buster/mongodb-org/4.2 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.2.list
        sudo apt-get update
        sudo apt-get install -y mongodb-org
    elif [ "$os" == "ubuntu" ]; then
        # mongodb installation for ubuntu
            wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.0g-2ubuntu4_amd64.deb
            sudo dpkg -i libssl1.1_1.1.0g-2ubuntu4_amd64.deb
            curl -fsSL https://pgp.mongodb.com/server-4.2.asc | \
            sudo gpg -o /usr/share/keyrings/mongodb-server-4.2.gpg \
            --dearmor
            echo "deb [ signed-by=/usr/share/keyrings/mongodb-server-4.2.gpg ] http://repo.mongodb.org/apt/debian buster/mongodb-org/4.2 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.2.list
            sudo apt-get update
            sudo apt-get install -y mongodb-org
    fi
    systemctl daemon-reload
    systemctl start mongod
    systemctl enable mongod
    echo "[INFO]: Done."
}
# __rita_install will install Golang 1.20 and RITA from src
__rita_install () {
    echo "[INFO]: Installing RITA..."
    #installing golang from src
    apt-get update
    wget https://go.dev/dl/go1.20.2.linux-amd64.tar.gz
    tar -C /usr/local/ -xvf go1.20.2.linux-amd64.tar.gz >> /dev/null
    {
        echo 'export GOROOT=/usr/local/go'
        # shellcheck disable=SC2016
        echo 'export GOPATH=$HOME/go'
        # shellcheck disable=SC2016
        echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH'
    } >> $HOME/.bashrc
    #installing rita from src
    git clone https://github.com/activecm/rita.git /opt/rita
    qq=$PWD
    cd /opt/rita
    make install
    sudo mkdir /etc/rita && sudo chmod 755 /etc/rita
    sudo mkdir -p /var/lib/rita/logs && sudo chmod -R 755 /var/lib/rita
    sudo chmod 777 /var/lib/rita/logs
    sudo cp etc/rita.yaml /etc/rita/config.yaml && sudo chmod 666 /etc/rita/config.yaml
    echo "[INFO]: Done."
    cd $qq
}
# __zeek_analyze will analyze pcap files and generate zeek tmp logs
__zeek_analyze () {
    for file in "$PCAP_DIR"/*; do
        if [[ $file == *.pcap ]]; then
            if [ ! -d "$ZEEK_DIR"/"$(basename ${file})" ]; then
                mkdir "$ZEEK_DIR"/"$(basename ${file})"
            fi
            zeek -C -r "$file" Log::default_logdir="$ZEEK_DIR"/"$(basename ${file})" # -C ignore TCP checksum errors, -r file
            mv "$file" "$RITA_DIR"/pcaps/
        fi
    done
}
# __rita_analyze will create reports based on zeek logs, and make this reports accessible via 80 port
__rita_analyze () {
    cd $RITA_DIR
    for dir in $ZEEK_DIR/*/; do ##
        if [ ! -z "$(ls -A $ZEEK_DIR)" ]; then
          dir_name="$(basename ${dir})"
          db_name="${dir_name%.*}"
          rita import $dir $db_name
          rita html-report $db_name
          cp -r $RITA_DIR/$db_name $NGINX_DIR
          rm -r $dir
          line="10 a <a href="
          line+='"'
          line+="./$db_name/$db_name/index.html"
          line+='"'
          line+=">$db_name"
          line+='</a>"'
          sed -i "$line" $NGINX_DIR/index.html
        fi
    done
}
# __nginx_conf will configure NGINX web-server to access thru him to rita reports
__nginx_conf () {
    systemctl start nginx
    rm /etc/nginx/nginx.conf
    touch /etc/nginx/nginx.conf
    cat ./templates/web/nginx.conf >> /etc/nginx/nginx.conf
    if [ -f /etc/nginx/conf.d/rita.conf ]; then
      rm /etc/nginx/conf.d/rita.conf
    fi
    touch /etc/nginx/conf.d/rita.conf
    cat ./templates/web/rita.conf >> /etc/nginx/conf.d/rita.conf
    if ! nginx -s reload; then
      echo "[INFO]: Error while reload NGINX."
    else
      echo "[INFO]: Nginx reloaded"
    fi
}
# __whitelist_generate will generate whitelists of IPs and Domains via main.py file
__whitelist_generate () {
    pip install -r ./requirements.txt --break-system-packages
    echo "Начинается генерация вайтлистов. Может занять примерно 15 минут"
    if ! python3 main.py; then 
        echo "Error while generating whitelist."
        exit 1
    fi
}
# __whitelist_attach will attach generated whitelists to rita config file
__whitelist_attach () {
    rm $RITA_CONF_FILE
    cp ./templates/rita/config.yaml $RITA_CONF_FILE
    ip_match="  # IP WHITELIST goes here"
    sed -i "/$ip_match/r $WHITELIST_FILE" $RITA_CONF_FILE
    dom_match='  # DOMAINS WHITELIST goes here'
    if [ "$DOM_FLAG" = "true" ]; then
        dom_replace="  NeverIncludeDomain:"
        sed -i "s/$dom_match/$dom_replace\n$dom_match/" $RITA_CONF_FILE
        sed -i "/$dom_replace/r $DOMAINS_FILE" $RITA_CONF_FILE
    else
        dom_replace="  NeverIncludeDomain: []"
        sed -i "s/$dom_match/$dom_replace\n$dom_match/" $RITA_CONF_FILE
    fi    
}
# __main func start inotify dir monitoring
__main () {
    /usr/games/cowsay -f eyes "The system has been started. Can be accessible on 80 port."
    inotifywait \
    "$PCAP_DIR" \
    --monitor \
    -e create \
    -e moved_to \
    --include "\.pcap" \
    | while read -r dir act fil; do
        __zeek_analyze
        __rita_analyze
    done
}
#=========================

#==========MAIN BODY==========

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

# Parse command args
while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                __help
                exit 0
                ;;
            -g|--generate)
                if [ -z ${WHITELIST+x} ] && [ -z ${DOMAINS+x} ]; then
                    WHITELIST_GEN_FLAG=true
                else
                    echo "You cannot generate whitelist file because you set WHITELIST and DOMAINS vars."
                    echo "Please, see help page (-h) or README file."
                    exit 1
                fi
                ;;
            -smb|--samba)
                SMB_CONF=true
                ;;
            --disable-zeek)
                INSTALL_ZEEK=false
                ;;
            --disable-mongo)
                INSTALL_MONGO=false
                ;;
            --disable-rita)
                INSTALL_RITA=false
                ;;
            --disable-all)
                INSTALL_MONGO=false
                INSTALL_RITA=false
                INSTALL_ZEEK=false
                ;;
            *)
            echo "Incorrect flags. See -h or --help."
            exit 1
            ;;
        esac
        shift
    done
__check_for_root
__hello
__os_detection
if [[ ! -z ${WHITELIST} ]] && [ -f "$WHITELIST" ]; then # check if other path defined
    WHITELIST_FILE="${WHITELIST}"
    CHANGE_CONFIG=true
    echo "Whitelist = $WHITELIST_FILE"
elif [ "$WHITELIST_GEN_FLAG" = "true" ]; then
    echo "Whitelist = will be generated"
else
    echo "Whitelist = none."
    CHANGE_CONFIG=false
fi
if [[ ! -z ${DOMAINS} ]] && [ -f "$DOMAINS" ]; then # check if other path defined
    DOMAINS_FILE="${DOMAINS}"
    echo "Domains whitelist = $DOMAINS_FILE"
    DOM_FLAG=true
elif [ "$WHITELIST_GEN_FLAG" = "true" ]; then
    echo "Domains whitelist = will be generated"
else
    echo "Domains whitelist = none."
    DOM_FLAG=false
fi
echo "Dirs will be located at $ROOTDIR. Ctrl+C to abort..." 
sleep 5
__dep_install
__create_dirs
if [ "$SMB_CONF" = "true" ]; then
    __smb_configure
fi
__nginx_conf
if [ "$INSTALL_ZEEK" = "true" ]; then
    __zeek_install
fi
if [ "$INSTALL_MONGO" = "true" ]; then
    __mongo_install
fi
if [ "$INSTALL_RITA" = "true" ]; then
    __rita_install
fi
if [ "$WHITELIST_GEN_FLAG" = "true" ]; then
    echo "Generation of whitelists can be up to 15 minutes"
    __whitelist_generate
    WHITELIST_FILE="$PWD/results.txt"
    DOMAINS_FILE="$PWD/domains.txt"
fi
if [ "$CHANGE_CONFIG" = "true" ]; then
    __whitelist_attach
fi
__main
#==================================
