#!/bin/bash
# Written by wellafl3x.

# TODO:
# check suricata installation on ubuntu and kali (DONE)
# add repo with -y (DONE)
# suricata config file template with custom alert output to specific location 
# write func suricata analyze (DONE)
# guess how to import suricata logs into web page (DONE)
# paste raw suricata alerts in rita reports web pages
# test final variant in debian, kali and ubuntu

# bug - при повторном прогоне дублируется инъект сигнатур

# shellcheck disable=SC1091
source vars

#========FUNCTIONS============

# __help will show help message with -h flag
__help () {
    echo ""
    echo "Usage:"
    echo ""
    echo "This script provides automatic report generation from pcap files thru Zeek and RITA frameworks."
    echo "PCAPS and REPORTS directories will be created in current directory (by default PWD)."
    echo "If you want to change default dirs location, define PATH_TO variable in vars file before start this script."
    echo "Define WHITELIST variable to choose whitelist file, DOMAINS variable to choose domains whitelist file."
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
    echo "--disable-sur     Run script without Suricata installation"
    echo "--disable-all     Run script without any install processes"
    echo ""
}
# __check_for_root will check if file running with root priveleges and detect Debian users running the script with "sh" instead of bash
__check_for_root () {
    if [ "$EUID" -ne 0 ]
        then echo "[ERROR]: Couldn't start script. Are you root?"
        exit
    fi
    if readlink /proc/$$/exe | grep -q "dash"; then
	    echo 'This installer needs to be run with "bash", not "sh".'
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
# __os_detection will detect which repo and version is system using
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
        echo "[FATAL]: This script running on an unsupported distro"
        echo "          Supported distros are: Kali, Debian and Ubuntu"
        exit
    fi
    if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
        echo "[FATAL]: Ubuntu 22.04 or higher is required to use this script"
        exit
    fi
    if [[ "$os" == "debian" ]]; then
        if grep -q '/sid' /etc/debian_version; then
            echo "[FATAL]: Debian Testing and Debian Unstable are unsupported by this script"
            exit
        fi
        if [[ "$os_version" -lt 11 ]]; then
            echo "[FATAL]: Debian 11 or higher is required to use this script"
            exit
        fi
    fi
    echo "[INFO]: This system is using $os distro and $os_version version"
}
# __create_dirs will create dirs for pcap files analyzing, zeek and rita dirs, web files
__create_dirs () { 
    if [ ! -d "$PCAP_DIR" ]; then
        mkdir "$PCAP_DIR"
    fi
    if [ ! -d "$SURICATA_DIR" ]; then
        mkdir "$SURICATA_DIR"
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
    bison libpcap-dev libssl-dev python3 lsof python3-launchpadlib \
    nginx python3-dev swig sudo zlib1g-dev gnupg pip software-properties-common \
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
    systemctl restart smbd.service
}
# __zeek install will install zeek to the system
__zeek_install () {
    echo "[INFO]: Installing ZEEK..."
    if [ "$os" == "debian" ] || [ "$os" == "kali" ]; then
        # zeek installation for Debian
        echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
        curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
        apt update
        if ! apt install -y zeek-6.0; then
            echo "[FATAL]: Errors while installing zeek. Abort..."
            exit
        fi
    elif  [ "$os" == "ubuntu" ]; then
        # zeek installation for Ubuntu
        echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
        curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
        apt update
        if ! apt install -y zeek-6.0; then
            echo "[FATAL]: Errors while installing zeek. Abort..."
            exit
        fi
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
# __suricata_install provides installation of suricata IDS
__suricata_install () {
    echo "[INFO]: Installing Suricata..."
    if [ "$os" == "debian" ] || [ "$os" == "kali" ]; then
        # suricata installation for debian and kali
        add-apt-repository -y ppa:oisf/suricata-stable 
        apt-get update
        if ! apt-get install -y suricata; then
            echo "[FATAL]: Errors while installing suricata. Abort..."
            exit
        fi
    elif [ "$os" == "ubuntu" ]; then
        # suricata installation for ubuntu
        add-apt-repository -y ppa:oisf/suricata-stable
        apt-get update
        if ! apt-get install -y suricata; then
            echo "[FATAL]: Errors while installing suricata. Abort..."
            exit
        fi
    fi
    echo "[INFO]: Done! Checking version of Suricata.."
    sleep 1
    /usr/bin/suricata -V
    echo "[INFO]: Done! Changing default cfg file..."
    if [ -f $SURICATA_CONF_FILE ]; then
        rm $SURICATA_CONF_FILE
    fi
    cp ./templates/suricata/suricata.yaml $SURICATA_CONF_FILE
    echo "[INFO]: Done!"
    echo "[INFO]: Checking signature bases..."
    /usr/bin/suricata-update
    sleep 1
    echo "[INFO]: Done!"
}
#__suricata_analyze will analyze pcap files with signature methods
__suricata_analyze () {
    for file in "$PCAP_DIR"/*; do
        if [[ $file == *.pcap ]]; then
            if [ ! -d "$SURICATA_DIR"/"$(basename ${file})" ]; then
                mkdir "$SURICATA_DIR"/"$(basename ${file})"
            fi
            suricata -r "$file" -l "$SURICATA_DIR"/"$(basename ${file})"
        fi
    done
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
    qqqq=$PWD
    cd $RITA_DIR
    for dir in $ZEEK_DIR/*/; do
        if [ ! -z "$(ls -A $ZEEK_DIR)" ]; then
            dir_name="$(basename ${dir})"
            db_name="${dir_name%.*}"
            rita_db_list=$(rita list)
            if [[ $rita_db_list == *"$db_name"* ]]; then
                echo "RITA already has this db_name. Report will not generating"
                sleep 3
            else
                rita import $dir $db_name
                #./sur_parser.py --database $db_name --dbhost localhost
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
        fi
    done
    cd $qqqq
}
# __suricata_attach will attach raw ET alerts to RITA report
__suricata_attach () {
    line="23 a 	<li><a href="
    line+='"../ET.html"'
    line+=">Suricata ETs</a></li>"
    for dirA in "$SURICATA_DIR"/*/; do
        dirA_name=$(basename $dirA)
        dirA_name=${dirA_name%.*}
        touch $NGINX_DIR/$dirA_name/ET.html
        if cat $dirA/fast.log | grep -q ET; then
            cat $dirA/fast.log | grep ET >> $NGINX_DIR/$dirA_name/ET.html
            sed -i 's/^/<div>/' $NGINX_DIR/$dirA_name/ET.html
        else
            cat "EMPTY" >> $NGINX_DIR/$dirA_name/ET.html
        fi
    done
    for dirB in "$NGINX_DIR"/*/; do
        dirB_n4me=$(basename $dirB)
        for fileA in $dirB$dirB_n4me/*; do
            sed -i "$line" $fileA
            #if [[ $fileA == "long-conns.html" ]]; then
            #    sed -i 's/Total Duration/Total Score/g' $fileA
            #fi 
        done
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
    if ! /usr/sbin/nginx -s reload; then
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
# __filecheck will check if file is completely exists in dir
__filecheck () {
    completed=false
    while [[ "$completed" != "true" ]]; do
        for file in "$PCAP_DIR"/*; do
            if [[ $(lsof -t $file) ]]; then
                echo "[INFO]: File is busy..."
                sleep 1
            else
                echo "[INFO]: File is ready"
                completed=true
            fi
        done
    done
}
# __varcheck will check defined vars for whitelists files and working directory
__varcheck () {
    if [[ -n ${PATH_TO} ]]; then
        if [ -d "$PATH_TO" ]; then
            ROOTDIR=$PATH_TO
            if [ ${ROOTDIR: -1} = "/" ]; then # fix if path has last "/" char
                ROOTDIR=${ROOTDIR::-1}
            fi
        echo "[INFO]: Working directories will be located at $ROOTDIR"
        else
            echo "[INFO]: PATH_TO location doesn't exists. Check PATH_TO variable in vars file"
            exit
        fi
    else
        echo "[INFO]: PATH_TO variable is not set. Using default (current dir)."
        ROOTDIR=$PWD
    fi
    PCAP_DIR=$ROOTDIR/PCAPS
    if [ $WHITELIST_GEN_FLAG = "true" ]; then
        WHITELIST_FILE=$PWD/results.txt
        DOMAINS_FILE=$PWD/domains.txt
        CHANGE_CONFIG=true
        echo "[INFO]: Whitelists will be generated by automation system."
        echo "[INFO]: It may take up to 20 minutes."
    else
        if [[ -n ${WHITELIST} ]] && [[ -n ${DOMAINS} ]]; then
            if [ -f $WHITELIST ] && [ -f $DOMAINS ]; then
                WHITELIST_FILE=$WHITELIST
                DOMAINS_FILE=$DOMAINS
                CHANGE_CONFIG=true
                echo "[INFO]: IPv4 whitelist = $WHITELIST_FILE"
                echo "[INFO]: Domains whitelist = $DOMAINS_FILE"
            else
                echo "[FATAL]: Some files doesnt exists. Check whitelist and domains variables."
                exit
            fi
        else
            echo "[INFO]: WHITELIST and DOMAINS variables are not set. Using without whitelists."
        fi
    fi
    echo "Proceed? [y/N]"
    read -r response
    case "$response" in
        [yY][eE][sS]|[yY]) 
            echo "[INFO]: OK. STARTING INSTALLATION"
            sleep 1
            ;;
        *)
            exit 
            ;;
    esac
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
        __filecheck
        __suricata_analyze
        __zeek_analyze
        __rita_analyze
        __suricata_attach
    done
}

#=============================

#==========MAIN BODY==========

# Parse command args
while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                __help
                exit 0
                ;;
            -g|--generate)
                WHITELIST_GEN_FLAG=true
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
            --disable-sur)
                INSTALL_SUR=false
                ;;
            --disable-all)
                INSTALL_MONGO=false
                INSTALL_RITA=false
                INSTALL_ZEEK=false
                INSTALL_SUR=false
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
__varcheck
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
if [ "$INSTALL_SUR" = "true" ]; then
    __suricata_install
fi
if [ "$WHITELIST_GEN_FLAG" = "true" ]; then
    __whitelist_generate
fi
if [ "$CHANGE_CONFIG" = "true" ]; then
    __whitelist_attach
fi
__main


#==================================
