#!/bin/bash
# Automation solution for analyzing PCAp files with Zeek and RITA frameworks.
# Written by wellafl3x.

# Troubles
# RITA make double reports

#========CONST_VARS========
if [[ ! -z ${PATH_TO} ]] && [ -d $PATH_TO ]; then # check if other path defined
    ROOTDIR="${PATH_TO}"
else
    ROOTDIR=$HOME
fi
PCAP_DIR="$ROOTDIR"/PCAPS
ZEEK_DIR=/tmp/ZEEK
RITA_DIR="$ROOTDIR"/REPORTS
NGINX_DIR=/var/www/html
INSTALL_ZEEK=true
INSTALL_MONGO=true
INSTALL_RITA=true
DB_BAN=('/' '\' '.' '"' '*' '<' '>' ':' '|' '?' '$' )
#==========================

#========FUNCTIONS========
__help () {
    echo ""
    echo "Usage:"
    echo ""
    echo "This script provides automatic report generation from pcap files thru Zeek and RITA frameworks."
    echo "PCAPS and REPORTS directories will be created in HOME directory (by default, so /root)."
    echo "If you want to change default dirs location, define PATH_TO variable before start this script."
    echo "For Ex.: PATH_TO=/home/user ./this_script.sh"
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
    echo "--disable-zeek    Run script without ZEEK installation"
    echo "--disable-rita    Run script without RITA installation"
    echo "--disable-mongo   Run script without Mongo installation"
    echo "--disable-all     Run script without any install processes"
    echo ""
}

__check_for_root () {

    if [ "$EUID" -ne 0 ]
        then echo "[ERROR]: Couldn't start script. Are you root?"
        exit
    fi

}

__zastavka () {

    echo "
              ____  ____  _    ____  _   _ _____   ____  __  __ _ _____ __  __  ___  
             / ___||  _ \| |__/ ___|| | | |_   _| / ___||  \/  (_)  ___|  \/  |/ _ \ 
             \___ \| |_) | '_ \___ \| | | | | |   \___ \| |\/| | | |_  | |\/| | | | |
              ___) |  __/| |_) |__) | |_| | | |    ___) | |  | | |  _| | |  | | |_| |
    maked by |____/|_|   |_.__/____/ \___/  |_|   |____/|_|  |_|_|_|   |_|  |_|\___/  

    "
}

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
    if [ ! -d ""$RITA_DIR"/pcaps" ]; then
        mkdir "$RITA_DIR"/pcaps
    fi
    if [ -f $NGINX_DIR/index.html ]; then
        rm $NGINX_DIR/index.html
    fi
    touch $NGINX_DIR/index.html
    echo '
    <head>
    <meta content="text/html;charset=utf-8" http-equiv="Content-Type">
    <meta content="utf-8" http-equiv="encoding">
    <link rel="stylesheet" type="text/css" href="./style.css">
    </head>    
    <p>
      <div class="info">To view individual databases, click on any of the links below.</div>
      <div class="vertical-menu">
        

        
      </div>
    </p>
    
    ' >> $NGINX_DIR/index.html

    if [ -f $NGINX_DIR/style.css ]; then
        rm $NGINX_DIR/style.css
    fi
    touch $NGINX_DIR/style.css
    echo "
    p {
    margin-bottom: 1.625em;
    font-family: 'Lucida Sans', Arial, sans-serif;
  }
  
  p {
    font-family: 'Lucida Sans', Arial, sans-serif;
    text-indent: 30px;
  }
  
  h1 {
    color: #000;
    font-family: 'Lato', sans-serif;
    font-size: 32px;
    font-weight: 300;
    line-height: 58px;
    margin: 0 0 58px;
    text-indent: 30px;
  }
  
  ul {
    list-style-type: none;
    margin: 0;
    padding: 0;
    overflow: hidden;
    background-color: #000;
    font-family: "Arial", Helvetica, sans-serif;
  }
  
  li {
    float: left;
    border-right: 1px solid #bbb;
  }
  
  li:last-child {
    border-right: none;
  }
  
  li a {
    display: block;
    color: white;
    text-align: center;
    padding: 14px 16px;
    text-decoration: none;
  }
  
  div {
    color: #adb7bd;
    font-family: 'Lucida Sans', Arial, sans-serif;
    font-size: 16px;
    line-height: 26px;
    margin: 0;
  }
  
  li a:hover {
    background-color: #34C6CD;
  }
  
  .vertical-menu {
    width: auto;
  }
  
  .vertical-menu a {
    background-color: #000;
    color: white;
    display: block;
    padding: 12px;
    text-decoration: none;
    text-align: center;
    vertical-align: middle;
  }
  
  .vertical-menu a:hover {
    background-color: #34C6CD;
  }
  
  .active {
    background-color: #A66F00;
    color: white;
  }
  
  .info {
    margin: 10px 0px;
    padding:12px;
    color: white;
    background-color: #333;
  }
  
  .container {
    overflow-x: auto;
    white-space: nowrap;
  }
  
  table {
    border-collapse: collapse;
    width: 100%;
  }
  
  th, td {
    text-align: left;
    padding: 8px;
  }
  
  tr:nth-child(even){
    background-color: #f2f2f2
  }
  
  #github {
    height: 1em;
  }
  
  
    " >> $NGINX_DIR/style.css


}

__dep_install () {
    echo "[INFO]: Installing dependencies..."
    apt-get install -y wget inotify-tools fortune \
    cmake make gcc g++ flex libfl-dev cowsay \
    bison libpcap-dev libssl-dev python3 \
    nginx python3-dev swig sudo zlib1g-dev gnupg \

    echo "[INFO]: Done."
    sleep 1
}

__zeek_install () {
    echo "[INFO]: Installing ZEEK..."
    sleep 1 
    apt install -y zeek
    git clone https://github.com/zeek/zeek-aux.git /opt/zeek-aux
    cd /opt/zeek-aux
    git clone https://github.com/zeek/cmake.git
    ./configure
    make 
    make install
    echo "[INFO]: Done."
    sleep 3

}

__mongo_install () { 
    #mongoDB
    echo "[INFO]: Installing MongoDB..."
    sleep 1 
    wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.0g-2ubuntu4_amd64.deb
    sudo dpkg -i libssl1.1_1.1.0g-2ubuntu4_amd64.deb
    curl -fsSL https://pgp.mongodb.com/server-4.2.asc | \
    sudo gpg -o /usr/share/keyrings/mongodb-server-4.2.gpg \
    --dearmor
    echo "deb [ signed-by=/usr/share/keyrings/mongodb-server-4.2.gpg ] http://repo.mongodb.org/apt/debian buster/mongodb-org/4.2 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.2.list
    sudo apt-get update
    sudo apt-get install -y mongodb-org
    systemctl daemon-reload
    systemctl start mongod
    systemctl enable mongod
    sleep 2
    netstat -luntp
    sleep 3
    echo "[INFO]: Done."
    sleep 3
}

__rita_install () {
    echo "[INFO]: Installing RITA..."
    sleep 1 
    #golang

    apt-get update
    apt-get upgrade -y
    wget https://go.dev/dl/go1.20.2.linux-amd64.tar.gz
    tar -C /usr/local/ -xvf go1.20.2.linux-amd64.tar.gz
    export GOROOT=/usr/local/go
    export GOPATH=$HOME/go
    export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
    #rita

    cd /opt
    git clone https://github.com/activecm/rita.git
    cd rita
    make install
    sudo mkdir /etc/rita && sudo chmod 755 /etc/rita
    sudo mkdir -p /var/lib/rita/logs && sudo chmod -R 755 /var/lib/rita
    sudo chmod 777 /var/lib/rita/logs
    sudo cp etc/rita.yaml /etc/rita/config.yaml && sudo chmod 666 /etc/rita/config.yaml
    echo "[INFO]: Done."
    sleep 3
}

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

__rita_analyze () {
    cd $RITA_DIR
    for dir in $ZEEK_DIR/*/; do ##
        dir_name="$(basename ${dir})"
        db_name="${dir_name%.*}"
        rita import $dir $db_name
        rita html-report $db_name
        cp -r $RITA_DIR/$db_name $NGINX_DIR
        line="10 a <a href="
        line+='"'
        line+="/$db_name/$db_name/index.html"
        line+='"'
        line+=">$db_name"
        line+='</a>"'
        sed -i "$line" $NGINX_DIR/index.html
    done
}

__nginx_conf () {
    systemctl start nginx
    rm /etc/nginx/nginx.conf
    touch /etc/nginx/nginx.conf
    echo "
        user www-data;
    worker_processes auto;
    pid /run/nginx.pid;
    include /etc/nginx/modules-enabled/*.conf;
    events {
            worker_connections 768;
    }
    http {
            sendfile on;
            tcp_nopush on;
            types_hash_max_size 2048;
            server_tokens off;
            include /etc/nginx/mime.types;
            default_type application/octet-stream;
            ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
            ssl_prefer_server_ciphers on;
            access_log /var/log/nginx/access.log;
            error_log /var/log/nginx/error.log;
            gzip on;
            gzip_vary on;
            gzip_proxied any;
            gzip_comp_level 6;
            gzip_buffers 16 8k;
            gzip_http_version 1.1;
            gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
            include /etc/nginx/conf.d/*.conf;
            #include /etc/nginx/sites-enabled/*;
    }
    " >> /etc/nginx/nginx.conf
    if [ -f /etc/nginx/conf.d/rita.conf ]; then
        rm /etc/nginx/conf.d/rita.conf
    fi
    touch /etc/nginx/conf.d/rita.conf
    echo '
        server {
        listen 80 default_server;
        listen [::]:80 default_server;
        root /var/www/html;
        server_name _;
        location / {
                try_files $uri $uri/ =404;
        }
    }
    ' >> /etc/nginx/conf.d/rita.conf
    nginx -s reload
}

#=========================

#==========MAIN BODY==========

# Parse command args
while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                __help
                exit 0
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
__zastavka
echo "Dirs will be located at $ROOTDIR. Ctrl+C to abort..."
sleep 5
__dep_install
__create_dirs
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
sleep 3
fortune | cowsay
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
#==================================
