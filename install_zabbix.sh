#!/usr/bin/env bash
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin

# ILNMPZ（Installation Linux Nginx MySQL Zabbix）Unattended PHP Zabbix Development Environment Tool
# Installation Zabbix Monitoring System Script
# Author: Renwole
# Last update 2020/7/17
# Script support highly customized
# Thank you for using Renwole script

# Application Version,Can be changed as needed
php_v="7.4.8"
nginx_v="1.19.1"
libzip_v="1.7.3"
libiconv_v="1.16"
mysql_v="8.0.21"
mariadb_v="10.5.4"
phpmyadmin_v="5.0.2"

# Zabbix Monitoring System DB and dir
zabbix_v="5.0.1"
zabbix_dbname="zabbix"
zabbix_dbuser="zabbix"
zabbix_dbpwd="zabbix"
zabbix_install_dir="/apps/server/zabbix"
zabbix_file="/apps/server/zabbix/etc/zabbix_server.conf"
zabbix="https://cdn.zabbix.com/zabbix/sources/stable/5.0/zabbix-${zabbix_v}.tar.gz"

# Application installation directory,Can be changed as needed
soft_dir=/opt
web_dir="/apps/web/default"
startup_dir="/lib/systemd/system"
php_install_dir="/apps/server/php"
nginx_install_dir="/apps/server/nginx"
mysql_install_dir="/apps/server/mysql"
mysql_data_dir="/apps/server/mysql/data"
mariadb_install_dir="/apps/server/mariadb"
mariadb_data_dir="/apps/server/mariadb/data"

# System config
timezone="Asia/Shanghai"
dbroot_password="I#p1%sX@Renwole"
cpu_thread=$(grep "processor" /proc/cpuinfo | sort -u | wc -l)

# Application package download
mirrors="http://mirrors.ustc.edu.cn"
php="http://mirrors.sohu.com/php/php-${php_v}.tar.gz"
nginx="http://mirrors.sohu.com/nginx/nginx-${nginx_v}.tar.gz"
libiconv="${mirrors}/gnu/libiconv/libiconv-${libiconv_v}.tar.gz"
libzip="https://libzip.org/download/libzip-${libzip_v}.tar.gz"
phpmyadmin="https://files.phpmyadmin.net/phpMyAdmin/${phpmyadmin_v}/phpMyAdmin-${phpmyadmin_v}-all-languages.tar.gz"
mysql=${mirrors}/mysql-ftp/Downloads/MySQL-8.0/mysql-${mysql_v}-linux-glibc2.12-x86_64.tar.xz
mariadb="${mirrors}/mariadb/mariadb-${mariadb_v}/bintar-linux-systemd-x86_64/mariadb-${mariadb_v}-linux-systemd-x86_64.tar.gz"

# System initialization
Sysytem_Init(){
	rm -f /etc/localtime && ln -sf /usr/share/zoneinfo/${timezone} /etc/localtime
	sed -i 's/^SELINUX=.*$/SELINUX=disabled/' /etc/selinux/config && setenforce 0
    if ps -A | grep firewalld > /dev/null 2>&1; then
    	firewall-cmd --permanent --zone=public --add-port={80,443,3306,10050,10051}/tcp
    	firewall-cmd --reload
    fi
    echo "fs.file-max=65535" >> /etc/sysctl.conf
    cat >> /etc/security/limits.conf << EOF
* soft nproc 65535
* hard nproc 65535
* soft nofile 65535
* hard nofile 65535
EOF
}

# Install common independent dependencies.
Generic_packages(){
	[[ ! -e "/etc/yum.repos.d/epel.repo" ]] && dnf -y install epel-release
	[[ -e "/etc/yum.repos.d/CentOS-PowerTools.repo" ]] && dnf config-manager --set-enabled PowerTools
	for packages in wget tar curl gcc gcc-c++ make cmake3 openssl openssl-devel jemalloc jemalloc-devel;
	do dnf -y install ${packages}; done && ln -sf /usr/bin/cmake3 /usr/bin/cmake > /dev/null 2>&1
}

# Nginx dependent packages
Nginx_with_packages(){
	for packages in gd gd-devel pcre pcre-devel pcre2 pcre2-devel automake zlib zlib-devel jemalloc jemalloc-devel;
	do dnf -y install ${packages}; done
}

# Installation Nginx
Install_Nginx(){
	[[ $(id -u www >/dev/null 2>&1) != "0" ]] && groupadd www > /dev/null 2>&1 && useradd -s /sbin/nologin -M -g www www > /dev/null 2>&1
	[[ ! -e "${web_dir}" ]] && mkdir -p ${web_dir} && [[ ! -e "${nginx_install_dir}" ]] && mkdir -p ${nginx_install_dir}
	ulimit -SHn 65535 && cd ${soft_dir} && wget -c ${nginx} && tar zxvf nginx-${nginx_v}.tar.gz && cd nginx-${nginx_v}
	sed -i 's@CFLAGS="$CFLAGS -g"@#CFLAGS="$CFLAGS -g"@' auto/cc/gcc
	./configure --prefix=${nginx_install_dir} --user=www --group=www --with-http_v2_module --with-http_ssl_module --with-http_realip_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_secure_link_module --with-http_stub_status_module --with-http_auth_request_module --with-http_image_filter_module --with-http_slice_module --with-threads --with-file-aio --with-stream --with-stream_ssl_module --with-pcre --with-pcre-jit --with-ld-opt='-ljemalloc'
	make -j ${cpu_thread} && make install

	# Whether the installation is successful
	if [[ -e "${nginx_install_dir}/sbin/nginx" ]]; then
		rm -rf ${soft_dir}/nginx-${nginx_v}
	else
		rm -rf ${nginx_install_dir}
		printf "\e[31mERROR: \033[0mNginx install failed, Please Contact the author! \n"
		exit 1
	fi

	# Import Nginx configuration file
	cat > ${nginx_install_dir}/conf/nginx.conf << EOF
user www www;
worker_processes auto;
error_log ${nginx_install_dir}/logs/error_nginx.log crit;
pid ${nginx_install_dir}/logs/nginx.pid;
worker_rlimit_nofile 65535;

events {
  use epoll;
  worker_connections 65535;
  multi_accept on;
}

http {
  include mime.types;
  default_type application/octet-stream;
  server_names_hash_bucket_size 128;
  client_header_buffer_size 32k;
  large_client_header_buffers 4 32k;
  client_max_body_size 1024m;
  client_body_buffer_size 10m;
  sendfile on;
  tcp_nopush on;
  keepalive_timeout 120;
  server_tokens off;
  tcp_nodelay on;

  fastcgi_connect_timeout 300;
  fastcgi_send_timeout 300;
  fastcgi_read_timeout 300;
  fastcgi_buffer_size 64k;
  fastcgi_buffers 4 64k;
  fastcgi_busy_buffers_size 128k;
  fastcgi_temp_file_write_size 128k;
  fastcgi_intercept_errors on;

  # Gzip Compression
  gzip on;
  gzip_buffers 16 8k;
  gzip_comp_level 5;
  gzip_http_version 1.1;
  gzip_min_length 312;
  gzip_proxied any;
  gzip_vary on;
  gzip_types
    text/xml application/xml application/atom+xml application/rss+xml application/xhtml+xml image/svg+xml
    text/javascript application/javascript application/x-javascript
    text/x-json application/json application/x-web-app-manifest+json
    text/css text/plain text/x-component
    font/opentype application/x-font-ttf application/vnd.ms-fontobject
    image/x-icon;
  gzip_disable   "MSIE [1-6]\.";

#################### Renwole and default ########################
  server {
    listen 80 default_server;
    server_name _;
    # 301 Permanent redirect
    # return 301 http://www.renwole.com$request_uri;
    access_log ${web_dir}/access_nginx.log combined;
    root ${web_dir};
    index index.html index.htm index.php;
    location /nginx_status {
      stub_status on;
      access_log off;
      allow 127.0.0.1;
      deny all;
    }

    # Wordpress Rewrite
    # location / { try_files $uri $uri/ /index.php?$args; }
    # Wordpress Deny access to PHP files in specific directory
    # location ~ /(wp-content|uploads|wp-includes|images)/.*\.php$ { deny all; }

    location ~ [^/]\.php(/|$) {
      # fastcgi_pass  127.0.0.1:9000;
      fastcgi_pass unix:/tmp/php-cgi.sock;
      fastcgi_index index.php;
      include fastcgi.conf;
    }
    location ~ .*\.(gif|jpg|jpeg|png|bmp|swf|flv|mp4|ico)$ {
      expires 30d;
      access_log off;
    }
    location ~ .*\.(js|css)?$ {
      expires 7d;
      access_log off;
    }
    location ~ ^/(\.user.ini|\.ht|\.git|\.svn|\.project|LICENSE|README.md) {
      deny all;
    }
  }

###################### Renwole New vhost #########################
  include ${nginx_install_dir}/conf/vhosts/*.conf;
}
EOF
	# Import systemctl Nginx startup file
	cat > ${startup_dir}/nginx.service << EOF
[Unit]
Description=nginx - high performance web server
After=network.target

[Service]
Type=forking
PIDFile=${nginx_install_dir}/logs/nginx.pid
ExecStartPost=/bin/sleep 0.1
ExecStartPre=${nginx_install_dir}/sbin/nginx -t -c ${nginx_install_dir}/conf/nginx.conf
ExecStart=${nginx_install_dir}/sbin/nginx -c ${nginx_install_dir}/conf/nginx.conf
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID

[Install]
WantedBy=multi-user.target
EOF
	echo 'PATH=$PATH:'${nginx_install_dir}'/sbin' > /etc/profile.d/nginx-renwole.sh
	systemctl enable nginx.service && systemctl start nginx.service
}

# MariaDB Binary installation
Install_MariaDB(){
	useradd -M -s /sbin/nologin mariadb > /dev/null 2>&1
	[[ ! -e "${mariadb_install_dir}" ]] && mkdir -p ${mariadb_install_dir}
	echo "-=-=-=-=-=- Start installing MariaDB -=-=-=-=-=-"
	cd ${soft_dir} && wget -c ${mariadb} && tar zxf mariadb-${mariadb_v}-linux-systemd-x86_64.tar.gz
	\mv mariadb-${mariadb_v}-linux-systemd-x86_64/* ${mariadb_install_dir}

	# MariaDB whether the installation is successful
	if [[ -d "${mariadb_install_dir}/scripts" ]]; then
		rm -rf mariadb-${mariadb_v}-linux-systemd-x86_64
	else
		rm -rf ${mariadb_install_dir}
		printf "\e[31mERROR: \033[0mMariaDB install failed, Please contact the author\n"
		exit 1
	fi

	\cp -f ${mariadb_install_dir}/support-files/mysql.server /etc/init.d/mysqld
	sed -i "s@^basedir=.*@basedir=${mariadb_install_dir}@" /etc/init.d/mysqld
	sed -i "s@^datadir=.*@datadir=${mariadb_data_dir}@" /etc/init.d/mysqld
	sed -i "s@/usr/local/mysql@${mariadb_install_dir}@g" ${mariadb_install_dir}/bin/mysqld_safe
	sed -i 's@executing mysqld_safe@executing mysqld_safe\nexport LD_PRELOAD=/usr/lib64/libjemalloc.so@' ${mariadb_install_dir}/bin/mysqld_safe
	echo 'PATH=$PATH:'${mariadb_install_dir}'/bin' > /etc/profile.d/mariadb-renwole.sh

    # Import MariaDB configuration file
	cat > /etc/my.cnf << EOF
[client]
port = 3306
socket = /tmp/mysql.sock
default-character-set = utf8mb4

[mysqld]
port = 3306
socket = /tmp/mysql.sock
basedir = ${mariadb_install_dir}
datadir = ${mariadb_data_dir}
pid-file = ${mariadb_data_dir}/mysql.pid
user = mariadb
bind-address = 0.0.0.0
server-id = 1
init-connect = 'SET NAMES utf8mb4'
character-set-server = utf8mb4

skip-name-resolve
#skip-networking
back_log = 300
max_connections = 1000
max_connect_errors = 6000
open_files_limit = 65535
table_open_cache = 128
max_allowed_packet = 500M
binlog_cache_size = 1M
max_heap_table_size = 8M
tmp_table_size = 16M
read_buffer_size = 2M
read_rnd_buffer_size = 8M
sort_buffer_size = 8M
join_buffer_size = 8M
key_buffer_size = 4M
thread_cache_size = 8
query_cache_type = 1
query_cache_size = 8M
query_cache_limit = 2M
ft_min_word_len = 4
log_bin = mysql-bin
binlog_format = mixed
expire_logs_days = 7
log_error = ${mariadb_data_dir}/mysql-error.log
slow_query_log = 1
long_query_time = 1
slow_query_log_file = ${mariadb_data_dir}/mysql-slow.log
performance_schema = 0
#lower_case_table_names = 1
skip-external-locking

default_storage_engine = InnoDB
innodb_file_per_table = 1
innodb_open_files = 500
innodb_buffer_pool_size = 64M
innodb_write_io_threads = 4
innodb_read_io_threads = 4
innodb_thread_concurrency = 0
innodb_purge_threads = 1
innodb_flush_log_at_trx_commit = 2
innodb_log_buffer_size = 2M
innodb_log_file_size = 32M
innodb_log_files_in_group = 3
innodb_max_dirty_pages_pct = 90
innodb_lock_wait_timeout = 120
bulk_insert_buffer_size = 8M
myisam_sort_buffer_size = 8M
myisam_max_sort_file_size = 10G
myisam_repair_threads = 1
interactive_timeout = 28800
wait_timeout = 28800

[mysqldump]
quick
max_allowed_packet = 500M
[myisamchk]
key_buffer_size = 8M
sort_buffer_size = 8M
read_buffer = 4M
write_buffer = 4M
EOF
	# Initialize MariaDB configuration
	chown -R mariadb:mariadb ${mariadb_install_dir}
	${mariadb_install_dir}/scripts/mysql_install_db --user=mariadb --basedir=${mariadb_install_dir} --datadir=${mariadb_data_dir}
	chmod +x /etc/init.d/mysqld && systemctl enable mysqld && systemctl start mysqld
	${mariadb_install_dir}/bin/mysql -e "grant all privileges on *.* to root@'127.0.0.1' identified by \"${dbroot_password}\" with grant option;"
	${mariadb_install_dir}/bin/mysql -e "grant all privileges on *.* to root@'localhost' identified by \"${dbroot_password}\" with grant option;"
	${mariadb_install_dir}/bin/mysql -uroot -p${dbroot_password} -e "delete from mysql.user where Password='';"
	${mariadb_install_dir}/bin/mysql -uroot -p${dbroot_password} -e "delete from mysql.db where User='';"
	${mariadb_install_dir}/bin/mysql -uroot -p${dbroot_password} -e "delete from mysql.proxies_priv where Host!='localhost';"
	${mariadb_install_dir}/bin/mysql -uroot -p${dbroot_password} -e "drop database test;"
	${mariadb_install_dir}/bin/mysql -uroot -p${dbroot_password} -e "reset master;"
	rm -rf /etc/ld.so.conf.d/{mysql,mariadb}*.conf && echo "${mariadb_install_dir}/lib" > /etc/ld.so.conf.d/mariadb-renwole.conf && ldconfig
	echo "-=-=-=- MariaDB installing Successfully -=-=-=-"
}

# MySQL Binary installation
Install_MySQL() {
	useradd -M -s /sbin/nologin mysql > /dev/null 2>&1
	[[ ! -e "${mysql_install_dir}" ]] && mkdir -p ${mysql_install_dir}
	echo "-=-=-=-=-=- Start installing MySQL -=-=-=-=-=-"
	cd ${soft_dir} && wget -c ${mysql} && tar xJf mysql-${mysql_v}-linux-glibc2.12-x86_64.tar.xz
	\mv mysql-${mysql_v}-linux-glibc2.12-x86_64/* ${mysql_install_dir}
	
	# MySQL whether the installation is successful
	if [[ -d "${mysql_install_dir}/support-files" ]]; then
		rm -rf mysql-${mysql_v}-linux-glibc2.12-x86_64
	else
		rm -rf ${mysql_install_dir}
		printf "\e[31mERROR: \033[0mMySQL install failed, Please contact the author \n"
		exit 1
	fi

	\cp -f ${mysql_install_dir}/support-files/mysql.server /etc/init.d/mysqld
	sed -i "s@^datadir=.*@datadir=${mysql_data_dir}@" /etc/init.d/mysqld
	sed -i "s@^basedir=.*@basedir=${mysql_install_dir}@" /etc/init.d/mysqld
	sed -i "s@/usr/local/mysql@${mysql_install_dir}@g" ${mysql_install_dir}/bin/mysqld_safe
	sed -i 's@executing mysqld_safe@executing mysqld_safe\nexport LD_PRELOAD=/usr/lib64/libjemalloc.so@' ${mysql_install_dir}/bin/mysqld_safe
	echo 'PATH=$PATH:'${mysql_install_dir}'/bin' > /etc/profile.d/mysql-renwole.sh

	# Import MySQL configuration file
	cat > /etc/my.cnf << EOF
[client]
port = 3306
socket = /tmp/mysql.sock
default-character-set = utf8mb4
[mysql]
prompt="MySQL [\\d]> "
no-auto-rehash

[mysqld]
port = 3306
socket = /tmp/mysql.sock
default_authentication_plugin = mysql_native_password
basedir = ${mysql_install_dir}
datadir = ${mysql_data_dir}
pid-file = ${mysql_data_dir}/mysql.pid
user = mysql
bind-address = 0.0.0.0
server-id = 1
init-connect = 'SET NAMES utf8mb4'
character-set-server = utf8mb4
collation-server = utf8mb4_0900_ai_ci

skip-name-resolve
#skip-networking
back_log = 300
max_connections = 1000
max_connect_errors = 6000
open_files_limit = 65535
table_open_cache = 128
max_allowed_packet = 500M
binlog_cache_size = 1M
max_heap_table_size = 8M
tmp_table_size = 16M
read_buffer_size = 2M
read_rnd_buffer_size = 8M
sort_buffer_size = 8M
join_buffer_size = 8M
key_buffer_size = 4M
thread_cache_size = 8
ft_min_word_len = 4
log_bin = mysql-bin
binlog_format = mixed
binlog_expire_logs_seconds = 604800
log_error = ${mysql_data_dir}/mysql-error.log
slow_query_log = 1
long_query_time = 1
slow_query_log_file = ${mysql_data_dir}/mysql-slow.log
performance_schema = 0
explicit_defaults_for_timestamp
#lower_case_table_names = 1
skip-external-locking

default_storage_engine = InnoDB
#default-storage-engine = MyISAM
innodb_file_per_table = 1
innodb_open_files = 500
innodb_buffer_pool_size = 64M
innodb_write_io_threads = 4
innodb_read_io_threads = 4
innodb_thread_concurrency = 0
innodb_purge_threads = 1
innodb_flush_log_at_trx_commit = 2
innodb_log_buffer_size = 2M
innodb_log_file_size = 32M
innodb_log_files_in_group = 3
innodb_max_dirty_pages_pct = 90
innodb_lock_wait_timeout = 120
bulk_insert_buffer_size = 8M
myisam_sort_buffer_size = 8M
myisam_max_sort_file_size = 10G
myisam_repair_threads = 1
interactive_timeout = 28800
wait_timeout = 28800

[mysqldump]
quick
max_allowed_packet = 500M
[myisamchk]
key_buffer_size = 8M
sort_buffer_size = 8M
read_buffer = 4M
write_buffer = 4M
EOF
	# Initialize MariaDB configuration
	chown -R mysql:mysql ${mysql_install_dir}
	${mysql_install_dir}/bin/mysqld --initialize-insecure --user=mysql --basedir=${mysql_install_dir} --datadir=${mysql_data_dir}
	chmod +x /etc/init.d/mysqld && systemctl enable mysqld && systemctl start mysqld
  	${mysql_install_dir}/bin/mysql -uroot -hlocalhost -e "create user root@'127.0.0.1' identified by \"${dbroot_password}\";"
  	${mysql_install_dir}/bin/mysql -uroot -hlocalhost -e "grant all privileges on *.* to root@'127.0.0.1' with grant option;"
 	${mysql_install_dir}/bin/mysql -uroot -hlocalhost -e "grant all privileges on *.* to root@'localhost' with grant option;"
  	${mysql_install_dir}/bin/mysql -uroot -hlocalhost -e "alter user root@'localhost' identified by \"${dbroot_password}\";"
  	${mysql_install_dir}/bin/mysql -uroot -p${dbroot_password} -e "reset master;"
  	rm -rf /etc/ld.so.conf.d/{mysql,mariadb,percona,alisql}*.conf
  	echo "${mysql_install_dir}/lib" > /etc/ld.so.conf.d/mysql-renwole.conf && ldconfig
  	echo "-=-=-=-=- MySQL installing Successfully -=-=-=-"
}

# PHP dependencies
PHP_with_packages(){
	for packages in boost169-devel bison libargon2 libargon2-devel libjpeg-turbo libjpeg-turbo-devel libpng libpng-devel libsodium libsodium-devel libxslt libxslt-devel libcurl libcurl-devel libxml2 libxml2-devel libevent libevent-devel libidn2 libidn2-devel libicu-devel glib2 glib2-devel glibc glibc-devel gmp gmp-devel ncurses ncurses-devel openldap-devel oniguruma-devel freetype freetype-devel mhash readline readline-devel sqlite-devel autoconf libtool*;
	do dnf -y install ${packages}; done
}

PHP_with_libiconv() {
	[[ ! -e "/usr/local/lib/libiconv.la" ]] && cd ${soft_dir} && wget -c ${libiconv} && tar zxf libiconv-${libiconv_v}.tar.gz
	cd libiconv-${libiconv_v} && ./configure && make -j ${cpu_thread} && make install && rm -rf ${soft_dir}/libiconv-${libiconv_v}
}

PHP_with_libzip() {
	[[ ! -e "/usr/lib64/libzip.so" ]] && cd ${soft_dir} && wget -c ${libzip} && tar xzf libzip-${libzip_v}.tar.gz
	cd libzip-${libzip_v} && mkdir build && cd build && cmake -DCMAKE_INSTALL_PREFIX=/usr .. && make -j ${cpu_thread}
	make install && rm -rf ${soft_dir}/libzip-${libzip_v}
}

Check_library() {
	ln -sf /usr/lib64/libldap* /usr/lib > /dev/null 2>&1
	ln -sf /usr/lib64/liblber* /usr/lib > /dev/null 2>&1
	ln -sf /usr/local/lib/libiconv.so.2 /usr/lib > /dev/null 2>&1
	echo "/usr/lib64" > /etc/ld.so.conf.d/local-renwole.conf
	echo "/usr/local/lib" > /etc/ld.so.conf.d/local-renwole.conf && ldconfig
}

# installation PHP
Install_PHP() {
	[[ ! -e "${php_install_dir}" ]] && mkdir -p ${php_install_dir}/etc/php.d && cd ${soft_dir} && wget -c ${php} && tar zxf php-${php_v}.tar.gz && cd php-${php_v}
	./configure --prefix=${php_install_dir} --with-config-file-path=${php_install_dir}/etc --with-config-file-scan-dir=${php_install_dir}/etc/php.d --enable-fpm --with-fpm-user=www --with-fpm-group=www --enable-mysqlnd --with-mysqli=mysqlnd --with-pdo-mysql=mysqlnd --with-iconv-dir --with-freetype --with-jpeg --with-zlib --enable-xml --disable-rpath --enable-bcmath --enable-shmop --enable-sysvsem --enable-inline-optimization --with-curl --enable-mbregex --enable-mbstring --enable-intl --enable-pcntl --enable-ftp --enable-gd --with-openssl --with-mhash --enable-sockets --with-xmlrpc --with-zip --with-xsl --with-gettext --with-sodium --enable-soap --enable-exif --enable-opcache --disable-fileinfo --disable-debug --with-password-argon2 --enable-ctype --with-ldap
	make ZEND_EXTRA_LIBS='-liconv' -j ${cpu_thread} && make install && \cp -f php.ini-production ${php_install_dir}/etc/php.ini

	# PHP whether the installation is successful
	if [[ -e "${php_install_dir}/bin/phpize" ]]; then
		rm -rf ${soft_dir}/php-${php_v}
	else
		rm -rf ${php_install_dir}
		printf "\e[31mERROR: \033[0mPHP install Failed, Please Contact the author\n"
		exit 1
	fi

	sed -i "s@^memory_limit.*@memory_limit = 128M@" ${php_install_dir}/etc/php.ini \
	&& sed -i "s@^max_input_time.*@max_input_time = 301@" ${php_install_dir}/etc/php.ini \
	&& sed -i 's@^post_max_size.*@post_max_size = 50M@' ${php_install_dir}/etc/php.ini \
	&& sed -i 's@^upload_max_filesize.*@upload_max_filesize = 50M@' ${php_install_dir}/etc/php.ini \
	&& sed -i 's@^short_open_tag = Off@short_open_tag = On@' ${php_install_dir}/etc/php.ini \
	&& sed -i 's@^expose_php = On@expose_php = Off@' ${php_install_dir}/etc/php.ini \
	&& sed -i 's@^request_order.*@request_order = "CGP"@' ${php_install_dir}/etc/php.ini \
	&& sed -i "s@^;date.timezone.*@date.timezone = ${timezone}@" ${php_install_dir}/etc/php.ini \
	&& sed -i 's@^max_execution_time.*@max_execution_time = 300@' ${php_install_dir}/etc/php.ini \
	&& sed -i 's@^;realpath_cache_size.*@realpath_cache_size = 4M@' ${php_install_dir}/etc/php.ini \
	&& sed -i 's@^disable_functions.*@disable_functions = passthru,exec,system,chroot,chgrp,chown,shell_exec,proc_open,proc_get_status,ini_alter,ini_restore,dl,readlink,symlink,popepassthru,stream_socket_server,fsocket,popen@' ${php_install_dir}/etc/php.ini
	echo 'PATH=$PATH:'${php_install_dir}'/bin' > /etc/profile.d/php-renwole.sh

	# Import opcache configuration file
	cat > ${php_install_dir}/etc/php.d/opcache-renwole.ini << EOF
[opcache]
zend_extension=opcache.so
opcache.enable=1
opcache.enable_cli=1
opcache.memory_consumption=128
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=6000
opcache.max_wasted_percentage=5
opcache.use_cwd=1
opcache.validate_timestamps=1
opcache.revalidate_freq=60
opcache.consistency_checks=0
EOF

	# Import php-fpm configuration file
	cat > ${php_install_dir}/etc/php-fpm.conf << EOF
[global]
pid = run/php-fpm.pid
error_log = log/php-fpm.log
log_level = warning

emergency_restart_threshold = 30
emergency_restart_interval = 60s
process_control_timeout = 5s
daemonize = yes

[www]
listen = /tmp/php-cgi.sock
listen.backlog = -1
listen.allowed_clients = 127.0.0.1
listen.owner = www
listen.group = www
listen.mode = 0666
user = www
group = www
pm = dynamic
pm.max_children = 12
pm.start_servers = 8
pm.min_spare_servers = 6
pm.max_spare_servers = 12
pm.max_requests = 2048
pm.process_idle_timeout = 10s
request_terminate_timeout = 140
request_slowlog_timeout = 0
EOF
	
	# Import systemctl php-fpm startup file
	cat > ${startup_dir}/php-fpm.service << EOF
[Unit]
Description=The PHP FastCGI Process Manager
After=network.target

[Service]
Type=simple
PIDFile=${php_install_dir}/var/run/php-fpm.pid
ExecStart=${php_install_dir}/sbin/php-fpm --nodaemonize --fpm-config ${php_install_dir}/etc/php-fpm.conf
ExecReload=/bin/kill -USR2 $MAINPID

[Install]
WantedBy=multi-user.target
EOF
	systemctl enable php-fpm.service && systemctl restart php-fpm.service
}

Install_phpMyAdmin() {
	echo "-=-=-=-=- Start installing phpMyAdmin -=-=-=-=-"
	cd ${soft_dir} && wget -c ${phpmyadmin} && tar xzf phpMyAdmin-${phpmyadmin_v}-all-languages.tar.gz
	\mv phpMyAdmin-${phpmyadmin_v}-all-languages ${web_dir}/phpmyadmin
	\cp ${web_dir}/phpmyadmin/{config.sample.inc.php,config.inc.php}
	mkdir ${web_dir}/phpmyadmin/{upload,save}
	sed -i "s@UploadDir.*@UploadDir'\] = 'upload';@" ${web_dir}/phpmyadmin/config.inc.php
	sed -i "s@SaveDir.*@SaveDir'\] = 'save';@" ${web_dir}/phpmyadmin/config.inc.php
	sed -i "s@host'\].*@host'\] = '127.0.0.1';@" ${web_dir}/phpmyadmin/config.inc.php
	sed -i "s@blowfish_secret.*;@blowfish_secret\'\] = \'$(date|base64|head -c 32)\';@" ${web_dir}/phpmyadmin/config.inc.php
	echo "<?phpinfo()?>" >${web_dir}/php.php
	chmod 755 -R ${web_dir}/phpmyadmin/ && chown www.www -R ${web_dir}
	[[ -e "${web_dir}/phpmyadmin" ]] && rm -rf phpMyAdmin-${phpmyadmin_v}-all-languages &&
	printf "phpMyAdmin\e[32m [  OK  ] \033[0m \n"
}

# Installation Zabbix Monitoring System
Zabbix_with_packages(){
  for packages in mysql-devel mysql++-devel openssl11-devel net-snmp-devel OpenIPMI-devel libssh2-devel java-devel; do
    dnf -y install ${packages}; done
}

Install_Zabbix(){
  . /etc/profile
  [[ $(id -u zabbix >/dev/null 2>&1) != "0" ]] && groupadd --system zabbix > /dev/null 2>&1 && useradd --system -g zabbix -s /sbin/nologin zabbix
  cd ${soft_dir} && wget -c --no-check-certificate ${zabbix} && tar zxf zabbix-${zabbix_v}.tar.gz && cd zabbix-${zabbix_v}
  ./configure --prefix=${zabbix_install_dir} --sysconfdir=${zabbix_install_dir}/etc --enable-server --enable-agent --with-mysql --with-net-snmp --with-libcurl --with-libxml2 --enable-proxy --enable-ipv6 --enable-java --with-ssh2 --with-iconv --with-openipmi --with-ldap
  make install

  # Whether the installation is successful
  if [[ ! -e ${zabbix_install_dir}/sbin/zabbix_server ]]; then
    rm -rf ${zabbix_install_dir}
    printf "\e[31mERROR: \033[0mZabbix install Failed, Please Contact the author\n"
    exit 1
  fi

  # Configure zabbix_server.conf file
  sed -i '/^# DBSocket=/c DBSocket=/tmp/mysql.sock' ${zabbix_file} \
  && sed -i '/^# DBPassword=/c DBPassword=zabbix' ${zabbix_file} \
  && sed -i '/^# LogFileSize=/c LogFileSize=4' ${zabbix_file} \
  && sed -i '/^# StartPingers=/c StartPingers=4' ${zabbix_file} \
  && sed -i '/^# StartDiscoverers=/c StartDiscoverers=8' ${zabbix_file} \
  && sed -i '/^# CacheSize=/c CacheSize=128M' ${zabbix_file} \
  && sed -i '/^# CacheUpdateFrequency=/c CacheUpdateFrequency=120' ${zabbix_file} \
  && sed -i '/^# HistoryCacheSize=/c HistoryCacheSize=256M' ${zabbix_file} \
  && sed -i '/^# HistoryIndexCacheSize=/c HistoryIndexCacheSize=64M' ${zabbix_file} \
  && sed -i '/^# TrendCacheSize=/c TrendCacheSize=64M' ${zabbix_file} \
  && sed -i '/^# ValueCacheSize=/c ValueCacheSize=128M' ${zabbix_file} \
  && sed -i "/^LogFile=/c LogFile=${zabbix_install_dir}/logs/zabbix_server.log" ${zabbix_file} \
  && sed -i "/^# PidFile=/c PidFile=${zabbix_install_dir}/logs/zabbix_server.pid" ${zabbix_file} \
  && echo 'PATH=$PATH:'${zabbix_install_dir}'/sbin' > /etc/profile.d/zabbix-renwole.sh \
  && echo "/usr/lib64/mysql" > /etc/ld.so.conf.d/zabbix-renwole.conf && ldconfig
  [[ -e /apps/web/default ]] && \cp -rf ui ${web_dir}/ui && chown -R www.www ${web_dir}
  [[ ! -e "${zabbix_install_dir}/logs" ]] && mkdir -p ${zabbix_install_dir}/logs && chown -R zabbix.zabbix ${zabbix_install_dir}

  # Create zabbix database information
    printf "\e[34mImporting Zabbix chart data... \033[0m\n"
    mysql -uroot -p${dbroot_password} -e "create database ${zabbix_dbname} character set utf8 collate utf8_bin;"
    mysql -uroot -p${dbroot_password} -e "create user '${zabbix_dbuser}'@'localhost' identified by '${zabbix_dbpwd}';"
    mysql -uroot -p${dbroot_password} -e "grant all privileges on ${zabbix_dbname}.* to '${zabbix_dbuser}'@'localhost' with grant option;"
    mysql -u${zabbix_dbuser} -p${zabbix_dbpwd} ${zabbix_dbname} < database/mysql/schema.sql
    mysql -u${zabbix_dbuser} -p${zabbix_dbpwd} ${zabbix_dbname} < database/mysql/images.sql
    mysql -u${zabbix_dbuser} -p${zabbix_dbpwd} ${zabbix_dbname} < database/mysql/data.sql
    printf "Zabbix Data importing\e[32m [  OK  ] \033[0m\n"

  # Create zabbix startup file
  cat > /usr/lib/systemd/system/zabbix.service << EOF
[Unit]
Description=Zabbix Server
After=syslog.target
After=network.target

[Service]
Environment="CONFFILE=${zabbix_file}"
EnvironmentFile=-${zabbix_install_dir}/etc/zabbix_server.conf.d
Type=forking
Restart=on-failure
PIDFile=${zabbix_install_dir}/logs/zabbix_server.pid
KillMode=control-group
ExecStart=${zabbix_install_dir}/sbin/zabbix_server -c \$CONFFILE
ExecStop=/bin/kill -SIGTERM \$MAINPID
RestartSec=10s
TimeoutSec=0

[Install]
WantedBy=multi-user.target
EOF
  systemctl enable zabbix && systemctl start zabbix
}

# Check if the service is started
Checkservice(){
	if [[ -e "${nginx_install_dir}/sbin/nginx" ]]; then
		if ps -A | grep nginx > /dev/null 2>&1; then
			printf "Nginx Start\e[32m [  OK  ] \033[0m\n"
		else
			printf "\e[31mERROR:\033[0m Nginx Start Failure \033[0m \n"
		fi
	else
		printf "\e[1mWARNING:\033[0m Nginx is not installed \n"
		
	fi

	if [[ -d "${mariadb_install_dir}/scripts" ]]; then
		if ps -A | grep mysqld > /dev/null 2>&1; then
			
			printf "MariaDB Start\e[32m [  OK  ] \033[0m\n"
		else
			printf "\e[31mERROR:\033[0m MariaDB Start Failure \033[0m \n"
		fi
	else
		printf "\e[1mWARNING:\033[0m MariaDB is not installed \n"
	fi

	if [[ -d "${mysql_install_dir}/support-files" ]]; then
		if ps -A | grep mysqld > /dev/null 2>&1; then
			printf "MySQL Start\e[32m [  OK  ] \033[0m\n"
		else
			printf "\e[31mERROR:\033[0m MySQL Start Failure \033[0m \n"
		fi
	else
		printf "\e[1mWARNING:\033[0m MySQL is not installed \n"
	fi

	if [[ -e "${php_install_dir}/bin/phpize" ]]; then
		if ps -A | grep php-fpm > /dev/null 2>&1; then
			printf "PHP Start\e[32m [  OK  ] \033[0m\n"
		else
			printf "\e[31mERROR:\033[0m PHP Start Failure \033[0m \n"
		fi
	else
		printf "\e[1mWARNING:\033[0m PHP is not installed \n"
	fi
  if [[ -e "${zabbix_install_dir}/sbin/zabbix_server" ]]; then
    if ps -A | grep zabbix > /dev/null 2>&1; then
      printf "Zabbix Start\e[32m [  OK  ] \033[0m\n"
    else
      printf "\e[31mERROR:\033[0m Zabbix Start Failure \033[0m \n"
    fi
  else
    printf "\e[1mWARNING:\033[0m Zabbix is not installed \n"
  fi
	echo "
-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
Thank you for using Renwole script       
-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
WebRoot:
wwwroot: ${web_dir}
phpinfo: http://IP/php.php
Zabbixweb: http://IP/ui
phpMyAdmin: http://IP/phpmyadmin/index.php
-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
Database information:
account: root
password: ${dbroot_password}
Zabbix Database:
database name: ${zabbix_dbname}
account: ${zabbix_dbuser}
password: ${zabbix_dbpwd}
-=-==-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
}

# Select Web Server
while :; do
	read -e -p "Whether to install Web service? [y/n]:" web_yn
	if [[ ! "${web_yn}" =~ ^[y,n]$ ]]; then
		printf "\e[31mERROR: \033[0mPlease enter y or n\n"
	else
		if [[ "${web_yn}" == "y" ]]; then
			break
		else
			break
		fi
	fi
done

# Select DataBase
while :; do
	read -e -p "Whether to install the database? [y/n]: " db_yn
	if [[ ! "${db_yn}" =~ ^[y,n]$ ]]; then
		printf "\e[31mERROR: \033[0mPlease enter y or n\n"
	else
		if [[ "${db_yn}" == "y" ]]; then
			while :; do
				echo "Please select a database version:"
				echo -e "1 install MariaDB ${mariadb_v}"
				echo -e "2 install MySQL ${mysql_v}"
				read -e -p "Please enter the number (Default 1 Enter) :" db_option
				db_option=${db_option:-1}
				if [[ ! ${db_option} =~ ^[1-2]$ ]]; then
					printf "\e[31mERROR: \033[0mPlease enter 1 or 2\n"
				else
					break
				fi
			done
		fi
		break
	fi
done

# Select PHP
while :; do
	read -e -p "Whether to install PHP? [y/n]: " php_yn
	if [[ ! ${php_yn} =~ ^[y,n]$ ]]; then
		printf "\e[31mERROR: \033[0mPlease enter y or n\n"
	else
		if [[ "${php_yn}" == "y" ]]; then
			break
		else
			break
		fi
	fi
done

# Select phpMyadmin
while :; do
	read -e -p "Whether to install phpMyadmin? [y/n]: " phpmyadmin_yn
	if [[ ! ${phpmyadmin_yn} =~ ^[y,n]$ ]]; then
		printf "\e[31mERROR: \033[0mPlease enter y or n\n"
	else
		if [[ "${phpmyadmin_yn}" == "y" ]]; then
			break
		else
			break
		fi
	fi
done

# Select Zabbix
while :; do
  read -e -p "Whether to install Zabbix Monitoring System? y/n: " zabbix_yn
  if [[ ! ${zabbix_yn} =~ ^[y,n]$ ]]; then
    printf "\e[31mError: \033[0mPlease enter y or n\n"
  else
    if [[ "${zabbix_yn}" == "y" ]]; then
      break
    else
      break
    fi
  fi
done

# Must be root user to execute
if [[ $(whoami) != "root" ]]; then
    printf "\e[31mERROR: \033[0mMust be root user to install \n"
    exit 1
else
	command -v dnf > /dev/null 2>&1 || { [[ -e "/etc/redhat-release" ]] && yum upgrade python* -y && yum -y install dnf; }
	command -v lsb_release > /dev/null 2>&1 || { [[ -e "/etc/redhat-release" ]] && dnf -y install redhat-lsb-core; }
	command -v lsb_release > /dev/null 2>&1 || { printf "\e[31mERROR: \033[0mUnable to obtain system release \n"; exit 1; }
fi

OS_Version=$(lsb_release -sr | awk -F. '{print $1}')
if [[ "${OS_Version}" -ge 7 ]]; then
	Sysytem_Init && Generic_packages
else
	printf "\e[31mERROR: \033[0mMust be Centos7.x or Centos8.x system to install \n"
	exit 1
fi

# Install Web server with conditions
case "${web_yn}" in
  y)
	Nginx_with_packages
  Install_Nginx
  ;;
esac

# Install Database with conditions
case "${db_option}" in
  1)
	Install_MariaDB
  ;;
  2)
  Install_MySQL
  ;;
esac

# Install PHP with conditions
case "${php_yn}" in
  y)
  PHP_with_packages
  PHP_with_libiconv
  PHP_with_libzip
  Check_library
  Install_PHP
  ;;
esac

# Install phpMyadmin with conditions
case "${php_yn}" in
  y)
  Install_phpMyAdmin
  ;;
esac

# Install Zabbix with conditions
case "${zabbix_yn}" in
  y)
  PHP_with_packages
  PHP_with_libiconv
  Check_library
  Zabbix_with_packages
  Install_Zabbix
  ;;
esac

[[ -e "/apps/server" ]] && Checkservice