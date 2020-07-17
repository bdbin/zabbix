## Zabbix install tool

The Zabbix Server Web dependent environment is based on [ILNMP](https://github.com/bdbin/lnmp "ILNMP") and has all the features of [ILNMP](https://github.com/bdbin/lnmp "ILNMP") one-click installation script. If you need to know MySQL/MariaDB/Nginx/PHP installation and configuration information, please refer to "[ILNMP](https://github.com/bdbin/lnmp "ILNMP")".

## Script properties

- Long-term maintenance, support customization;
- Support Zabbix Server 5 + series version;
- Interactively, supporting multiple versions that depend on the environment;
- Support CentOS 7 ~ 8 and Redhat 7 ~ 8 x86_64 bit system;
- The default installation (Nginx 1.19.1 PHP 7.4.8/MariaDB 10.5.4/Zabbix 5.0.1/phpMyAdmin 5) can modify the version number in the script (must be an officially known version) before installing.

## How to install

```
wget --no-check-certificate https://raw.githubusercontent.com/bdbin/zabbix/master/install_zabbix.sh
chmod 755 install_zabbix.sh
bash install_zabbix.sh
```
> Note: After the script is successfully installed, the corresponding root/Zabbix database and account/password information will be generated and printed on the current screen. After the installation is complete, please refer to the following information to manage the Zabbix monitoring system:

> Zabbix UI entrance: http://IP/ui<br/>
Zabbix management platform account password: Admin/zabbix<br/>
Zabbix database/account/password: zabbix/zabbix/zabbix

## Script support module


|  Module name | description  |
| ------------ | ------------ |
| enable-server  | Enable Zabbix Server  |
| enable-agent |  Enable Zabbix agent |
| enable-proxy  |  Enable Zabbix proxy to proxy data collection, thus sharing the load of a single Zabbix server |
| enable-ipv6  | Enable support for IPV6 protocol  |
| enable-java  | Enable Zabbix Java gateway to support monitoring of JMX applications  |
| with-mysql  | Enable MySQL as the back-end storage database  |
| with-iconv |  Enable transcoding, such as GBK to UTF-8 to prevent garbled characters |
| with-libcurl  | Enable the components required for Web monitoring, VMware monitoring, and SMTP (email sending)  |
| with-libxml2 | Required components for enabling VMware monitoring  |
| with-ssh2| SSH inspection is performed as agentless monitoring. SSH inspection does not require Zabbix Agent  |
| with-openipmi  | Enable IPMI protocol to monitor server temperature, fan speed, etc.  |
| with-net-snmp  |  Enable SNMP protocol to monitor printers, routers, UPS and other devices |

> The above modules have been automatically added and opened in compiling and installing zabbix.

## Application installation directory
|path   |description   |
| ------------ | ------------ |
|/apps/server   |All ILNMP application installation and data storage directories   |
|/apps/server/zabbix   |Zabbix Server monitoring installation directory   |
|/apps/server/zabbix/etc   |The directory where the Zabbix Server configuration file is located   |
