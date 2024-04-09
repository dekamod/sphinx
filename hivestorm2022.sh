#!/bin/bash

mkdir /backups
tar -czf "/backups/etc-$(date).tar.gz" /etc
tar -czf "/backups/var-www-$(date).tar.gz" /var/www

#check last modified files and write to location.
apt-get -qq update -y --allow-unauthenticated > /dev/null && apt-get -qq upgrade -y --allow-unauthenticated > /dev/null && apt-get install -qq --reinstall debsums coreutils auditd ufw gufw aptitude openssl bum clamav unhide bash openssl libssl-dev libpam-cracklib apparmor apparmor-profiles -ym --allow-unauthenticated > /dev/null
apt-get install apparmor apparmor-profiles apparmor-utils -ymqq
echo "Do you want to quit and run debsums now? If so, run 'debsums -a'"
read exitdesired
if [ $exitdesired == "y" ]; then
	exit
fi
echo "y" | sudo ufw enable
ufw logging high
ufw default deny incoming
echo "ufw complete"
echo "Do you want Apache to be installed? [y/n] "
read apachedesired
if [ $apachedesired == "y" ]; then
    apt install apache2 -ymqq
    apt install libxml2 libxml2-dev libxml2-utils -ymqq
    apt install libaprutil1 libaprutil1-dev -ymqq
    apt install libapache2-mod-security2 -ymqq
    apt install libapache2-mod-evasive -ymqq
    apt install libapache2-mod-apparmor -ymqq
    sed -i 's/ServerTokens.*/ServerTokens Prod/g' /etc/apache2/conf-enabled/security.conf
    sed -i 's/ServerSignature.*/ServerSignature Off/g' /etc/apache2/conf-enabled/security.conf
    sed -i 's/TraceEnable.*/TraceEnable Off/g' /etc/apache2/conf-enabled/security.conf
    sed -i '/nosniff/s/^#//g' /etc/apache2/conf-enabled/security.conf
    sed -i '/sameorigin/s/^#//g' /etc/apache2/conf-enabled/security.conf
    sed -i 's/Timeout.*/Timeout 45/g' /etc/apache2/apache2.conf
    sed -i 's/KeepAliveTimeout.*/KeepAliveTimeout 1/g' /etc/apache2/apache2.conf
    sed -i 's/^KeepAlive.*/KeepAlive Off/g' /etc/apache2/apache2.conf
    sed -i 's/MaxKeepAliveRequests.*/MaxKeepAliveRequests 50/g' /etc/apache2/apache2.conf
    sed -i 's/LogLevel.*/LogLevel info/g' /etc/apache2/apache2.conf
    sed -i 's/Options Indexes FollowSymLinks/Options -Indexes/g' /etc/apache2/apache2.conf
    grep "Directory />" /etc/apache2/apache2.conf -A 3 | grep -v "Options FollowSymLinks" | grep -v "AllowOverride None" | grep -v "Require all denied" | grep -v "Directory />"
    grep "Directory /usr/share>" /etc/apache2/apache2.conf -A 2 | grep -v "Directory /usr/share>" | grep -v "AllowOverride None" | grep -v "Require all granted"
    grep "Directory /var/www/>" /etc/apache2/apache2.conf -A3 | grep -v "Directory /var/www/>" | grep -v "Options Indexes FollowSymLinks" | grep -v "AllowOverride None" | grep -v "Require all granted"
    grep "Directory /srv/>" /etc/apache2/apache2.conf -A3 | grep -v "#"
    grep "<FilesMatch" -A1 /etc/apache2/apache2.conf | grep -v "FilesMatch" | grep -v "Require all denied"
    ps aux|grep apache2 | grep -v "www-data" | grep -v "grep " | grep -v " -k start"
    if [ $? -eq 0 ]; then
        echo "apache may be running as the root user"
    fi
    for file in $(find /etc -iname "php.ini")
    do
      sed -i 's/short_open_tag.*/short_open_tag = Off/g'  $file
      sed -i 's/output_buffering.*/output_buffering = 4096/g'  $file
      sed -i 's/expose_php.*/expose_php = Off/g'  $file
      sed -i 's/display_errors.*/display_errors = Off/g'  $file
      sed -i 's/log_errors.*/log_errors = On/g'  $file
      sed -i 's/enable_dl.*/enable_dl = Off/g'  $file
      sed -i 's/sql.safe_mode.*/sql.safe_mode = On/g'  $file
      sed -i 's/file_uploads.*/file_uploads = On/g'  $file
      sed -i 's/allow_url_fopen.*/allow_url_fopen = Off/g'  $file
      sed -i 's/allow_url_include.*/allow_url_include = Off/g'  $file
      sed -i 's/session.name.*/session.name = COOKIEMONSTER/g'  $file
      sed -i 's/disable_functions.*/disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source/g'  $file
    done

    find /var/www -iname "*.php" -print -exec grep "(exec|CMD|shell|system|passthru)" -exec mv -t /backups {} +

    a2enmod headers
    a2enmod rewrite
    a2enmod mpm_prefork
    a2enmod apparmor
    a2enmod ssl
    a2ensite default-ssl
    a2dismod -f autoindex
    a2dismod status
    service apache2 restart
    update-rc.d apache2 enable
    ufw allow in 80

    sed -i '30 i Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"' /etc/apache2/sites-enabled/default-ssl.conf
    sed -i '30 i Header always set X-Content-Type-Options nosniff"' /etc/apache2/sites-enabled/default-ssl.conf
    sed -i '30 i Header always set X-Frame-Options DENY"' /etc/apache2/sites-enabled/default-ssl.conf
    mv /etc/apache2/mods-available/ssl.load /etc/apache2/mods-enabled/
    mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
    sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/" /etc/modsecurity/modsecurity.conf
    sed -i "s/SecResponseAccess On/SecResponseAccess Off/" /etc/modsecurity/modsecurity.conf
    aa-enforce apache2
    service apache2 restart
    update-rc.d apache2 enable
else
    apt purge apache2 --auto-remove 
fi
echo -n "Do you want SSHD installed (y/n)? " 
read sshinstalled
if [ $sshinstalled == "y" ]; then
sed -i -E 's/PasswordAuthentication.*/PasswordAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/Protocol.*/Protocol 2/g' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin.*/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
sed -i 's/UsePam no/UsePam yes/g' /etc/ssh/sshd_config
sed -i 's/RSAAuthentication no/RSAAuthentication yes/g' /etc/ssh/sshd_config
sed -i 's/PermitEmptyPasswords yes/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/StrictModes no/StrictModes yes/g' /etc/ssh/sshd_config
sed -i 's/LoginGraceTime.*/LoginGraceTime 60/g' /etc/ssh/sshd_config
sed -i 's/IgnoreRhosts no/IgnoreRhosts yes/g' /etc/ssh/sshd_config
sed -i 's/TCPKeepAlive yes/TCPKeepAlive no/g' /etc/ssh/sshd_config
sed -i 's/UsePrivilegeSeperation no/UsePrivilegeSeperation yes/g' /etc/ssh/sshd_config
sed -i 's/PubkeyAuthentication.*/PubkeyAuthentication yes/g' /etc/ssh/sshd_config
sed -i 's/PermitBlacklistedKeys yes/PermitBlacklistedKeys no/g' /etc/ssh/sshd_config
sed -i 's/HostbasedAuthentication yes/HostbasedAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/PrintMotd yes/PrintMotd no/g' /etc/ssh/sshd_config
ufw allow in 22
update-rc.d ssh defaults
update-rc.d ssh enable
service ssh restart
service ssh reload
#apparmor for all services.
else
  apt purge openssh-server -ymqq
  ufw deny in 22
fi

sed -i 's/net.ipv4.ip_forward.*/net.ipv4.ip_forward=0/g' /etc/sysctl.conf
sed -i 's/net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies=1/g' /etc/sysctl.conf
sed -i 's/net.ipv4.conf.default.accept_source_route.*/net.ipv4.conf.default.accept_source_route=0/g' /etc/sysctl.conf
sed -i 's/kernel.sysrq.*/kernel.sysrq=0/g' /etc/sysctl.conf
sed -i 's/net.ipv4.tcp_synack_retries.*/net.ipv4.tcp_synack_retries=5/g' /etc/sysctl.conf
sed -i 's/net.ipv4.conf.all.send_redirects.*/net.ipv4.conf.all.send_redirects=0/g' /etc/sysctl.conf
sed -i 's/net.ipv4.conf.default.send_redirects.*/net.ipv4.conf.default.send_redirects=0/g' /etc/sysctl.conf
sed -i 's/net.ipv4.conf.all.secure_redirects.*/net.ipv4.conf.all.secure_redirects=0/g' /etc/sysctl.conf
sed -i 's/net.ipv4.conf.all.accept_redirects.*/net.ipv4.conf.all.accept_redirects=0/g' /etc/sysctl.conf
sed -i 's/net.ipv4.conf.default.accept_redirects.*/net.ipv4.conf.default.accept_redirects=0/g' /etc/sysctl.conf
sed -i 's/net.ipv4.conf.default.secure_redirects.*/net.ipv4.conf.default.secure_redirects=0/g' /etc/sysctl.conf
sed -i 's/kernel.randomize_va_space.*/kernel.randomize_va_space=2/g' /etc/sysctl.conf
sed -i 's/net.ipv4.icmp_echo_ignore_broadcasts.*/net.ipv4.icmp_echo_ignore_broadcasts=1/g' /etc/sysctl.conf
sed -i 's/net.ipv4.icmp_ignore_bogus_error_responses.*/net.ipv4.icmp_ignore_bogus_error_responses=1/g' /etc/sysctl.conf
sed -i 's/fs.protected_hardlinks.*/fs.protected_hardlinks=1/g' /etc/sysctl.conf
sed -i 's/fs.protected_symlinks.*/fs.protected_symlinks=1/g' /etc/sysctl.conf
sed -i 's/kernel.exec-shield.*/kernel.exec-shield=2/g' /etc/sysctl.conf
sed -i 's/kernel.kernel.dmesg_restrict.*/kernel.dmesg_restrict=1/g' /etc/sysctl.conf
sed -i 's/net.ipv4.conf.all.log_martians.*/net.ipv4.conf.all.log_martians=1/g' /etc/sysctl.conf
sed -i 's/net.ipv4.conf.all.rp_filter.*/net.ipv4.conf.all.rp_filter=1/g' /etc/sysctl.conf
sed -i 's/net.ipv4.conf.default.rp_filter.*/net.ipv4.conf.default.rp_filter=1/g' /etc/sysctl.conf
sed -i 's/net.ipv4.tcp_rfc1337.*/net.ipv4.tcp_rfc1337=1/g' /etc/sysctl.conf
echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_rfc1337=1" >> /etc/sysctl.conf
echo "kernel.dmesg_restrict=1" >> /etc/sysctl.conf

sysctl -w net.ipv4.tcp_rfc1337=1
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w kernel.sysrq=0
sysctl -w net.ipv4.tcp_synack_retries=5
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w kernel.randomize_va_space=2
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1 
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w fs.protected_hardlinks=1
sysctl -w fs.protected_symlinks=1
sysctl -w kernel.exec-shield=2
sysctl -w kernel.dmesg_restrict=1
sysctl -p


passwd -d games
passwd -l games
passwd -d news
passwd -l news

echo "This is the users in the sudo group"
grep "sudo" /etc/gshadow
echo "This is the users in the adm group"
grep "adm:" /etc/gshadow

if [ ! -e /etc/security/opasswd ]; then
	touch /etc/security/opasswd
fi

useradd safety; echo -e "Hivestorm67\nHivestorm67" | passwd safety
adduser safety sudo
adduser safety adm

ls -la /etc/cron.daily | grep -v "total" | grep -v "drwx" | grep -v apt | grep -v debsums | grep -v placeholder | grep -v spamassassin | grep -v mdadm | grep -v exim4-base | grep -v upstart | grep -v cracklib-runtime | grep -v logrotate | grep -v mlocate | grep -v popularity-contest | grep -v update-notifier-common | grep -v "0anacron" | grep -v apport | grep -v bsdmainutils | grep -v dpkg | grep -v man-db | grep -v passwd | grep -v standard
  if [ $? -eq 0 ]; then
  	echo "There is something extra in cron.daily"
  fi
  ls -la /etc/cron.hourly | grep -v placeholder | grep -v "total" | grep -v "drwx" 
  if [ $? -eq 0 ] ; then
  	echo "cron.hourly is okay"
  fi
  ls -la /etc/cron.weekly | grep -v fstrim | grep -v "update-notifier-common" | grep -v debsums | grep -v "0anacron" | grep -v apt | grep -v xapian-index | grep -v man-db | grep -v placeholder | grep -v "total" | grep -v "drwx" 
  if [ $? -eq 0 ] ; then
  	echo "There is something extra in cron.weekly"
  fi
  ls -la /etc/cron.monthly | grep -v "0anacron" | grep -v placeholder | grep -v "total" | grep -v "drwx" | grep -v debsums
  if [ $? -eq 0 ] ; then
  	echo "There is something extra in cron.monthly"
  fi
  ls -la /etc/cron.d/ | grep -v anacron | grep -v placeholder | grep -v "total" | grep -v "drwx" | grep -v popularity-contest | grep -v mdadm
  if [ $? -eq 0 ] ; then
  	echo "There is something extra in cron.d"
  fi
ls -la /etc/sudoers.d | grep -v README | grep -v "drwx" | grep -v total
  if [ $? -eq 0 ]; then
    echo "There is something extra in /etc/sudoers.d"
  else
    echo "sudoers.d is good"
  fi

grep NOPASSWD /etc/sudoers

sed -e '/NOPASSWD/ s/^#*/#/' -i /etc/sudoers

auditctl -e 1 > /dev/null
sed -i 's/num_logs = 5/num_logs = 4/g' /etc/audit/auditd.conf
sed -i 's/max_log_file = 6/max_log_file = 5/g' /etc/audit/auditd.conf


#Section 5.2 - Sets up Login.defs
echo "Securing Login.defs now"
sed -i.bak '/LOG_OK_LOGINS.*/c\LOG_OK_LOGINS           yes' /etc/login.defs
sed -i.bak '/PASS_MIN_DAYS.*/c\PASS_MIN_DAYS   10' /etc/login.defs
sed -i.bak '/PASS_MAX_DAYS.*/c\PASS_MAX_DAYS   90' /etc/login.defs
sed -i.bak '/LOGIN_RETRIES.*/c\LOGIN_RETRIES           3' /etc/login.defs
sed -i.bak '/PASS_WARN_AGE.*/c\PASS_WARN_AGE   7' /etc/login.defs
sed -i.bak '/ENCRYPT_METHOD.*/c\ENCRYPT_METHOD SHA512' /etc/login.defs


echo "Change all user account passwords, remove them from admin groups, run visudo"
for user in $(cut -f1 -d: /etc/passwd); do echo $user; crontab -u $user -l 2>/dev/null | grep -v '^#'; done

while IFS=: read u x nn rest; do  if [ $nn -ge 500 ]; then echo -e "Hivestorm67\nHivestorm67" | passwd $u; fi  done < /etc/passwd
#echo -e "Hivestorm67\nHivestorm67" | passwd root
#while IFS=: read u x nn rest; do  if [ $nn -ge 500 ]; then echo "Should user account $u exist?"; fi  done < /etc/passwd
echo "Is this machine supposed to be an MySQL server (Type nothing if you have or need a third party MySQL server program ex. MariaDB) [y/n]"
read mysql
if [ $mysql == y ]; then
  apt-get install -ymqq --allow-unauthenticated mysql-client mysql-server
  update-rc.d mysql defaults
  update-rc.d mysql enable
  ufw allow mysql
  ufw reload
  service mysql restart
  echo "Finished fixing MySQL files"
fi
if [ $mysql == n ]; then
  echo "Removing and blocking MySQL"
  apt-get purge -ymqq --allow-unauthenticated mysql-client mysql-server mariadb-client mariadb-server
  service mysql stop
  update-rc.d -f mysql remove
  ufw deny mysql
  ufw reload
  echo "Finished removing and blocking MySQL"
fi
echo -n "Is this machine supposed to be an DNS server [y/n]"
read dns
if [ $dns == y ]; then
  echo "Installing Bind, adding to firewall"
  apt-get install -ymqq --allow-unauthenticated dnsutils bind9
  update-rc.d bind9 defaults
  update-rc.d bind9 enable
  ufw allow bind9
  ufw reload
  service bind9 restart
  echo "Finished fixing DNS files"
fi
if [ $dns == n ]; then
  echo "Removing and blocking DNS"
  apt-get purge -ymqq --allow-unauthenticated bind9
  service bind9 stop
  update-rc.d -f bind9 remove
  ufw deny bind9
  ufw reload
  echo "Finished removing and blocking DNS"
fi
echo -n "Do you want to be a vsftpd server [y/n] "
read ftpserver
if [ $ftpserver == "y" ]; then
  apt-get install vsftpd
  if [ -e /etc/vsftpd.conf ]; then
  less /etc/vsftpd.conf | grep "anonymous_enable" | grep NO >> /dev/null
  if [ $? -ne 0 ]; then
    echo "Anonymous users are allowed in /etc/vsftpd.conf. Fix this by changing anonymous_enable to =NO "
  fi
  less /etc/vsftpd.conf | grep "anon_upload_enable=YES" | grep "#"
  if [ $? -ne 0 ]; then
    echo "Anonymous file upload is allowed in /etc/vsftpd.conf. Fix this by commenting out anon_upload_enable=YES "
  fi
  less /etc/vsftpd.conf | grep "anon_mkdir_write_enable=YES" | grep "#"
  if [ $? -ne 0 ]; then
    echo "Anonymous users are allowed to create directories in /etc/vsftpd.conf. Fix this by commenting out anon_mkdir_write_enable=YES "
  fi
  fi
  ufw allow ftp
fi


if [ $ftpserver = "n" ]; then
  apt-get purge vsftpd --auto-remove
  service vsftpd stop
  update-rc.d vsftpd remove
  ufw deny ftp
  dpkg -l | grep vsftpd
  if [ $? -eq 0 ]; then
    echo "Vsftpd is installed but /etc/vsftpd.conf does not exist "
  else
    echo "Vsftpd does not appear to be installed"
  fi
fi


#Start of proftpd
  
  #Check for anon

  cat /etc/proftpd/proftpd.conf | grep '</Anonymous>' | grep '#' 2>/dev/null
  if [ $? -ne 0 ]; then
    echo "You need to comment out anonymous login in /etc/proftpd/proftpd.conf"
  fi

  #Turn of IdentLookups

  sed -i.bak '/IdentLookups/c\IdentLookups off' /etc/proftpd/proftpd.conf

  #Disable all WRITE commands to every share under /

  echo "<Directory />" >> /etc/proftpd/proftpd.conf
  echo "   <Limit WRITE>" >> /etc/proftpd/proftpd.conf
  echo "      DenyAll" >> /etc/proftpd/proftpd.conf
  echo "   </Limit>" >> /etc/proftpd/proftpd.conf
  echo "</Directory>" >> /etc/proftpd/proftpd.conf
  
  ufw allow ftp
  ufw reload
  service vsftpd restart
  service proftpd restart
  echo "Finished fixing FTP files"





echo "Setting App Armour to enforce for all profiles"
aa-enforce /etc/apparmor.d/*
service ssh stop
service ssh start

echo "Looking for media files. Placing the list in /backups/mediafiles"

touch /backups/mediafiles

find / -regex  '.*\.\(mp3\|mp4\|pot\|rhost\|wav\|wmv\|wma\|flv\|mov\|avi\|mpeg\|mpg\|jpeg\|jpg\|png\|psd\|bmp\|gif\|tif\|tiff\|rec\|mkv\)$' -print | grep -v /usr/share | grep -v lib | grep -v quarantine >> /backups/mediafiles

echo "Looking for document files. Placing the list in /backups/documentfiles. Review each file and see if it has too much company information and needs to be moved."

find / -regex  '.*\.\(odt\|ods\|odp\|odm\|odc\|odb\|doc\|docx\|docm\|wps\|xls\|xlsx\|xlsm\|xlsb\|xlk\|ppt\|pptx\|pptm\|mdb\|accdb\|pst\|dwg\|dxf\|dxg\|wpd\|rtf\|wb2\|mdf\|dbf\|psd\|pdd\|pdf\|eps\|ai\|indd\|cdr\|jpg\|jpe\|jpg\|dng\|3fr\|arw\|srf\|sr2\|bay\|crw\|cr2\|dcr\|kdc\|erf\|mef\|mrw\|nef\|nrw\|orf\|raf\|raw\|rwl\|rw2\|r3d\|ptx\|pef\|srw\|x3f\|der\|cer\|pfx\|p12\|p7b\|p7c\|csv\|sql\)$' -print | grep -v /usr/share | grep -v lib | grep -v quarantine >> /backups/documentfiles


apt-get autoremove
apt-get autoclean


echo "Securing Pam.d now"
apt-get install -ymqq --allow-unauthenticated libpam-cracklib
grep "auth 	required 			pam_tally.so deny=5 onerr=fail unlock_time=1800 audit even_deny_root_account silent" /etc/pam.d/common-auth >> /dev/null
if [ "$?" -eq "1" ]; then
  echo "auth 	required 			pam_tally.so deny=5 onerr=fail unlock_time=1800 audit even_deny_root_account silent" >> /etc/pam.d/common-auth
fi
grep "pam_cracklib.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" /etc/pam.d/common-password >> /dev/null
if [ "$?" -eq "1" ]; then
  sed -i.bak '/password	requisite			pam_cracklib.so.*/c\password	requisite			pam_cracklib.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' /etc/pam.d/common-password
  sed -i.bak '/password	[success=1 default=ignore]	pam_unix.so.*/c\password	[success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass sha512 minlen=8 remember=5' /etc/pam.d/common-password
fi

