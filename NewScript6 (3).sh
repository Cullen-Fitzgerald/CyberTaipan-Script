#!/bin/bash
UserName=$(whoami)
LogTime=$(date '+%Y-%d %H:%M;%S')

getent passwd | awk -F: '$3 >= 1000 {print $1}' > users
getent group | cut -d: -f1 > groups

##Adds a pause statement
pause(){
	read -p "Press [Enter] key to continue..."
}

##Exits the script
exit20(){
        clear
	exit 1
}

##Detect the Operating System
apt install gcc
gcc || apt-get install gcc >> /dev/null
gcc || yum install gcc >> /dev/null
gcc --version | grep -i ubuntu
if [ $? -eq 0 ]; then
	opsys="Ubuntu"
fi
gcc --version | grep -i debian >> /dev/null
if [ $? -eq 0 ]; then
	opsys="Debian"
fi

gcc --version | grep -i RedHat >> /dev/null
if [ $? -eq 0 ]; then
	opsys="RedHat"
fi

gcc --version | grep -i #CentOS >> /dev/null
if [ $? -eq 0 ]; then
	opsys="CentOS"
fi

update(){
	case "$opsys" in
	"Debian"|"Ubuntu")
		sudo add-apt-repository -y ppa:libreoffice/ppa
		wait
		sudo apt-get update -y
		wait
		sudo apt-get upgrade -y
		wait
		sudo apt-get dist-upgrade -y
		wait
		killall firefox
		wait
		sudo apt upgrade firefox
		wait
		apt install clamtk -y	
		apt install clamav
		echo "Now performing a clamscan."
		wait
		clamscan
		pause
	;;
	esac
}

disCronJobs(){
	crontab -l > user_cron
	crontab -r
	sudo systemctl stop cron
	sudo systemctl disable cron
	echo "Disabled all cronjobs"

	LOG_FILE="$HOME/rkhunter.log"
	apt-get install rkhunter
	echo "Updating rkhunter database..."
	sudo rkhunter --update > "$LOG_FILE" 2>&1
	echo "Scanning for rootkits..."
	sudo rkhunter --checkall --skip-keypress >> "$LOG_FILE" 2>&1
	echo "Scan completed. Results are logged in $LOG_FILE"
	cat "$LOG_FILE"
	pause
}

secureCron(){
	cron_jobs=$(sudo crontab -l)
	ufw_disable_pattern="ufw disable"
	if [[ $cron_jobs =~ $ufw_disable_pattern ]]; then
		echo "Cron job to disable UFW found. Removing..."
		updated_cron_jobs=$(echo "$cron_jobs" | sed "s/$ufw_disable_pattern//g")
		echo "$updated_cron_jobs" | sudo crontab -
		echo "Cron job to disable UFW removed successfully."
	else
		echo "No cron job found that disables UFW."
	fi

	chmod 600 /etc/crontab
	chmod 600 /etc/cron.d
	chmod 600 /var/spool/cron/crontabs
	chmod 600 /etc/at.allow
	chmod 600 /etc/at.deny
	echo "cron.* /var/log/cron.log" >> /etc/rsyslog.d/50-default.conf
	echo "at.* /var/log/at.log" >> /etc/rsyslog.d/50-default.conf
	service rsyslog restart
	chown root:root /etc/crontab
	chown root:root /etc/cron.d
	chown root:root /var/spool/cron/crontabs
	chown root:root /etc/at.allow
	chown root:root /etc/at.deny
	touch /etc/cron.allow
	touch /etc/cron.deny
	touch /etc/at.allow
	touch /etc/at.deny
	service cron restart
	service atd restart
	echo "Cron and At secured successfully."
	pause
}

backup() {
	mkdir /BackUps
	##Backups the sudoers file
	sudo cp /etc/sudoers /Backups
	##Backups the home directory
	cp /etc/passwd /BackUps
	##Backups the log files
	cp -r /var/log /BackUps
	##Backups the passwd file
	cp /etc/passwd /BackUps
	##Backups the group file
	cp /etc/group /BackUps
	##Back ups the shadow file
	cp /etc/shadow /BackUps
	##Backing up the /var/spool/mail
	cp /var/spool/mail /Backups
	##backups all the home directories
	for x in $(ls /home)
	do
		cp -r /home/"$x" /BackUps
	done

	pause
}

autoUpdate() {
    echo "Setting auto updates."
	case "$opsys" in
	"Debian"|"Ubuntu")

	##Set daily updates
        echo "Setting Daily Updates..."
		sed -i -e 's/APT::Periodic::Update-Package-Lists.*\+/APT::Periodic::Update-Package-Lists "1";/' /etc/apt/apt.conf.d/10periodic
		sed -i -e 's/APT::Periodic::Download-Upgradeable-Packages.*\+/APT::Periodic::Download-Upgradeable-Packages "0";/' /etc/apt/apt.conf.d/10periodic
		sed -i -e 's/APT::Periodic::Unattended-Upgrade.*\+/APT::Periodic::Unattended-Upgrade "true";/' /etc/apt/apt.conf.d/20auto-upgrades
        # Define the configuration file path
		sudo bash -c 'echo "Unattended-Upgrade::Allowed-Origins {" >> /etc/apt/apt.conf.d/20auto-upgrades'
		sudo bash -c 'echo "    \"o=Ubuntu,a=stable-security\";" >> /etc/apt/apt.conf.d/20auto-upgrades'
		sudo bash -c 'echo "    \"o=Ubuntu,a=stable-updates\";" >> /etc/apt/apt.conf.d/20auto-upgrades'
		sudo bash -c 'echo "};" >> /etc/apt/apt.conf.d/20auto-upgrades'

	# Restart the Unattended-Upgrades service
		sudo apt-get install unattended-upgrades -y
		sudo systemctl restart unattended-upgrades
		echo "Daily Updates Set."
	##Set "install security updates"
        echo "Installing Security Updates..."
		cat /etc/apt/sources.list | grep "deb http://security.ubuntu.com/ubuntu/ trusty-security universe main multiverse restricted" >> /etc/apt/sources.list
		if [ $? -eq 1 ]
		then
			echo "deb http://security.ubuntu.com/ubuntu/ trusty-security universe main multiverse restricted" >> /etc/apt/sources.list
		fi
		pause
	esac
}

pFiles() {
    echo "Finding media files..."
	##Media files
	echo "###MEDIA FILES###" >> pFiles.log
    find / -name "*.mov" -type f >> pFiles.log
    find / -name "*.mp4" -type f >> pFiles.log
	find / -name "*.mp3" -type f >> pFiles.log
	find / -name "*.wav" -type f >> pFiles.log
	##Pictures
	echo "Finding picture files..."
	echo "###PICTURES###" >> pFiles.log
 #	find / -name "*.png" -type f >> pFiles.log
    find / -name "*.jpg" -type f >> pFiles.log
	find / -name "*.jpeg" -type f >> pFiles.log
 #	find / -name "*.gif" -type f >> pFiles.log
	##Other Files
	echo "Finding other files..."
	echo "###OTHER###" >> pFiles.log
	find / -name "*.tar.gz" -type f >> pFiles.log
	find / -name "*.php" -type f >> pFiles.log
	find / -name "*backdoor*.*" -type f >> pFiles.log
	find / -name "*backdoor*.php" -type f >> pFiles.log
	##Items without groups
	echo "Finding uncatergorised files..."
	echo "###FILES WITHOUT GROUPS###" >> pFiles.log
	find / -nogroup >> pFiles.log
	echo "Finding games..."
	echo "###GAMES###" >> pFiles.log
	dpkg -l | grep -i game
	cat pFiles.log
	echo "This shows all of the potentially prohibited files on the PC"
	pause
}

configureFirewall() {
    echo "Checking for firewall..." 
	case "$opsys" in
	"Ubuntu"|"Debian")
		dpkg -l | grep ufw >> output.log
		if [ $? -eq 1 ]
		then
			apt-get install ufw 
		fi
        echo "Enabling firewall..." 
		sudo ufw enable 
		sudo sed -i 's/^LOGLEVEL=.*/LOGLEVEL=high/' /etc/ufw/ufw.conf
		ufw logging high
		ufw status verbose
		echo "UFW logging level set to high."
		sleep 1
		ufw default allow outgoing
		ufw default deny incoming
		ufw deny 23
		ufw status
		echo "Firewall has been turned on and configured." 
		pause
	;;
	esac
}

loginConf() {	
	file_paths=("/usr/share/lightdm/lightdm.conf.d/50-disable-guest.conf" "/etc/lightdm/lightdm.conf")
	for file in "${file_paths[@]}"; do
		if [ -e "$file" ]; then
			if grep -q "allow-guest=true" "$file"; then
				sudo sed -i 's/allow-guest=true/allow-guest=false/' "$file"
				echo "The 'allow-guest' setting in '$file' has been changed to 'false'."
			elif grep -q "allow-guest=false" "$file"; then
				echo "Guests are not allowed in '$file'."
			else
				echo "allow-guest=false" | sudo tee -a "$file" > /dev/null
				echo "The 'allow-guest' setting has been added and set to 'false' in '$file'."
			fi

			if grep -q "autologin-user=" "$file"; then
				sudo sed -i '/autologin-user=/d' "$file"
				echo "The 'autologin-user' setting has been removed from '$file'."
			fi

			# Add or change greeter0hide-users=true and greeter-show-manual-login=true lines
			if grep -q "greeter-hide-users=" "$file"; then
				sudo sed -i 's/greeter-hide-users=.*/greeter-hide-users=true/' "$file"
				echo "The 'greeter-hide-users' setting in '$file' has been changed to 'true'."
			else
				echo "greeter-hide-users=true" | sudo tee -a "$file" > /dev/null
				echo "The 'greeter-hide-users' setting has been added and set to 'true' in '$file'."
			fi

			if grep -q "greeter-show-manual-login=" "$file"; then
				sudo sed -i 's/greeter-show-manual-login=.*/greeter-show-manual-login=true/' "$file"
				echo "The 'greeter-show-manual-login' setting in '$file' has been changed to 'true'."
			else
				echo "greeter-show-manual-login=true" | sudo tee -a "$file" > /dev/null
				echo "The 'greeter-show-manual-login' setting has been added and set to 'true' in '$file'."
			fi

		else
			echo "The file '$file' does not exist."
		fi
	done

	echo "LightDM configuration has been secured."
	pause
}

gdmConf() {
	echo "Configuring GDM settings..."
	if grep -q "AutomaticLoginEnable=true" /etc/gdm3/custom.conf; 
	then
		sed -i 's/AutomaticLoginEnable=true/AutomaticLoginEnable=false/' /etc/gdm3/custom.conf
		sed -i '/AutomaticLogin=/d' /etc/gdm3/custom.conf
		echo "Automatic login disabled."
	fi
	echo "user-list=false" >> /etc/gdm3/greeter.dconf-defaults
	echo "disable-user-list=true" >> /etc/gdm3/greeter.dconf-defaults
	echo "User list on the login screen hidden."
	echo "allow-guest=false" >> /etc/gdm3/greeter.dconf-defaults
	echo "Guest session disabled."
	sleep 6s
	systemctl restart gdm
	echo "GDM settings have been configured."
	pause
}

gdmInstall() {
	if dpkg -l | grep -q gdm3; then
    	echo "GDM is already installed."
	else
		# Install GDM3
		echo "Installing GDM3..."
		apt-get update
		apt-get install gdm3 -y
		echo "GDM3 has been installed."
	fi
	pause
}

lightdmInstall() {
	if dpkg -l | grep -q lightdm; then
		echo "LightDM is already installed."
	else
		# Install LightDM
		echo "Installing LightDM..."
		apt-get install lightdm -y
		apt-get install lightdm lightdm-gtk-greeter lightdm-gtk-greeter-settings
		echo "LightDM has been installed."
	fi
	pause
}

defDM() {
	if dpkg -l | grep -q lightdm; then
		echo "LightDM is installed."
		# Reconfigure LightDM
		sudo dpkg-reconfigure lightdm
	else
		echo "LightDM is not installed. Reconfiguring GDM3."
		# Reconfigure GDM3
		sudo dpkg-reconfigure gdm3
	fi
	pause
}

createUser() {
	read -p "Are there any users you would like to add?[y/n]: " a
	while [ "$a" = y ]
	do
		read -p "Please enter the name of the user: " user
		useradd "$user"
		mkdir /home/"$user"
		read -p "Are there any more users you would like to add?[y/n]: " a
        echo "Now, please stop running this script and start it back up to enable changes - Cullen."
	done
    
	pause
}

createGroup() {
	read -p "Do you want to create a new group?[y/n]: " create_group_choice
	if [ "$create_group_choice" = "y" ]; 
	then
		read -p "Please enter the name of the new group: " group_name
   		groupadd "$group_name"
   		echo "Group '$group_name' created."
	fi
	for user in $(getent passwd | cut -d: -f1); do
    if [ -d "/home/$user" ]; then
        read -p "Do you want to add user '$user' to the new group? [y/n]: " add_to_group_choice
        if [ "$add_to_group_choice" = "y" ]; then
            usermod -aG "$group_name" "$user"
            echo "User '$user' added to group '$group_name'."
        fi
    fi
	done
	pause
}

chgPasswd(){
	while IFS=: read -r username _ uid _; do
		if [ "$uid" -ge 1000 ]; then
			echo "Changing password for user: $username (UID: $uid)"
			echo "$username:L/7d=YmsKn+E]hGx" | chpasswd
			if [ $? -eq 0 ]; then
				echo "Password changed successfully."
			else
				echo "Failed to change password for $username."
			fi
		fi
	done < /etc/passwd
	pause
}

passPol() {
	user_list=$(cut -d: -f1,3 /etc/passwd | awk -F: '$2 >= 1000 {print $1}')
	for username in $user_list; do
		sudo passwd -x 90 "$username"
		sudo passwd -n 10 "$username"
		sudo passwd -w 14 "$username"
		echo "Password expiration settings updated for user: $username"
	done
	echo "Password expiration settings have been updated for all users."

	sed -i 's/\(minlen=\).*/\18/' /etc/pam.d/common-password
	sed -i 's/\(dcredit=\).*/\11/' /etc/pam.d/common-password
	sed -i 's/\(ucredit=\).*/\11/' /etc/pam.d/common-password
	sed -i 's/\(lcredit=\).*/\11/' /etc/pam.d/common-password
	sed -i 's/\(ocredit=\).*/\11/' /etc/pam.d/common-password
	echo "Password policy values have been set in /etc/pam.d/common-password file."

	sed -i.bak -e 's/PASS_MAX_DAYS\t[[:digit:]]\+/PASS_MAX_DAYS\t90/' /etc/login.defs
	sed -i -e 's/PASS_MIN_DAYS\t[[:digit:]]\+/PASS_MIN_DAYS\t10/' /etc/login.defs
	sed -i -e 's/PASS_WARN_AGE\t[[:digit:]]\+/PASS_WARN_AGE\t14/' /etc/login.defs
	echo "System wide password expiration dates have also been changed."

	pwquality_config="/etc/security/pwquality.conf"
	pwquality_line="minlen = 8\nminclass = 3\nmaxrepeat = 3\nminspecial = 1\nmindigits = 1"
	if [ -f "$pwquality_config" ]; then
		echo "Modifying existing pwquality.conf..."
		echo -e "$pwquality_line" > "$pwquality_config"
	else
		echo "Creating new pwquality.conf..."
		touch "$pwquality_config"
		echo -e "$pwquality_line" > "$pwquality_config"
	fi
	pam_passwd_config="/etc/security/pwquality.conf"
	pam_passwd_line="password requisite pam_pwquality.so retry=3"

	if grep -q "$pam_passwd_line" "$pam_passwd_config"; then
		echo "pam_pwquality.so line already exists in $pam_passwd_config."
	else
		echo "Adding pam_pwquality.so line to $pam_passwd_config..."
		echo "$pam_passwd_line" >> "$pam_passwd_config"
	fi
	echo "Password policy has been configured."
	echo "You can now test the policy by changing your password using the 'passwd' command."
	echo "Reloading PAM..."
	pam-auth-update 
    echo "Password Policy Set." 
	
	chown root:root /etc/shadow
	chown root:root /etc/passwd
	chown root:root /etc/group
	echo "Ownership of /etc/shadow, /etc/passwd, and /etc/group has been changed to root."

	echo "Setting permissions for /etc/shadow..."
	chmod 640 /etc/shadow
	chattr -i /etc/shadow
	echo "Permissions for /etc/shadow set."
	echo "Setting permissions for /etc/group..."
	chmod 644 /etc/group
	chattr -i /etc/group
	echo "Permissions for /etc/group set."
	echo "Setting permissions for /etc/passwd..."
	chmod 644 /etc/passwd
	chattr -i /etc/passwd
	echo "Permissions for /etc/passwd set."
	echo "Password files secured successfully."
	pause
}

fileEdit() {
	read -p "Do you want to edit a file? [y/n]: " choice
	if [ "$choice" = "y" ]; then
		read -p "Enter the file name that you want to edit: " file_name
		echo "Displaying file... (3)"
		sleep 1s
		echo "Displaying file... (2)"
		sleep 1s
		echo "Displaying file... (1)"
		sleep 1s
		nano "$file_name"
	else
		echo "Alrighty then, pal, be like that."
	fi
    pause
}

fixPATH(){
	if [ -f ~/.bashrc ]; then
		cp ~/.bashrc ~/.bashrc.bak
		new_path=$(echo $PATH | awk -F: '!($0 in a) {a[$0]; print}')
		echo "export PATH=$new_path:/usr/local/bin:/usr/bin:/bin" > ~/.bashrc
		source ~/.bashrc
		echo "PATH variable has been fixed. Original .bashrc file backed up as .bashrc.bak."
	else
		echo "Error: .bashrc file not found in the home directory."
	fi
	pause
}

userInfo() {
	for user in $(cut -d: -f1 /etc/passwd); do
		uid=$(id -u "$user")
		if [ "$uid" -ge 1000 ] || [ "$uid" -eq 0 ]; then
			echo "User: $user"
			echo "UID: $uid"
			groups=$(id -Gn "$user" | tr ' ' ', ')
			echo "Groups: $groups"
			last_login=$(last "$user" | grep -v 'still logged in' | head -n 1)
			echo "Last Login: $last_login"
			echo "-------------------"
		fi
	done
	pause
}

filePerms() {
	apt install auditd
	read -p "Enter the path to the file: " file_path
	if [ -e "$file_path" ]; then
		file_owner=$(stat -c "%U" "$file_path")
		file_group=$(stat -c "%G" "$file_path")
		echo "File owner: $file_owner"
		echo "File group: $file_group"
		file_permissions=$(stat -c "%A" "$file_path")
		echo "File permissions: $file_permissions"
		echo "File access history:"
		ausearch -f "$file_path"
	else
		echo "File not found."
	fi
	pause
}

secDirectories() {
	sudo apt-get install cryptsetup
	sudo apt-get install ecryptfs-utils
	permissions="u+rwx,g+rwx,o-rwx"
	user_directories=(/home/*)
	for user_dir in "${user_directories[@]}"; do
		if [ -d "$user_dir" ]; then
			find "$user_dir" -type d -exec chmod "$permissions" {} \;
			echo "Directory permissions have been updated for user: $(basename "$user_dir")"
			chmod 700 "$user_dir"
		fi
	done
	
	directories=$(ls -d */)
	for dir in $directories; do
		if [[ $dir == .* ]]; then
			echo "Hidden directory found: $dir"
		fi
	done

	apt-get install acl
	user_directories=$(find /home -maxdepth 1 -type d)
	for user_dir in $user_directories; do
		if [ "$user_dir" != "/home" ]; then
			setfacl -R -m u::rwx,g::r-x,o::--- "$user_dir"
			setfacl -d -m u::rwx,g::r-x,o::--- "$user_dir"
			acl_output=$(getfacl -R "$user_dir")
			echo "ACLs have been set for $user_dir:"
			echo "$acl_output"
		fi
	done
	echo "Directories secured successfully."
	pause
}

delUser() {
	for user in $(getent passwd | awk -F: '$3 >= 1000 { print $1 }'); do
		read -p "Do you want to delete user '$user'? (y/n): " choice
		if [ "$choice" == "y" ]; then
			sudo deluser --remove-home "$user"
			echo "User '$user' has been deleted."
		elif [ "$choice" == "n" ]; then
			echo "User '$user' will not be deleted."
		else
			echo "Invalid choice. User '$user' will not be deleted."
		fi
	done
}

delGroup() {
	exclude_groups=('root' 'daemon' 'games' 'bin' 'sys' 'adm' 'tty' 'disk' 'lp' 'mail' 'news' 'uucp' 'man' 'proxy' 'kmem' 'dialout' 'fax' 'voice' 'cdrom' 'floppy' 'tape' 'sudo' 'audio' 'dip' 'www-data' 'backup' 'operator' 'list' 'irc' 'src' 'gnats' 'shadow' 'utmp' 'video' 'sasl' 'plugdev' 'staff' 'users' 'nogroup' 'systemd-journal' 'systemd-network' 'systemd-resolve' 'crontab' 'messagebus' 'systemd-timesync' 'input' 'sgx' 'kvm' 'render' 'syslog' '_ssh' 'tss' 'bluetooth' 'ssl-cert' 'uuidd' 'systemd-oom' 'tcpdump' 'avahi-autoipd' 'netdev' 'avahi' 'lpadmin' 'rtkit' 'whoopsie' 'sssd' 'fwupd-refresh' 'nm-openvpn' 'scanner' 'saned' 'colord' 'geoclue' 'pulse' 'pulse-access' 'gdm' 'lxd' 'postfix' 'postdrop' 'clamav' 'ftp' 'cdrom' 'sudo' 'dip' 'plugdev' 'lpadmin' 'sambashare')
	for group in $(cut -d: -f1 /etc/group); do
		if [[ ! " ${exclude_groups[@]} " =~ " $group " ]]; then
			read -p "Do you want to delete the group '$group'? [y/n]: " delete_group_choice
			if [ "$delete_group_choice" = "y" ]; then
				groupdel "$group"
				echo "Group '$group' deleted."
			fi
		fi
	done
	pause
}

groupMembers() {
	exclude_groups=('root' 'daemon' 'games' 'bin' 'sys' 'adm' 'tty' 'disk' 'lp' 'mail' 'news' 'uucp' 'man' 'proxy' 'kmem' 'dialout' 'fax' 'voice' 'cdrom' 'floppy' 'tape' 'sudo' 'audio' 'dip' 'www-data' 'backup' 'operator' 'list' 'irc' 'src' 'gnats' 'shadow' 'utmp' 'video' 'sasl' 'plugdev' 'staff' 'users' 'nogroup' 'systemd-journal' 'systemd-network' 'systemd-resolve' 'crontab' 'messagebus' 'systemd-timesync' 'input' 'sgx' 'kvm' 'render' 'syslog' '_ssh' 'tss' 'bluetooth' 'ssl-cert' 'uuidd' 'systemd-oom' 'tcpdump' 'avahi-autoipd' 'netdev' 'avahi' 'lpadmin' 'rtkit' 'whoopsie' 'sssd' 'fwupd-refresh' 'nm-openvpn' 'scanner' 'saned' 'colord' 'geoclue' 'pulse' 'pulse-access' 'gdm' 'lxd' 'postfix' 'postdrop' 'clamav' 'ftp' 'cdrom' 'sudo' 'dip' 'plugdev' 'lpadmin' 'sambashare')
    all_groups=($(getent group | cut -d: -f1))  # Get all groups on the system
    for group in "${all_groups[@]}"; do
        # Check if the current group is in the exclusion list
        if [[ ! " ${exclude_groups[@]} " =~ " $group " ]]; then
            read -p "Edit members of group '$group'? (y/n): " edit_group
            if [ "$edit_group" == "y" ]; then
                for user in $(getent passwd | awk -F: '$3 >= 1000 {print $1}'); do
                    read -p "Add $user to group $group? (y/n): " add_to_group
                    if [ "$add_to_group" == "y" ]; then
                        usermod -aG "$group" "$user"
                        echo "Added $user to group $group"
                    elif [ "$add_to_group" == "n" ]; then
                        gpasswd -d "$user" "$group"
                        echo "Removed $user from group $group"
                    else
                        echo "Invalid input. Skipping $user for group $group."
                    fi
                done
            elif [ "$edit_group" == "n" ]; then
                echo "No changes made to group $group members."
            else
                echo "Invalid input. Skipping group $group."
            fi
        else
            echo "Skipping group $group."
        fi
    done
}

admin() {
    getent passwd | awk -F: '$3 >= 1000 {print $1}' > users
	for x in $(cat users)
	do
		read -p "Is $x considered an admin?[y/n]: " a
		if [ "$a" = y ]
		then
			##Adds to the adm group
			sudo usermod -a -G adm "$x"

			##Adds to the sudo group
			sudo usermod -a -G sudo "$x"
		else
			##Removes from the adm group
			sudo deluser "$x" adm

			##Removes from the sudo group
			sudo deluser "$x" sudo
		fi
	done

	pause
}

secRoot() {
	echo "Securing root by changing the password..."
	new_root_password="L/7d=YmsKn+E]hGx"
	echo "root:$new_root_password" | chpasswd
	echo "Root password changed successfully."	

	ssh_config_file=("/etc/ssh/sshd_config" "/etc/sshd/sshd_config")
	if [ ! -f "$ssh_config_file" ]; then
		echo "SSH configuration file $ssh_config_file not found."
	fi
	if grep -q "^PermitRootLogin" "$ssh_config_file"; then
		if grep -q "^PermitRootLogin yes" "$ssh_config_file"; then
			sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' "$ssh_config_file"
			echo "PermitRootLogin was set to 'no' in $ssh_config_file. SSH service restarted."
			sleep 3s
			service ssh restart
		elif grep -q "^PermitRootLogin no" "$ssh_config_file"; then
			echo "PermitRootLogin is already set to 'no' in $ssh_config_file."
		fi
	else
		echo "PermitRootLogin no" >> "$ssh_config_file"
		echo "PermitRootLogin added and set to 'no' in $ssh_config_file. SSH service restarted."
		sleep 3s
		service ssh restart
	fi
	passwd -l root
	pause
}

lockoutPol() {
	if ! command -v fail2ban-client &>/dev/null; then
		echo "Installing fail2ban..."
		
		# Install fail2ban
		if [[ $(command -v apt-get) ]]; then
			sudo apt-get update
			sudo apt-get install -y fail2ban
		elif [[ $(command -v yum) ]]; then
			sudo yum install -y epel-release
			sudo yum install -y fail2ban
		else
			echo "Unsupported package manager. Please install fail2ban manually."
			exit 1
		fi
	fi

	user_list=$(awk -F: '$3 >= 1000 { print $1 }' /etc/passwd)
	echo "[DEFAULT]" | sudo tee /etc/fail2ban/jail.local > /dev/null
	echo "ignoreip = 127.0.0.1/8 ::1" | sudo tee -a /etc/fail2ban/jail.local > /dev/null
	echo "" | sudo tee -a /etc/fail2ban/jail.local > /dev/null
	echo "[sshd]" | sudo tee -a /etc/fail2ban/jail.local > /dev/null
	echo "enabled = true" | sudo tee -a /etc/fail2ban/jail.local > /dev/null
	echo "maxretry = 3" | sudo tee -a /etc/fail2ban/jail.local > /dev/null
	echo "findtime = 600" | sudo tee -a /etc/fail2ban/jail.local > /dev/null
	echo "bantime = 600" | sudo tee -a /etc/fail2ban/jail.local > /dev/null
	sudo service fail2ban restart
	echo "Fail2ban configured to secure SSH for users with UID 1000 or higher."


	pause
}

hiddenFiles(){
	echo "Hidden User Directories on the System:"
	for user_dir in /home/*/
	do
		hidden_dirs=$(find "$user_dir" -maxdepth 1 -type d -name ".*")
		for dir in $hidden_dirs
		do
			echo $dir
		done
	done
	pause
}

sshd() {
	getent passwd | awk -F: '$3 >= 1000 {print $1}' > users
    echo "Checking for ssh..." 
	dpkg -l | grep openssh-server >> output.log
        	if [ $? -eq 0 ];
        	then
					read -p "Enter the SSH port (press Enter to keep default): " ssh_port
					sed -i 's/#LoginGraceTime .*/LoginGraceTime 60/g' /etc/ssh/sshd_config
					sed -i 's/#PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config
					sed -i 's/#Protocol .*/Protocol 2/g' /etc/ssh/sshd_config
					sed -i 's/#PermitEmptyPasswords .*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
					sed -i 's/#PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
					sed -i 's/#X11Forwarding .*/X11Forwarding no/g' /etc/ssh/sshd_config
					if [ -n "$ssh_port" ]; then
						if grep -q "^\s*Port\s$ssh_port" /etc/ssh/sshd_config; then
							echo "Port $ssh_port is already configured in sshd_config."
						else
							sed -i '/^#Port/s/^#//g' /etc/ssh/sshd_config
							sed -i "s/^Port .*/Port $ssh_port/g" /etc/ssh/sshd_config
							echo "SSH port changed to $ssh_port."
						fi
					fi
					sed -i '/^AllowUsers/d' /etc/ssh/sshd_config
					sed -i '$a AllowUsers' /etc/ssh/sshd_config
					for username in $(awk -F: '$3 >= 1000 { print $1 }' /etc/passwd); do
						read -p "Allow user $username SSH access? (y/n): " allow_ssh
						if [ "$allow_ssh" = "y" ]; then
							sed -i "/^AllowUsers/ s/$/ $username /" /etc/ssh/sshd_config
							echo "User $username allowed SSH access."
						fi
					done
					echo "SSH configuration has been secured."
					pause
        	else
                read -p "Does SSH NEED to be installed?[y/n]: " a
                if [ "$a" = y ];
                then
                    echo "Installing and securing SSH now..." 
                    apt-get install -y openssh-server ssh >> output.log
					wait
					read -p "Enter the SSH port (press Enter to keep default): " ssh_port
					sed -i 's/#LoginGraceTime .*/LoginGraceTime 60/g' /etc/ssh/sshd_config
					sed -i 's/#PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config
					sed -i 's/#Protocol .*/Protocol 2/g' /etc/ssh/sshd_config
					sed -i 's/#PermitEmptyPasswords .*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
					sed -i 's/#PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
					sed -i 's/#X11Forwarding .*/X11Forwarding no/g' /etc/ssh/sshd_config
					if [ -n "$ssh_port" ]; then
						if grep -q "^\s*Port\s$ssh_port" /etc/ssh/sshd_config; then
							echo "Port $ssh_port is already configured in sshd_config."
						else
							sed -i '/^#Port/s/^#//g' /etc/ssh/sshd_config
							sed -i "s/^Port .*/Port $ssh_port/g" /etc/ssh/sshd_config
							echo "SSH port changed to $ssh_port."
						fi
					fi
					sed -i '/^AllowUsers/d' /etc/ssh/sshd_config
					sed -i '$a AllowUsers' /etc/ssh/sshd_config
					for username in $(awk -F: '$3 >= 1000 { print $1 }' /etc/passwd); do
						read -p "Allow user $username SSH access? (y/n): " allow_ssh
						if [ "$allow_ssh" = "y" ]; then
							sed -i "/^AllowUsers/ s/$/ $username /" /etc/ssh/sshd_config
							echo "User $username allowed SSH access."
						fi
					done
					echo "SSH  has been installed and configuration has been secured."
					pause
				fi
        	fi
}

secureShadow() {
    echo "$LogTime uss: [$UserName]# Securing /etc/shadow..." >> output.log
	chmod 640 /etc/shadow
	ls -l /etc/shadow
	pause
}

hakTools() {
    echo "Removing hacking tools..." 
	dpkg -l | grep apache
	if [ $? -eq 0 ];
	then
        read -p "Do you want apache installed on the system[y/n]: " a
        if [ "$a" = "n" ];
        then
      	    apt-get autoremove -y --purge apache2 
			apt-get remove apache2
		else
            if [ -e /etc/apache2/apache2.conf ]
			then
				chown -R root:root /etc/apache2
				echo \<Directory \> >> /etc/apache2/apache2.conf
				echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
				echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
				echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
				echo UserDir disabled root >> /etc/apache2/apache2.conf
			else
				apt-get install apache2 -y
				chown -R root:root /etc/apache2
				echo \<Directory \> >> /etc/apache2/apache2.conf
				echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
				echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
				echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
				echo UserDir disabled root >> /etc/apache2/apache2.conf
				apt-get install mysql-server -y
				apt-get install php5 -y
				chmod 640 /etc/php5/apache2/php.ini
				fi
        	fi
	else
        echo "Apache is not installed"
		sleep 1
	fi
	dpkg -l | grep john >> output.log
	if [ $? -eq 0 ];
	then
        	echo "JOHN HAS BEEEN FOUND! DIE DIE DIE"
        	apt-get autoremove -y --purge john 
        	echo "John has been ripped"
			sleep 1
	else
        	echo "John The Ripper has not been found on the system"
			sleep 1
	fi
 ##Look for HYDRA
	dpkg -l | grep hydra >>output.log
	if [ $? -eq 0 ];
	then
		echo "HEIL HYDRA"
		apt-get autoremove -y --purge hydra 
	else
		echo "Hydra has not been found."
	fi
 ##Looks for nginx web server
	dpkg -l | grep nginx 
	if [ $? -eq 0 ];
	then
        	echo "NGINX HAS BEEN FOUND! OHHHH NOOOOOO!"
        	apt-get autoremove -y --purge nginx 
	else
        	echo "NGINX has not been found"
			sleep 1
	fi
 ##Looks for samba
	if [ -d /etc/samba ];
	then
		read -p "Samba has been found on this system, do you want to remove it?[y/n]: " a
		if [ "$a" = y ];
		then
        echo "Uninstalling samba..." 
			sudo apt-get autoremove --purge -y samba 
			sudo apt-get remove samba
        echo "Samba has been removed." 
		else
			sudo cp /etc/samba/smb.conf /etc/samba/smb.conf.bak
			sudo sed -i '/\[global\]/a encrypt passwords = yes\nrestrict anonymous = 2\nserver signing = auto\nserver min protocol = SMB2\nserver max protocol = SMB3\nlog file = /var/log/samba/log.%m\nmax log size = 1000\nlogging = file' /etc/samba/smb.conf
			sudo sed -i '$a [homes]\ncomment = Home Directories\nbrowseable = no\nread only = no\ncreate mode = 0750' /etc/samba/smb.conf
			sudo sed -i '$a [shared]\ncomment = Shared Folder\npath = /path/to/your/shared/folder\nbrowseable = yes\nread only = no\ncreate mask = 0755\ndirectory mask = 0755\nvalid users = @sambashare' /etc/samba/smb.conf
			sudo smbpasswd -a username
			sudo service smbd restart
			sudo service nmbd restart

			echo "Samba has been configured securely."
		fi
	else
		echo "Samba has not been found."
		sleep 1
	fi
 ##LOOK FOR DNS
	if [ -d /etc/bind ];
	then
		read -p "DNS server is running would you like to shut it down?[y/n]: " a
		if [ "$a" = y ];
		then
			apt-get autoremove -y --purge bind9 
			apt-get remove bind9
		fi
	else
		echo "DNS not found."
		sleep 1
	fi

	##Looks for FTP
	if dpkg -l | grep -q -i 'vsftpd\|ftp'; then
		echo "FTP Server has been installed."
		read -p "Would you like to remove it? [y/n]: " a
		if [ "$a" = y ]; then
			PID=$(pgrep vsftpd)
			if [ -n "$PID" ]; then
				sed -i 's/^/#/' /etc/vsftpd.conf
				kill "$PID"
			fi
			apt-get autoremove -y --purge vsftpd ftp
			apt-get remove vsftpd ftp
			ufw deny 20
			ufw deny 21
			echo "FTP Server removed."
		else
			sed -i 's/anonymous_enable=.*/anonymous_enable=NO/' /etc/vsftpd.conf
			sed -i 's/local_enable=.*/local_enable=YES/' /etc/vsftpd.conf
			sed -i 's/#write_enable=.*/write_enable=YES/' /etc/vsftpd.conf
			sed -i 's/#chroot_local_user=.*/chroot_local_user=YES/' /etc/vsftpd.conf
			ufw allow 20
			ufw deny 21
			echo "FTP Server configuration updated."
		fi
	else
		echo "FTP has not been found."
		sleep 1
	fi

 ##Looks for TFTPD
	dpkg -l | grep tftpd >> output.log
	if [ $? -eq 0 ]
	then
		read -p "TFTPD has been installed, would you like to remove it?[y/n]: " a
		if [ "$a" = y ]
		then
			apt-get autoremove -y --purge tftpd
		fi
	else
		echo "TFTPD not found."
		sleep 1
	fi
 ##Looking for VNC
	dpkg -l | grep -E 'x11vnc|tightvncserver' >> output.log
	if [ $? -eq 0 ]
	then
		read -p "VNC has been installed, would you like to remove it?[y/n]: " a
		if [ "$a" = y ]
		then
			apt-get autoremove -y --purge x11vnc tightvncserver 
		##else
			##Configure VNC
		fi
	else
		echo "VNC not found."
		sleep 1
	fi

 ##Looking for NFS
	dpkg -l | grep nfs-kernel-server >> output.log
	if [ $? -eq 0 ]
	then	
		read -p "NFS has been found, would you like to remove it?[y/n]: " a
		if [ "$a" = 0 ]
		then
			apt-get autoremove -y --purge nfs-kernel-server
			apt-get remove nfs
		##else
			##Configure NFS
		fi
	else
		echo "NFS has not been found."
		sleep 1
	fi
 ##Looks for snmp
	dpkg -l | grep snmp >> output.log
	if [ $? -eq 0 ]
	then	
		echo "SNMP HAS BEEN LOCATED!"
		apt-get autoremove -y --purge snmp
	else
		echo "SNMP has not been found."
		sleep 1
	fi
 ##Looks for sendmail and postfix
	dpkg -l | grep -E 'postfix|sendmail' >> output.log
	if [ $? -eq 0 ]
	then
		echo "Mail servers have been found."
		apt-get autoremove -y --purge postfix sendmail
	else
		echo "Mail servers have not been located."
		sleep 1
	fi
 ##Looks xinetd
	dpkg -l | grep xinetd >> output.log
	if [ $? -eq 0 ]
	then
		echo "XINIT HAS BEEN FOUND!"
		apt-get autoremove -y --purge xinetd
	else
		echo "XINETD has not been found."
		sleep 1
	fi

	# Remove Telnetd
	dpkg -l | grep telnetd
	if [ $? -eq 0 ];
	then
		read -p "Telnet server found. Do you want to remove it? [y/n]: " a
		if [ "$a" = "y" ];
		then
			apt-get autoremove -y --purge telnetd
			echo "Telnet server has been removed."
		else
			echo "Telnet server has not been removed."
		fi
	else
		echo "Telnet server not found."
	fi

	## Remove crack
	dpkg -l | grep crack
	if [ $? -eq 0 ];
	then
		read -p "Crack found. Do you want to remove it? [y/n]: " a
		if [ "$a" = "y" ];
		then
			apt-get autoremove -y --purge crack
			apt-get remove ophcrack
			echo "Crack has been removed."
		else
			echo "Crack has not been removed."
		fi
	else
		echo "Crack not found."
	fi

	dpkg -l | grep rsh
	if [ $? -eq 0 ];
	then
		read -p "RSH found. Do you want to remove it? [y/n]: " a
		if [ "$a" = "y" ];
		then
			apt-get autoremove -y --purge rsh-server
			apt-get remove rsh-server
			echo "RSH has been removed."
		else
			echo "RSH has not been removed."
		fi
	else
		echo "RSH not found."
	fi

	if dpkg -s "ettercap" >/dev/null 2>&1; then
		echo "Removing ettercap..."
		sudo apt-get purge -y "ettercap"
	else
		echo "ettercap is not installed."
	fi

	# Check and remove deluge
	if dpkg -s "deluge" >/dev/null 2>&1; then
		echo "Removing deluge..."
		sudo apt-get purge -y "deluge"
	else
		echo "deluge is not installed."
	fi

	# Check and remove linuxdcpp
	if dpkg -s "linuxdcpp" >/dev/null 2>&1; then
		echo "Removing linuxdcpp..."
		sudo apt-get purge -y "linuxdcpp"
	else
		echo "linuxdcpp is not installed."
	fi

	# Check and remove rfdump
	if dpkg -s "rfdump" >/dev/null 2>&1; then
		echo "Removing rfdump..."
		sudo apt-get purge -y "rfdump"
	else
		echo "rfdump is not installed."
	fi

	# Check and remove bittorrent
	if dpkg -s "bittorrent" >/dev/null 2>&1; then
		echo "Removing bittorrent..."
		sudo apt-get purge -y "bittorrent"
	else
		echo "bittorrent is not installed."
	fi

	# Check and remove aircrack
	if dpkg -s "aircrack" >/dev/null 2>&1; then
		echo "Removing aircrack..."
		sudo apt-get purge -y "aircrack"
	else
		echo "aircrack is not installed."
	fi

	# Check and remove teamviewer
	if dpkg -s "teamviewer" >/dev/null 2>&1; then
		echo "Removing teamviewer..."
		sudo apt-get purge -y "teamviewer"
	else
		echo "teamviewer is not installed."
	fi

	# Check and remove wireshark
	if dpkg -s "wireshark" >/dev/null 2>&1; then
		echo "Removing wireshark..."
		sudo apt-get purge -y "wireshark"
	else
		echo "wireshark is not installed."
	fi

	# Check and remove xfreerdp
	if dpkg -s "freerdp2-x11" >/dev/null 2>&1; then
		echo "Removing xfreerdp..."
		sudo apt-get purge -y "freerdp2-x11"
	else
		echo "xfreerdp is not installed."
	fi
	pause
}

sys() {
	##Disables IPv6
    echo "Disabling IPv6"
	sed -i '$a net.ipv6.conf.all.disable_ipv6 = 1' /etc/sysctl.conf 
	sed -i '$a net.ipv6.conf.default.disable_ipv6 = 1' /etc/sysctl.conf
	sed -i '$a net.ipv6.conf.lo.disable_ipv6 = 1' /etc/sysctl.conf 
    echo "IPv6 has been disabled."

	##Disables IP Spoofing
    echo "Disabling IP Spoofing"
	sed -i '$a net.ipv4.conf.all.rp_filter=1' /etc/sysctl.conf
    echo "IP Spoofing has been disabled."

	##Disables IP source routing
    echo "Disabling IP source routing"
	sed -i '$a net.ipv4.conf.all.accept_source_route=0' /etc/sysctl.conf
    echo "IP source routing has been disabled"

	##SYN Flood Protection
    echo "Enabling SYN Flood Protection"
	sed -i '$a net.ipv4.tcp_max_syn_backlog = 2048' /etc/sysctl.conf
	sed -i '$a net.ipv4.tcp_synack_retries = 2' /etc/sysctl.conf
	sed -i '$a net.ipv4.tcp_syn_retries = 5' /etc/sysctl.conf
	sed -i '$a net.ipv4.tcp_syncookies=1' /etc/sysctl.conf
    echo "SYN Flood Protection has been enabled."

	##IP redirecting is disallowed
    echo "Disabling IP redirecting"
	sed -i '$a net.ipv4.ip_foward=0' /etc/sysctl.conf
	sed -i '$a net.ipv4.conf.all.send_redirects=0' /etc/sysctl.conf
	sed -i '$a net.ipv4.conf.default.send_redirects=0' /etc/sysctl.conf
    echo "IP redirecting has been disabled."

	sysctl -p
	pause
}

proc() {
	ps aux --forest
	pause
}

moveFile() {
	while true; do
		read -p "Do you want to move a file? (y/n): " choice
		if [ "$choice" != "y" ]; then
			break
		fi
		read -p "Enter the file you want to move: " source_file
		if [ ! -f "$source_file" ]; then
			echo "Error: File not found!"
			continue
		fi
		read -p "Enter the destination directory: " destination_dir
		if [ ! -d "$destination_dir" ]; then
			echo "Error: Destination directory not found!"
			continue
		fi
		destination_path="$destination_dir/$(basename "$source_file")"
		mv "$source_file" "$destination_path"
		echo "File moved to $destination_path"
		read -p "Do you want to move another file? (y/n): " another_choice
		if [ "$another_choice" != "y" ]; then
			break
		fi
	done
}

nc(){
	if [ $? -eq 0 ]
	then
		cat runningProcesses.log
			read -p "What is the name of the suspected netcat?: " nc
				if [ "$nc" == "none" ]
				then
					echo "k xd"
				else
					whereis "$nc" > Path
					ALIAS=$(alias | grep nc | cut -d' ' -f2 | cut -d'=' -f1)
					PID=$(pgrep "$nc")
					for path in $(cat Path)
					do
							echo "$path"
							if [ $? -eq 0 ]
							then
									sed -i 's/^/#/' "$path"
									kill "$PID"
							else
									echo "This is not a netcat process."
							fi
					done
				fi

				ls /etc/init | grep "$nc".conf >> /dev/null
				if [ $? -eq 0 ]
				then
					cat /etc/init/"$nc".conf | grep -E -i 'nc|netcat|$ALIAS' >> /dev/null
					if [ $? -eq 0 ]
					then
						sed -i 's/^/#/' /etc/init/"$nc".conf
						kill "$PID"
					else
						echo "This is not a netcat process."
					fi
				fi

			ls /etc/init.d | grep "$nc" >>/dev/null
			if [ $? -eq 0 ]
			then
					cat /etc/init.d/"$nc" | grep -E -i 'nc|netcat|$ALIAS' >> /dev/null
					if [ $? -eq 0 ]
					then
							sed -i 's/^/#/' /etc/init.d/"$nc"
							kill "$PID"
					else
							echo "This is not a netcat process."
					fi
			fi

			ls /etc/cron.d | grep "$nc" >>/dev/null
			if [ $? -eq 0 ]
			then
					cat /etc/cron.d/"$nc" | grep -E -i 'nc|netcat|$ALIAS' >> /dev/null
					if [ $? -eq 0 ]
					then
							sed -i 's/^/#/' /etc/init.d/"$nc"
							kill "$PID"
					else
							echo "This is not a netcat process."
					fi
			fi

			ls /etc/cron.hourly | grep "$nc" >>/dev/null
			if [ $? -eq 0 ]
			then
					cat /etc/cron.hourly/"$nc" | grep -E -i 'nc|netcat|$ALIAS' >> /dev/null
					if [ $? -eq 0 ]
					then
							sed -i 's/^/#/' /etc/init.d/"$nc"
							kill "$PID"
					else
							echo "This is not a netcat process."
					fi
			fi

			for x in $(ls /var/spool/cron/crontabs)
			do
				cat "$x" | grep '$nc|nc|netcat|$ALIAS'
				if [ $? -eq 0 ]
				then
					sed -i 's/^/#/' /var/spool/cron/crontabs/"$x"
					kill "$PID"
				else
					echo "netcat has not been found in $x crontabs."
				fi
			done

			cat /etc/crontab | grep -i 'nc|netcat|$ALIAS'
			if [ $? -eq 0 ]
			then
				echo "NETCAT FOUND IN CRONTABS! GO AND REMOVE!!!!!!!!!!"
			fi
			echo "Uninstalling netcat now."

			apt-get autoremove --purge netcat netcat-openbsd netcat-traditional
	else
		echo "Netcat is not installed"
	fi
	pause
}

audit() {
	apt install net-tools
	service auditd start
	output_file="system_audit_report.txt"
	print_section() {
	echo "--------------------------------------------------" >> "$output_file"
	echo "   $1" >> "$output_file"
	echo "--------------------------------------------------" >> "$output_file"
	}
	check_system() {
	print_section "System Information"
	uname -a >> "$output_file"
	print_section "Disk Space Usage"
	df -h >> "$output_file"
	print_section "Memory Usage"
	free -m >> "$output_file"
	print_section "Users and Groups"
	cat /etc/passwd >> "$output_file"
	cat /etc/group >> "$output_file"
	print_section "Running Processes"
	ps aux >> "$output_file"
	print_section "Listening Ports"
	netstat -tuln >> "$output_file"
	print_section "Installed Packages"
	dpkg -l >> "$output_file"
	}
	check_system
	echo "System audit completed. Report saved to $output_file."
	pause
	cat system_audit_report.txt
	pause
}

secureFTP() {
	sudo apt install vsftpd -y
	sudo cp /etc/vsftpd.conf /etc/vsftpd.conf.bak
	echo "anonymous_enable=NO" | sudo tee -a /etc/vsftpd.conf
	read -p "What would you like the minimum port to be? (Default is 40000): " min
	read -p "What would you like the maximum port to be? (Default is 40100): " max
	echo "local_enable=YES" | sudo tee -a /etc/vsftpd.conf
	echo "write_enable=YES" | sudo tee -a /etc/vsftpd.conf
	echo "chroot_local_user=YES" | sudo tee -a /etc/vsftpd.conf
	echo "user_sub_token=\$USER" | sudo tee -a /etc/vsftpd.conf
	echo "local_root=/home/\$USER/ftp" | sudo tee -a /etc/vsftpd.conf
	echo "pasv_min_port=$min" | sudo tee -a /etc/vsftpd.conf
	echo "pasv_max_port=$max" | sudo tee -a /etc/vsftpd.conf
	sudo ufw allow 20
	sudo ufw allow 21
	sudo ufw allow $min:$max/tcp
	sudo ufw enable
	sudo mkdir -p /home/ftp
	sudo chmod 550 /home/ftp
	sudo chown root:root /home/ftp
	sudo systemctl restart vsftpd
	echo "FTP server setup complete."
	
	echo "Now adding/removing users from having FTP access."
	USERS=$(awk -F: '$3 >= 1000 {print $1}' /etc/passwd)
	for USER in $USERS
	do
		read -p "Should user $USER have FTP access? (y/n): " CHOICE
		if [[ $CHOICE == "y" ]]; then
			sudo usermod -aG ftp $USER
			echo "FTP access granted to $USER."
		elif [[ $CHOICE == "n" ]]; then
			sudo deluser $USER ftp
			echo "FTP access revoked from $USER."
		else
			echo "Invalid choice. Skipping user $USER."
		fi
	done
}

games(){
	# Minecraft
	if dpkg -l | grep -q "minecraft"; then
		read -p "Do you want to keep Minecraft? (y/n): " choice
		if [ "$choice" == "n" ]; then
			echo "Removing Minecraft..."
			sudo apt-get purge minecraft -y
			echo "Minecraft removed."
		else
			echo "Minecraft kept."
		fi
	else
		echo "Minecraft is not installed."
	fi

	# OpenRA
	if dpkg -l | grep -q "openra"; then
		read -p "Do you want to keep OpenRA? (y/n): " choice
		if [ "$choice" == "n" ]; then
			echo "Removing OpenRA..."
			sudo apt-get purge openra -y
			echo "OpenRA removed."
		else
			echo "OpenRA kept."
		fi
	else
		echo "OpenRA is not installed."
	fi

	# 0 A.D.
	if dpkg -l | grep -q "0ad"; then
		read -p "Do you want to keep 0 A.D.? (y/n): " choice
		if [ "$choice" == "n" ]; then
			echo "Removing 0 A.D...."
			sudo apt-get purge 0ad -y
			echo "0 A.D. removed."
		else
			echo "0 A.D. kept."
		fi
	else
		echo "0 A.D. is not installed."
	fi

	# SuperTuxKart
	if dpkg -l | grep -q "supertuxkart"; then
		read -p "Do you want to keep SuperTuxKart? (y/n): " choice
		if [ "$choice" == "n" ]; then
			echo "Removing SuperTuxKart..."
			sudo apt-get purge supertuxkart -y
			echo "SuperTuxKart removed."
		else
			echo "SuperTuxKart kept."
		fi
	else
		echo "SuperTuxKart is not installed."
	fi

	# FlightGear
	if dpkg -l | grep -q "flightgear"; then
		read -p "Do you want to keep FlightGear? (y/n): " choice
		if [ "$choice" == "n" ]; then
			echo "Removing FlightGear..."
			sudo apt-get purge flightgear -y
			echo "FlightGear removed."
		else
			echo "FlightGear kept."
		fi
	else
		echo "FlightGear is not installed."
	fi

	# Freeciv
	if dpkg -l | grep -q "freeciv"; then
		read -p "Do you want to keep Freeciv? (y/n): " choice
		if [ "$choice" == "n" ]; then
			echo "Removing Freeciv..."
			sudo apt-get purge freeciv -y
			echo "Freeciv removed."
		else
			echo "Freeciv kept."
		fi
	else
		echo "Freeciv is not installed."
	fi

	# Battle for Wesnoth
	if dpkg -l | grep -q "wesnoth"; then
		read -p "Do you want to keep Battle for Wesnoth? (y/n): " choice
		if [ "$choice" == "n" ]; then
			echo "Removing Battle for Wesnoth..."
			sudo apt-get purge wesnoth -y
			echo "Battle for Wesnoth removed."
		else
			echo "Battle for Wesnoth kept."
		fi
	else
		echo "Battle for Wesnoth is not installed."
	fi

	# 0verkill
	if dpkg -l | grep -q "0verkill"; then
		read -p "Do you want to keep 0verkill? (y/n): " choice
		if [ "$choice" == "n" ]; then
			echo "Removing 0verkill..."
			sudo apt-get purge 0verkill -y
			echo "0verkill removed."
		else
			echo "0verkill kept."
		fi
	else
		echo "0verkill is not installed."
	fi
	# Aisleriot
	if dpkg -l | grep -q "aisleriot"; then
		read -p "Do you want to keep Aisleriot? (y/n): " choice
		if [ "$choice" == "n" ]; then
			echo "Removing Aisleriot..."
			sudo apt-get purge aisleriot -y
			echo "Aisleriot removed."
		else
			echo "Aisleriot kept."
		fi
	else
		echo "Aisleriot is not installed."
	fi

	if dpkg -s "aisleriot" >/dev/null 2>&1; then
		echo "Removing Solitaire game..."
		sudo apt-get purge -y "aisleriot"
	else
		echo "Solitaire game is not installed."
	fi

	# Check and remove Mines game
	if dpkg -s "gnome-mines" >/dev/null 2>&1; then
		echo "Removing Mines game..."
		sudo apt-get purge -y "gnome-mines"
	else
		echo "Mines game is not installed."
	fi
	echo "Game check completed."
	pause
}

searchFile() {
	echo "Do you want to search for a file? (y/n)"
	read choice
	if [ "$choice" = "y" ]; then
		read -p "Enter the name of the file you want to search for: " file_name
		result=$(find / -type f -name "$file_name" 2>/dev/null)
		if [ -n "$result" ]; then
			echo "File found at the following location(s):"
			echo "$result"
		else
			echo "File not found."
		fi
	elif [ "$choice" = "n" ]; then
		echo "Exiting the script."
	else
		echo "Invalid choice. Exiting the script."
	fi
	pause
}

sudoers() {
	cat /etc/sudoers | grep NOPASSWD.* >> /dev/null
	if [ $? -eq 0 ]
	then
		echo "## NOPASSWD VALUE HAS BEEN FOUND IN THE SUDOERS FILE, GO CHANGE IT."
	fi
	cat /etc/sudoers | grep timestamp_timeout >> /dev/null
	if [ $? -eq 0 ]
	then
		TIME=$(cat /etc/sudoers | grep timestamp_timeout | cut -f2 | cut -d= -f2)
		echo "## Time out value has been set to $TIME Please go change it or remove it." 
	fi
    echo "Succesfully exported the /etc/sudoers file."
 	echo "You are about to be shown a file containing all of the users and groups with special permissions. Make sure that only verified users/groups have these."
	sleep 5s
	visudo
	pause
}

delFile() {
	read -p "Would you like to delete a file? (y/n): " choice
	choice=${choice,,}
	if [ "$choice" == "y" ]; then
		read -p "Enter the file name you want to delete: " file_name
		if [ -f "$file_name" ]; then
			rm "$file_name"
			echo "Successfully deleted file '$file_name'."
		else
			echo "File '$file_name' not found."
		fi
	else
		echo "No files were deleted."
	fi
}

cron() {

 #	Listing all the cronjobs
	echo "###CRONTABS###" > cron.log
	for x in $(cat users); do crontab -u "$x" -l; done >> cron.log
	echo "###CRON JOBS###" >> cron.log
	ls /etc/cron.* >> cron.log
	ls /var/spool/cron/crontabs/.* >> cron.log
	ls /etc/crontab >> cron.log

 #	Listing the init.d/init files
	echo "###Init.d###" >> cron.log
	ls /etc/init.d >> cron.log

	echo "###Init###" >> cron.log
	ls /etc/init >> cron.log
	cat cron.log
	pause
}

CAD() {
	sed -i '/exec shutdown -r not "Control-Alt-Delete pressed"/d' /etc/init/control-alt-delete.conf	
	echo "Control-Alt-Delete disabled. Reboot your system for the changes to take effect."

	aliases=$(alias -p | sed -E 's/alias ([^=]+)=\x27(.+)\x27/\1=\2/')
	for alias_def in $aliases; do
		alias_command=$(echo "$alias_def" | cut -d= -f2-)
		if [[ $alias_command == *"rm"* || $alias_command == *"sudo"* ]]; then
			alias_name=$(echo "$alias_def" | cut -d= -f1)
			unalias "$alias_name"
			echo "Alias '$alias_name' removed."
		fi
	done
	pause
}

runFull(){
        echo "NOTE THIS PART OF THE SCRIPT DOES LOTS OF THINGS AND MAY TAKE TIME"
        echo "NOTE THIS WILL NOT DO EVERYTHING!! IT DOES NOT: Change Passwords, Create New Users, Change Lockout Polocies, Reboot The Machine, Run Postscript Things, "
        echo "YOU HAVE 10 SECONDS TO STOP THIS AND cntrl c!"
        sleep 10s
        echo "Ok here we go!"
        sleep 1s
        pause
        update
	autoUpdate
	pFiles
	configureFirewall
	loginConf
	delUser
	admin
	1cron
	passPol
	hakTools
	sshd
	sys
	sudoers
	proc
	nc
        secRoot
	CAD
	createGroup
	delGroup
	VirtualCon
	
        
}
# Does everything
# Written by Max


show_menu(){
	case "$opsys" in
	"Ubuntu")
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "           ██╗   ██╗██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗         "
				echo "           ██║   ██║██╔══██╗██║   ██║████╗  ██║╚══██╔══╝██║   ██║         "
				echo "           ██║   ██║██████╔╝██║   ██║██╔██╗ ██║   ██║   ██║   ██║         "
				echo "           ██║   ██║██╔══██╗██║   ██║██║╚██╗██║   ██║   ██║   ██║         "
				echo "           ╚██████╔╝██████╔╝╚██████╔╝██║ ╚████║   ██║   ╚██████╔╝         "
				echo "            ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ╚═════╝          "
				echo "~~~~~~~~~~~~~~~~~~	Written by: Cullen Fitzgerald	~~~~~~~~~~~~~~~~"
				echo "~~~~~~~~~~~~~~~~~~	 Co-Written by: Max Gallagher	~~~~~~~~~~~~~~~~"
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo " "
				echo "1) Update the machine.			2) Set automatic updates."
				echo "3) Search for prohibited file.		4) configure the firewall."
				echo "5) Configure LightDM.			6) Create any new users."
				echo "7) Change all the passwords.		8) Delete any users."
				echo "9) Set all the admins.			10) List all cronjobs."
				echo "11) Set the password policy.		12) Set the lockout policy."
				echo "13) Remove the hacking tools.		14) Configure SSH."
				echo "15) Edit the sysctl.conf.		16) Export the sudoers file."
				echo "17) List all running processes.		18) Find all user info."
				echo "19) Reboot the machine.			20) Secure the root account"
				echo "21) Configure GDM (Reboot)		22)Disable ctrl-alt-del and aliases"
				echo "23) Create a group			24) Delete a group"			
				echo "25) System audit			26)Exit"
				echo "27) Change group permissions		28) Current display manager"
				echo "29) Install LightDM			30) Install GDM3"
				echo "31) File info/permissions		32) Secure directories"
				echo "33) Delete file				34) Disable cronjobs"
				echo "35) Edit group members			36) File search"
				echo "37) Secure FTP				38) Move file"
				echo "39 Remove Netcat			40) Fix PATH"
				echo "41) Hidden directories			42) Secure cron"
				echo "43) Remove games			44) Edit file"
				echo ""
				echo "69) DO ALL WITHIN REASON"
	;;
	"Debain")
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "				██████╗ ███████╗██████╗  █████╗ ██╗███╗   ██╗				"
				echo "				██╔══██╗██╔════╝██╔══██╗██╔══██╗██║████╗  ██║				"
				echo "				██║  ██║█████╗  ██████╔╝███████║██║██╔██╗ ██║				"
				echo "				██║  ██║██╔══╝  ██╔══██╗██╔══██║██║██║╚██╗██║				"
				echo "				██████╔╝███████╗██████╔╝██║  ██║██║██║ ╚████║				"
				echo "	    		╚═════╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝				"
				echo "~~~~~~~~~~~~~~~~~~	Written by: Cullen Fitzgerald	~~~~~~~~~~~~~~~~~~~~"
				echo "~~~~~~~~~~~~~~~~~~	 Co-Written by: Max Gallagher	~~~~~~~~~~~~~~~~~~~~"
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo " "
				echo "1) Update the machine.			2) Set automatic updates."
				echo "3) Search for prohibited file.		4) configure the firewall."
				echo "5) Configure LightDM.			6) Create any new users."
				echo "7) Change all the passwords.		8) Delete any users."
				echo "9) Set all the admins.			10) List all cronjobs."
				echo "11) Set the password policy.		12) Set the lockout policy."
				echo "13) Remove the hacking tools.		14) Configure SSH."
				echo "15) Edit the sysctl.conf.		16) Export the sudoers file."
				echo "17) List all running processes.		18) Find all user info."
				echo "19) Reboot the machine.			20) Secure the root account"
				echo "21) Configure GDM (Reboot)		22)Disable ctrl-alt-del and aliases"
				echo "23) Create a group			24) Delete a group"			
				echo "25) System audit			26)Exit"
				echo "27) Change group permissions		28) Current display manager"
				echo "29) Install LightDM			30) Install GDM3"
				echo "31) File info/permissions		32) Secure directories"
				echo "33) Delete file				34) Disable cronjobs"
				echo "35) Edit group members			36) File search"
				echo "37) Secure FTP				38) Move file"
				echo "39 Remove Netcat			40) Fix PATH"
				echo "41) Hidden directories			42) Secure cron"
				echo "43) Remove games			44) Edit file"
				echo ""
				echo "69) DO ALL WITHIN REASON"
	;;
	"RedHat")
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "			██████╗ ███████╗██████╗ ██╗  ██╗ █████╗ ████████╗				"
				echo "			██╔══██╗██╔════╝██╔══██╗██║  ██║██╔══██╗╚══██╔══╝				"
				echo "			██████╔╝█████╗  ██║  ██║███████║███████║   ██║   				"
				echo "			██╔══██╗██╔══╝  ██║  ██║██╔══██║██╔══██║   ██║   				"
				echo "			██║  ██║███████╗██████╔╝██║  ██║██║  ██║   ██║   				"
				echo "			╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   				"
				echo "~~~~~~~~~~~~~~~~Written by: Ethan Fowler Team-ByTE~~~~~~~~~~~~~~~~~~~~~~~~"
                echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
                echo " "
			##NOT ALL OF THESE WORK YET, NEED TO FIX
                echo "1) Update the machine.                    2) Set automatic updates."
                echo "3) Search for prohibited file.            4) configure the firewall."
                echo "5) Configure login screen.                6) Create any new users."
                echo "7) Change all the passwords.              8) Delete any users."
                echo "9) Set all the admins.                    10) List all cronjobs."
                echo "11) #Set the password policy.              12) Set the lockout policy."
                echo "13) #Remove the hacking tools.             14) #Configure SSH."
                echo "15) Edit the sysctl.conf.                 16) Export the sudoers file."
                echo "17) List all running processes.           18) #Remove NetCat."
                echo "19) Reboot the machine.                   20) Secure the root account"
                echo "21) PostScript                            22) Disable ctrl-alt-del"
                echo "23) Disable Virtual Terminals     	24) Exit"
	;;
	"CentOS")
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "			 ██████╗███████╗███╗   ██╗████████╗ ██████╗ ███████╗			"
				echo "			██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔═══██╗██╔════╝			"
				echo "			██║     █████╗  ██╔██╗ ██║   ██║   ██║   ██║███████╗			"
				echo "			██║     ██╔══╝  ██║╚██╗██║   ██║   ██║   ██║╚════██║			"
				echo "			╚██████╗███████╗██║ ╚████║   ██║   ╚██████╔╝███████║			"
				echo " 	  	     ╚═════╝╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚══════╝			"
                echo "~~~~~~~~~~~~~~~~Written by: Ethan Fowler Team-ByTE~~~~~~~~~~~~~~~~~~~~~~~~"
                echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
                echo " "
                ##NOT ALL OF THESE WORK YET, NEED TO FIX
                echo "1) Update the machine.                    2) Set automatic updates."
                echo "3) Search for prohibited file.            4) configure the firewall."
                echo "5) Configure login screen.                6) Create any new users."
                echo "7) Change all the passwords.              8) Delete any users."
                echo "9) Set all the admins.                    10) List all cronjobs."
                echo "11) #Set the password policy.              12) Set the lockout policy."
                echo "13) #Remove the hacking tools.             14) #Configure SSH."
                echo "15) Edit the sysctl.conf.                16) Export the sudoers file."
                echo "17) List all running processes.           18) #Remove NetCat."
                echo "19) Reboot the machine.                   20) Secure the root account"
                echo "21) PostScript                            22) Disable ctrl-alt-del"
                echo "23) Disable Virtual Terminals    		24) Exit"
	;;
	esac

}

read_options(){
	case $opsys in
	"Ubuntu"|"Debain")
		local choice
		read -p "Pease select item you wish to do: " choice

		case $choice in
			1) update;;
			2) autoUpdate;;
			3) pFiles;;
			4) configureFirewall;;
			5) loginConf;;
			6) createUser;;
			7) chgPasswd;;
			8) delUser;;
			9) admin;;
			10) cron;;
			11) passPol;;
			12) lockoutPol;;
			13) hakTools;;
			14) sshd;;
			15) sys;;
			16) sudoers;;
			17) proc;;
			18) userInfo;;
	 		19) reboot;;
			20) secRoot;;
			21) gdmConf;;
			22) CAD;;
			23) createGroup;;
			24) delGroup;;
			25) audit;;
			26) exit20;;
			27) adminGroup;;
			28) defDM;;
			29) lightdmInstall;;
			30) gdmInstall;;
			31) filePerms;;
			32) secDirectories;;
			33) delFile;;
			34) disCronJobs;;
			35) groupMembers;;
			36) searchFile;;
			37) secureFTP;;
			38) moveFile;;
			39) nc;;
			40) fixPATH;;
			41) hiddenFiles;;
			42) secureCron;;
			43) games;;
			44) fileEdit;;
			69) runFull;;
			*) echo "Sorry that is not an option please select another one..."
			;;
		esac
	;;
	"CentOS")
		local choice
		read -p "Pease select item you wish to do: " choice

		case $choice in
			1) update;;
			2) autoUpdate;;
			3) pFiles;;
			4) configureFirewall;;
			5) loginConf;;
			6) createUser;;
			7) chgPasswd;;
			8) delUser;;
			9) admin;;
			10) cron;;
			11) passPol;;
			12) lockoutPol;;
			13) hakTools;;
			14) sshd;;
			15) sys;;
			16) sudoers;;
			17) proc;;
			18) nc;;
	 		19) reboot;;
			20) secRoot;;
			21) cat postScript; pause;;
			22) CAD;;
			23)VirtualCon;;
			24) exit20;;
			69)runFull;;
			*) echo "Sorry that is not an option please select another one..."
			;;
		esac
	;;
	"RedHat")
		local choice
		read -p "Pease select item you wish to do: " choice

		case $choice in
			1) update;;
			2) autoUpdate;;
			3) pFiles;;
			4) configureFirewall;;
			5) loginConf;;
			6) createUser;;
			7) chgPasswd;;
			8) delUser;;
			9) admin;;
			10) cron;;
			11) passPol;;
			12) lockoutPol;;
			13) hakTools;;
			14) sshd;;
			15) sys;;
			16) sudoers;;
			17) proc;;
			18) nc;;
	 		19) reboot;;
			20) secRoot;;
			21) cat postScript; pause;;
			22) CAD;;
			23)VirtualCon;;
			24) exit20;;
			69)runFull;;
			*) echo "Sorry that is not an option please select another one..."
			;;
		esac
	;;
	
	esac
}

##This runs .the actual script
while true
do
	clear
	show_menu
	read_options
done
