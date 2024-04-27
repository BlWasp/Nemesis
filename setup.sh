#!/bin/bash

echo "WARNING! BloodHound CE won't be installed because the docker installation never returns the hand and blocks the rest of the script."
echo "Think about installing it manually when this script will finish: curl -L https://ghst.ly/getbhce | sudo docker compose -f - up"
echo "Additionally, think about cloning and compiling CoercedPotato manually, the best potato! -> https://github.com/Prepouce/CoercedPotato"
echo "Enter the user who will use this installation"
read username
echo "Will you use this installation for pentest or CTF ? CTF choice will install additionnal tools for pwn, stego, forensics... (pentest/ctf)"
read usage
path=$(pwd)
cd

#Environment
echo "CiBfX19fXyAgICAgICAgICAgXyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBfICAgICBfICAgICAgICAgICBfICAgICAgICBfIF8gICAgICAgXyAgIF8gICAgICAgICAgICAgCnwgIF9fX3wgICAgICAgICAoXykgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHwgfCAgIChfKSAgICAgICAgIHwgfCAgICAgIHwgfCB8ICAgICB8IHwgKF8pICAgICAgICAgICAgCnwgfF9fIF8gX19fXyAgIF9fXyBfIF9fIF9fXyAgXyBfXyAgIF9fXyBfIF9fIF9fXyAgIF9fXyBfIF9fIHwgfF8gICBfIF8gX18gIF9fX3wgfF8gX18gX3wgfCB8IF9fIF98IHxfIF8gIF9fXyAgXyBfXyAgCnwgIF9ffCAnXyBcIFwgLyAvIHwgJ19fLyBfIFx8ICdfIFwgLyBfIFwgJ18gYCBfIFwgLyBfIFwgJ18gXHwgX198IHwgfCAnXyBcLyBfX3wgX18vIF9gIHwgfCB8LyBfYCB8IF9ffCB8LyBfIFx8ICdfIFwgCnwgfF9ffCB8IHwgXCBWIC98IHwgfCB8IChfKSB8IHwgfCB8ICBfXy8gfCB8IHwgfCB8ICBfXy8gfCB8IHwgfF8gIHwgfCB8IHwgXF9fIFwgfHwgKF98IHwgfCB8IChffCB8IHxffCB8IChfKSB8IHwgfCB8ClxfX19fL198IHxffFxfLyB8X3xffCAgXF9fXy98X3wgfF98XF9fX3xffCB8X3wgfF98XF9fX3xffCB8X3xcX198IHxffF98IHxffF9fXy9cX19cX18sX3xffF98XF9fLF98XF9ffF98XF9fXy98X3wgfF98Cg==" |base64 -d
sleep 2

sudo apt update --fix-missing
sudo apt dist-upgrade
#go
curl -O https://dl.google.com/go/go1.22.2.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.2.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
#gem
sudo apt -y install gem
#rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
export PATH=$PATH:$HOME/.cargo/bin
#poetry
curl -sSL https://install.python-poetry.org | python3 -
#python2 pip installation
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
python2 get-pip.py
python2 -m pip install --upgrade pip


#Softwares
echo "IF9fX19fICAgICAgICBfXyBfICAgICAgICAgICAgICAgICAgICAgICAgICAgIF8gICAgICAgICAgIF8gICAgICAgIF8gXyAgICAgICBfICAgXyAgICAgICAgICAgICAKLyAgX19ffCAgICAgIC8gX3wgfCAgICAgICAgICAgICAgICAgICAgICAgICAgKF8pICAgICAgICAgfCB8ICAgICAgfCB8IHwgICAgIHwgfCAoXykgICAgICAgICAgICAKXCBgLS0uICBfX18gfCB8X3wgfF9fXyAgICAgIF9fX18gXyBfIF9fIF9fXyAgIF8gXyBfXyAgX19ffCB8XyBfXyBffCB8IHwgX18gX3wgfF8gXyAgX19fICBfIF9fICAKIGAtLS4gXC8gXyBcfCAgX3wgX19cIFwgL1wgLyAvIF9gIHwgJ19fLyBfIFwgfCB8ICdfIFwvIF9ffCBfXy8gX2AgfCB8IHwvIF9gIHwgX198IHwvIF8gXHwgJ18gXCAKL1xfXy8gLyAoXykgfCB8IHwgfF8gXCBWICBWIC8gKF98IHwgfCB8ICBfXy8gfCB8IHwgfCBcX18gXCB8fCAoX3wgfCB8IHwgKF98IHwgfF98IHwgKF8pIHwgfCB8IHwKXF9fX18vIFxfX18vfF98ICBcX198IFxfL1xfLyBcX18sX3xffCAgXF9fX3wgfF98X3wgfF98X19fL1xfX1xfXyxffF98X3xcX18sX3xcX198X3xcX19fL3xffCB8X3wKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA=" |base64 -d
sleep 2

#apt packages
echo "ICAgICAgICAgICAgIF8gICAgICAgICAKICBfXyBfIF8gX18gfCB8XyAgICAgICAKIC8gX2AgfCAnXyBcfCBfX3wgICAgICAKfCAoX3wgfCB8XykgfCB8XyBfIF8gXyAKIFxfXyxffCAuX18vIFxfXyhffF98XykKICAgICAgfF98ICAgICAgICAgICAgICA=" |base64 -d
sleep 2
#Usefull stuff
sudo apt -y install libpcap-dev libpq-dev libmariadb-dev-compat libmariadb-dev libcairo2-dev libgmp3-dev libmpc-dev
sudo apt -y install python2-dev python-dev-is-python3
sudo apt -y install python3.12-venv
sudo apt -y install seahorse
sudo apt -y install terminator
sudo apt -y install rlwrap

#Docker and Docker compose install
# Add Docker's official GPG key
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
# Add the repository to Apt sources
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  bookworm stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt -y install docker docker.io
sudo apt -y install docker-compose-plugin

sudo apt -y install mingw-w64
sudo apt -y install ewf-tools
sudo apt -y install squidclient
sudo apt -y install sshuttle iptables
sudo apt -y install fcrackzip
sudo apt -y install pdfcrack
sudo apt -y install seclists
#Fish shell
sudo apt -y install fish
chsh -s $(which fish)
#Cause I'm using fish. Adapte this command to your shell solution
set -Ua fish_user_paths $fish_user_paths /usr/local/go/bin /home/$username/.local/bin /home/$username/.cargo/bin

if [ "$usage" = "pentest" ]; then
	sudo apt -y install flameshot
	sudo apt -y install airgeddon
fi

#Microsoft stuff
sudo apt purge crackmapexec
sudo apt purge python3-impacket
#Install neo4j 4.X instead of 5.X to avoid performance issues
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable 4' | sudo tee /etc/apt/sources.list.d/neo4j.list > /dev/null
sudo apt update
sudo apt -y install apt-transport-https
sudo apt -y install neo4j
#BloodHound Legacy, the CE version must be installed manually
sudo apt -y install bloodhound
#Kerberos and NTLM
sudo apt install -y libkrb5-dev krb5-user libpam-krb5 libpam-ccreds gss-ntlmssp

if [ "$usage" = "ctf" ]; then
	#PWN stuff
	sudo apt -y install gdb
	sudo apt -y install gdbserver
	sudo apt -y install qemu-user
	sudo apt -y install qemu-system
	sudo apt -y install gdb-multiarch
	sudo apt -y install patchelf

	#Crypto stuff
	sudo apt -y install osslsigncode
	
	#Stego stuff
	sudo apt -y install steghide
fi

#Sublime Text
wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | sudo apt-key add -
echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list
sudo apt update
sudo apt -y install sublime-text


#pip packets
echo "ICAgICAgIF8gICAgICAgICAgICAKIF8gX18gKF8pXyBfXyAgICAgICAKfCAnXyBcfCB8ICdfIFwgICAgICAKfCB8XykgfCB8IHxfKSB8IF8gXyAKfCAuX18vfF98IC5fXyhffF98XykKfF98ICAgICB8X3wgICAgICAgICA=" |base64 -d
sleep 2
#Usefull stuff
pip3 install --upgrade setuptools
pip3 install --user pipx
python3 -m pipx ensurepath
export PATH=$PATH:/home/$username/.local/bin
pip3 install dnspython
pip3 install pandas
pip3 install prettytable
pip3 install python-libpcap

#Microsoft stuff
pip3 install py2neo
pip3 install ldap3
pip3 install kerberos
pipx install bloodhound
pipx install aclpwn
pipx install minikerberos --force
pipx install kerberoast
pipx install pypykatz
pipx install roadrecon
pipx install coercer
pipx install masky
pip3 uninstall lsassy
pipx install lsassy
pipx install git+https://github.com/Pennyw0rth/NetExec
pipx install certsync
pipx install donpapi
pipx install dploot
pipx install krbjack
pipx install certipy-ad
pipx install git+https://github.com/synacktiv/GPOddity

#Web stuff
pip3 install pycryptodomex
pipx install bypass-url-parser

if [ "$usage" = "ctf" ]; then
	#PWN stuff
	python2 -m pip install pwntools
	pip3 install pwntools
	pipx install ropper
	pip3 install capstone
	pip3 install keystone-engine
	pip3 install filebytes

	#Crypto stuff
	python2 -m pip install pycrypto
	pip3 install z3-solver
fi
if [ "$usage" = "pentest" ]; then
	#Wireless stuff
	pip3 install wpa_supplicant
fi

echo "Update all Python packets"
for x in $(python2 -m pip list -o --format=columns | sed -n '3,$p' | cut -d' ' -f1); do python2 -m pip install $x --upgrade; done
for x in $(pip3 list -o --format=columns | sed -n '3,$p' | cut -d' ' -f1); do pip3 install $x --upgrade; done


#gem packages
echo "ICBfXyBfICBfX18gXyBfXyBfX18gICAgICAgIAogLyBfYCB8LyBfIFwgJ18gYCBfIFwgICAgICAgCnwgKF98IHwgIF9fLyB8IHwgfCB8IHxfIF8gXyAKIFxfXywgfFxfX198X3wgfF98IHxfKF98X3xfKQogfF9fXy8gICAgICAgICAgICAgICAgICAgICAg" |base64 -d
sleep 2
sudo gem install evil-winrm
sudo gem install wpscan

if [ "$usage" = "ctf" ]; then
	sudo gem install one_gadget
fi


#go packages
echo "ICBfXyBfICBfX18gICAgICAgCiAvIF9gIHwvIF8gXCAgICAgIAp8IChffCB8IChfKSB8IF8gXyAKIFxfXywgfFxfX18oX3xffF8pCiB8X19fLyAgICAgICAgICAgIA==" |base64 -d
sleep 2
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/drk1wi/Modlishka@latest
go install -v github.com/Hackmanit/TInjA@latest
go install github.com/denandz/sourcemapper@latest
go install github.com/g0ldencybersec/CloudRecon@latest
go install github.com/bitquark/shortscan/cmd/shortscan@latest
go install github.com/neex/phuip-fpizdam@latest

#echo "docker http3..."
#docker run -it --rm ymuski/curl-http3 curl -ILv https://10.10.10.186/ --http3


#Scripts installation
echo "IF9fX19fICAgICAgICAgICBfICAgICAgIF8gICAgICAgICBfICAgICAgICAgICBfICAgICAgICBfIF8gICAgICAgXyAgIF8gICAgICAgICAgICAgCi8gIF9fX3wgICAgICAgICAoXykgICAgIHwgfCAgICAgICAoXykgICAgICAgICB8IHwgICAgICB8IHwgfCAgICAgfCB8IChfKSAgICAgICAgICAgIApcIGAtLS4gIF9fXyBfIF9fIF8gXyBfXyB8IHxfIF9fXyAgIF8gXyBfXyAgX19ffCB8XyBfXyBffCB8IHwgX18gX3wgfF8gXyAgX19fICBfIF9fICAKIGAtLS4gXC8gX198ICdfX3wgfCAnXyBcfCBfXy8gX198IHwgfCAnXyBcLyBfX3wgX18vIF9gIHwgfCB8LyBfYCB8IF9ffCB8LyBfIFx8ICdfIFwgCi9cX18vIC8gKF9ffCB8ICB8IHwgfF8pIHwgfF9cX18gXCB8IHwgfCB8IFxfXyBcIHx8IChffCB8IHwgfCAoX3wgfCB8X3wgfCAoXykgfCB8IHwgfApcX19fXy8gXF9fX3xffCAgfF98IC5fXy8gXF9ffF9fXy8gfF98X3wgfF98X19fL1xfX1xfXyxffF98X3xcX18sX3xcX198X3xcX19fL3xffCB8X3wKICAgICAgICAgICAgICAgICAgfCB8ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgIHxffCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA==" |base64 -d
sleep 2
cd $path
sudo mkdir /opt/Tools
sudo mkdir /opt/Tools/Windows
sudo mv Tools/Windows /opt/Tools/Windows/Others

#Windows
echo "IF9fICAgIF9fIF8gICAgICAgICAgIF8gICAgICAgICAgICAgICAgICAgICAgICAgCi8gLyAvXCBcIChfKV8gX18gICBfX3wgfCBfX19fXyAgICAgIF9fX19fICAgICAgIApcIFwvICBcLyAvIHwgJ18gXCAvIF9gIHwvIF8gXCBcIC9cIC8gLyBfX3wgICAgICAKIFwgIC9cICAvfCB8IHwgfCB8IChffCB8IChfKSBcIFYgIFYgL1xfXyBcXyBfIF8gCiAgXC8gIFwvIHxffF98IHxffFxfXyxffFxfX18vIFxfL1xfLyB8X19fKF98X3xfKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA=" |base64 -d
sleep 2
cd /opt/Tools/Windows

#Install the impacket version of ThePorgs which is way better maintained
echo "Impacket"
sudo git clone https://github.com/ThePorgs/impacket.git
cd impacket
pip3 install -r requirements.txt
sudo pip3 install .
cd ..

echo "Recon tools"
sudo git clone https://github.com/ropnop/windapsearch.git
sudo git clone https://github.com/411Hall/JAWS.git
sudo git clone https://github.com/kaluche/bloodhound-quickwin.git
sudo git clone https://github.com/franc-pentest/ldeep.git
cd ldeep
pip3 install -r requirements.txt
sudo pip3 install .
cd ..
sudo git clone https://github.com/OPENCYBER-FR/RustHound.git
cd RustHound
sudo docker build -t rusthound .
cd ..
sudo git clone https://github.com/aniqfakhrul/powerview.py.git
cd powerview.py
pipx install .
cd ..

if [ "$usage" = "pentest" ]; then
	sudo git clone https://github.com/byt3bl33d3r/ItWasAllADream
	cd ItWasAllADream && sudo docker build -t itwasalladream .
	cd ..
fi

echo "Brute Force tools"
curl -s https://api.github.com/repos/ropnop/kerbrute/releases/latest |grep "browser_download_url.*linux_amd64" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O kerbrute
sudo chmod 755 kerbrute
sudo git clone https://github.com/Greenwolf/Spray.git

echo "Relay/NTLM tools"
sudo git clone https://github.com/Tw1sm/RITM.git
cd RITM
pipx install .
cd ..
sudo git clone https://github.com/topotam/PetitPotam.git
sudo git clone https://github.com/evilmog/ntlmv1-multi.git
sudo git clone https://github.com/dirkjanm/mitm6.git
cd mitm6
pip3 install -r requirements.txt
sudo pip3 install .
cd ..
sudo git clone https://github.com/Kevin-Robertson/Inveigh.git
sudo git clone https://github.com/dirkjanm/krbrelayx.git
sudo git clone https://github.com/Hackndo/WebclientServiceScanner.git
cd WebclientServiceScanner
sudo pip3 install .
cd ..

echo "Potato tools"
#SweetPotato is in the SharpCollection repo
sudo mkdir Potato
cd Potato
curl -s https://api.github.com/repos/ohpe/juicy-potato/releases/latest |grep "browser_download_url.*exe" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O JuicyPotato.exe
sudo wget https://github.com/breenmachine/RottenPotatoNG/raw/master/RottenPotatoEXE/x64/Release/MSFRottenPotato.exe -O RottenPotato.exe
sudo wget https://github.com/breenmachine/RottenPotatoNG/raw/master/RottenPotatoDLL/x64/Release/MSFRottenPotato.dll -O RottenPotato.dll
sudo wget https://github.com/antonioCoco/RemotePotato0/releases/download/1.2/RemotePotato0.zip -O RemotePotato0.zip
sudo unzip RemotePotato0.zip && sudo rm RemotePotato0.zip
sudo wget https://github.com/antonioCoco/RoguePotato/releases/download/1.0/RoguePotato.zip -O RoguePotato.zip
sudo unzip RoguePotato.zip && sudo rm RoguePotato.zip
#Not potato, but same goal
sudo wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe -O PrintSpoofer64.exe
sudo wget https://github.com/antonioCoco/JuicyPotatoNG/releases/download/v1.1/JuicyPotatoNG.zip -O JuicyPotatoNG.zip
sudo unzip JuicyPotatoNG.zip && sudo rm JuicyPotatoNG.zip
sudo wget https://github.com/decoder-it/LocalPotato/releases/download/v1.0/LocalPotato.zip -O LocalPotato.zip
sudo unzip LocalPotato.zip && sudo rm LocalPotato.zip
cd ..

echo "Impersonate"
sudo git clone https://github.com/zblurx/impersonate-rs
cd impersonate-rs
make release
cd ..

echo "Mimikatz"
sudo wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.7z -O mimikatz.7z
sudo wget https://github.com/gentilkiwi/kekeo/releases/download/2.2.0-20211214/kekeo.zip -O kekeo.zip

echo "ADCS tools"
sudo git clone https://github.com/dirkjanm/PKINITtools
cd PKINITtools
pip3 install -r requirements.txt
cd ..

echo "Obfuscation tools"
sudo git clone https://github.com/CBHue/PyFuscation.git
sudo git clone https://github.com/Genetic-Malware/Ebowla.git
sudo git clone https://github.com/optiv/ScareCrow.git
sudo chown -R $username:$username ScareCrow
sudo chmod -R 755 ScareCrow
cd ScareCrow
go get github.com/fatih/color && go get github.com/yeka/zip && go get github.com/josephspurrier/goversioninfo && go get github.com/Binject/debug/pe && go get github.com/awgh/rawreader
go get github.com/mattn/go-isatty@v0.0.17
go build ScareCrow.go
cd ..
sudo git clone https://github.com/optiv/Freeze.rs.git
rustup target add x86_64-pc-windows-gnu
cd Freeze.rs
cargo build --release
cd ..

echo "Specific tools: SQL/SCCM/WSUS/Backup"
sudo git clone https://github.com/NetSPI/PowerUpSQL.git
#Personal fork with CMScripts deployement (PR still open)
sudo git clone https://github.com/BlWasp/PowerSCCM.git
sudo git clone https://github.com/garrettfoster13/sccmhunter.git
cd sccmhunter
pip3 install -r requirements.txt
cd ..
sudo git clone https://github.com/GoSecure/pywsus.git
sudo git clone https://github.com/giuliano108/SeBackupPrivilege.git

echo "Azure/ADFS tools"
#ADFSDump is in the SharpCollection repo
sudo git clone https://github.com/mandiant/ADFSpoof.git
cd ADFSpoof
pip3 install -r requirements.txt
cd ..
sudo git clone https://github.com/Gerenios/AADInternals.git
sudo git clone https://github.com/LMGsec/o365creeper.git
sudo git clone https://github.com/morRubin/PrtToCert.git
cd PrtToCert
pip3 install -r requirements.txt
cd ..
sudo git clone https://github.com/morRubin/AzureADJoinedMachinePTC.git
sudo git clone https://github.com/0xZDH/o365spray.git
cd o365spray
pip3 install -r requirements.txt
pip3 install .
cd ..
sudo git clone https://github.com/yuyudhn/AzSubEnum.git
cd AzSubEnum
pip3 install -r requirements.txt
cd ..

echo "PowerShell tools compilation"
sudo cp -r /usr/share/windows-resources/powersploit ./
sudo git clone https://github.com/samratashok/nishang.git
sudo git clone https://github.com/samratashok/ADModule.git
sudo git clone https://github.com/Kevin-Robertson/Powermad.git

#Those two repos are very similar, but interesting to get everything
echo "C# tools compilation"
sudo git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git
sudo git clone https://github.com/Flangvik/SharpCollection.git

echo "CVE repos"
sudo git clone https://github.com/Ridter/noPac.git
sudo git clone https://github.com/ly4k/SpoolFool.git
sudo git clone https://github.com/ly4k/PrintNightmare.git
sudo git clone https://github.com/SecuraBV/CVE-2020-1472.git

echo "Add user DLL"
sudo git clone https://github.com/newsoft/adduser.git


#Linux
cd ..
echo "ICAgX18gXyAgICAgICAgICAgICAgICAgICAgICAgIAogIC8gLyhfKV8gX18gIF8gICBfX18gIF9fICAgICAgCiAvIC8gfCB8ICdfIFx8IHwgfCBcIFwvIC8gICAgICAKLyAvX198IHwgfCB8IHwgfF98IHw+ICA8IF8gXyBfIApcX19fXy9ffF98IHxffFxfXyxfL18vXF8oX3xffF8pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA=" |base64 -d
sleep 2
sudo mkdir Linux
cd Linux
sudo wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar -O yso.jar
sudo wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 -O pspy64
curl -s https://api.github.com/repos/java-decompiler/jd-gui/releases/latest |grep "browser_download_url.*[0-9].jar" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O jd-gui.jar
sudo git clone https://github.com/mxrch/snmp-shell.git


#Web
cd ..
echo "IF9fICAgIF9fICAgICBfICAgICAgICAgIAovIC8gL1wgXCBcX19ffCB8X18gICAgICAgClwgXC8gIFwvIC8gXyBcICdfIFwgICAgICAKIFwgIC9cICAvICBfXy8gfF8pIHwgXyBfIAogIFwvICBcLyBcX19ffF8uX18oX3xffF8pCiAgICAgICAgICAgICAgICAgICAgICAgICA=" |base64 -d
sleep 2
sudo mkdir Web
cd Web
sudo git clone https://github.com/cisagov/log4j-scanner.git
sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git
sudo git clone https://github.com/ticarpi/jwt_tool.git
sudo git clone https://github.com/FlorianPicca/JWT-Key-Recovery.git
sudo git clone https://github.com/gsmith257-cyber/GraphCrawler.git
sudo git clone https://github.com/dolevf/graphw00f.git
sudo git clone https://github.com/arthaud/git-dumper.git
sudo git clone https://github.com/mxrch/webwrap.git
sudo git clone https://github.com/WhiteWinterWolf/wwwolf-php-webshell.git
sudo git clone https://github.com/epinna/tplmap.git
sudo git clone https://github.com/vladko312/SSTImap.git
sudo git clone https://github.com/CerTusHack/Citrix-bleed-Xploit.git
sudo git clone https://github.com/lobuhi/byp4xx.git
cd byp4xx
go build byp4xx.go
cd ..
sudo git clone https://github.com/milan277/RTSPBruter.git
sudo git clone https://github.com/0xbigshaq/firepwn-tool.git
sudo git clone https://github.com/defparam/smuggler.git
if [ "$usage" = "ctf" ]; then
	sudo git clone https://github.com/AonCyberLabs/PadBuster.git
	sudo git clone https://github.com/cnotin/SplunkWhisperer2.git
fi


if [ "$usage" = "ctf" ]; then
	#Crypto
	cd ..
	echo "ICAgX19fICAgICAgICAgICAgICAgICBfICAgICAgICAgICAgIAogIC8gX19cIF9fIF8gICBfIF8gX18gfCB8XyBfX18gICAgICAgCiAvIC8gfCAnX198IHwgfCB8ICdfIFx8IF9fLyBfIFwgICAgICAKLyAvX198IHwgIHwgfF98IHwgfF8pIHwgfHwgKF8pIHwgXyBfIApcX19fXy9ffCAgIFxfXywgfCAuX18vIFxfX1xfX18oX3xffF8pCiAgICAgICAgICAgfF9fXy98X3wgICAgICAgICAgICAgICAgICA=" |base64 -d
	sleep 2
	sudo mkdir Crypto
	cd Crypto
	sudo git clone https://github.com/Ganapati/RsaCtfTool.git
	sudo git clone https://github.com/nccgroup/featherduster.git
	sudo mkdir XORSearch
	cd XORSearch
	sudo wget https://github.com/DidierStevens/FalsePositives/raw/master/XORSearch_V1_11_4.zip -O XORSearch.zip
	sudo unzip XORSearch.zip && sudo rm XORSearch.zip
	cd ..

	#Stego
	cd ..
	echo "IF9fIF8gICAgICAgICAgICAgICAgICAgICAgICAKLyBfXCB8XyBfX18gIF9fIF8gIF9fXyAgICAgICAKXCBcfCBfXy8gXyBcLyBfYCB8LyBfIFwgICAgICAKX1wgXCB8fCAgX18vIChffCB8IChfKSB8IF8gXyAKXF9fL1xfX1xfX198XF9fLCB8XF9fXyhffF98XykKICAgICAgICAgICAgfF9fXy8gICAgICAgICAgICA=" |base64 -d
	sleep 2
	sudo mkdir Stego
	cd Stego
	sudo git clone https://github.com/Va5c0/Steghide-Brute-Force-Tool.git
	sudo mkdir stegsolve
	cd stegsolve
	sudo wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
	cd ..
	#For stego docker futur use
	#sudo mkdir data
	#sudo service docker start
	#sudo docker pull dominicbreuker/stego-toolkit

	#PWN
	cd ..
	echo "ICAgX19fICBfXyAgICBfXyAgICBfXyAgICAgCiAgLyBfIFwvIC8gL1wgXCBcL1wgXCBcICAgIAogLyAvXykvXCBcLyAgXC8gLyAgXC8gLyAgICAKLyBfX18vICBcICAvXCAgLyAvXCAgLyBfIF8gClwvICAgICAgIFwvICBcL1xfXCBcKF98X3xfKQogICAgICAgICAgICAgICAgICAgICAgICAgICA=" |base64 -d
	sleep 2
	sudo mkdir pwn
	cd pwn
	sudo git clone https://github.com/Diefunction/Canary.git
	sudo git clone https://github.com/sashs/ropper.git
	cd ropper
	sudo git submodule init
	sudo git submodule update
	cd ..

	#Forensics
	cd ..
	echo "ICAgX19fICAgICAgICAgICAgICAgICAgICAgICAgXyAgICAgICAgICAgICAgICAKICAvIF9fXF9fICBfIF9fIF9fXyBfIF9fICBfX18oXykgX19fIF9fXyAgICAgICAKIC8gX1wvIF8gXHwgJ19fLyBfIFwgJ18gXC8gX198IHwvIF9fLyBfX3wgICAgICAKLyAvIHwgKF8pIHwgfCB8ICBfXy8gfCB8IFxfXyBcIHwgKF9fXF9fIFxfIF8gXyAKXC8gICBcX19fL3xffCAgXF9fX3xffCB8X3xfX18vX3xcX19ffF9fXyhffF98XykKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA=" |base64 -d
	sleep 2
	sudo mkdir Forensics
	cd Forensics
	sudo git clone https://github.com/volatilityfoundation/volatility.git
fi


#Android
cd ..
echo "ICAgXyAgICAgICAgICAgICBfICAgICAgICAgICBfICAgICBfICAgICAgIAogIC9fXCAgXyBfXyAgIF9ffCB8XyBfXyBfX18gKF8pIF9ffCB8ICAgICAgCiAvL19cXHwgJ18gXCAvIF9gIHwgJ19fLyBfIFx8IHwvIF9gIHwgICAgICAKLyAgXyAgXCB8IHwgfCAoX3wgfCB8IHwgKF8pIHwgfCAoX3wgfF8gXyBfIApcXy8gXF8vX3wgfF98XF9fLF98X3wgIFxfX18vfF98XF9fLF8oX3xffF8pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA=" |base64 -d
sleep 2
sudo docker pull opensecurity/mobile-security-framework-mobsf:latest
sudo mkdir Android
cd Android
sudo wget https://dl.google.com/android/repository/platform-tools-latest-linux.zip -O platform-tools-latest-linux.zip
sudo unzip platform-tools-latest-linux.zip && sudo rm platform-tools-latest-linux.zip
sudo git clone https://github.com/WithSecureLabs/drozer.git
sudo chown -R $username:$username drozer/
cd drozer
python2 setup.py bdist_wheel 
python2 -m pip install dist/drozer-2.5.0-py2-none-any.whl
wget https://github.com/FSecureLABS/drozer/releases/download/2.3.4/drozer-agent-2.3.4.apk -O drozer-agent-2.3.4.apk
cd ..
cd ..


if [ "$usage" = "pentest" ]; then
	#Wireless
	echo "IF9fICAgIF9fIF8gICAgICAgICAgXyAgICAgICAgICAgICAgICAgICAgIAovIC8gL1wgXCAoXylfIF9fIF9fX3wgfCBfX18gIF9fXyBfX18gICAgICAgClwgXC8gIFwvIC8gfCAnX18vIF8gXCB8LyBfIFwvIF9fLyBfX3wgICAgICAKIFwgIC9cICAvfCB8IHwgfCAgX18vIHwgIF9fL1xfXyBcX18gXF8gXyBfIAogIFwvICBcLyB8X3xffCAgXF9fX3xffFxfX198fF9fXy9fX18oX3xffF8pCg==" |base64 -d
	sleep 2
	sudo mkdir Wireless
	cd Wireless
	sudo git clone https://github.com/Wh1t3Rh1n0/air-hammer.git
	sudo git clone https://github.com/s0lst1c3/eaphammer.git
	cd eaphammer
	sudo ./kali-setup
	cd ..
	cd ..
fi


#OSINT tools
echo "ICAgX19fICBfXyAgIF9fX19fICAgIF9fICBfX19fXyAgIAogIC9fX19cLyBfXCAgXF8gICBcL1wgXCBcL19fICAgXCAgCiAvLyAgLy9cIFwgICAgLyAvXC8gIFwvIC8gIC8gL1wvICAKLyBcXy8vIF9cIFwvXC8gL18vIC9cICAvICAvIC8gXyBfIApcX19fLyAgXF9fL1xfX19fL1xfXCBcLyAgIFwoX3xffF8pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA=" |base64 -d
sleep 2
sudo mkdir OSINT
cd OSINT
sudo git clone https://github.com/l4rm4nd/LinkedInDumper.git
cd LinkedInDumper
pip3 install -r requirements.txt
cd ..


#General tools
cd ..
echo "ICAgX19fICAgICAgICAgICAgICAgICAgICAgICAgICBfICAgXyAgICAgICAgICAgICAgXyAgICAgICAgICAgCiAgLyBfIFxfX18gXyBfXyAgIF9fXyBfIF9fIF9fIF98IHwgfCB8XyBfX18gICBfX18gfCB8X19fICAgICAgIAogLyAvX1wvIF8gXCAnXyBcIC8gXyBcICdfXy8gX2AgfCB8IHwgX18vIF8gXCAvIF8gXHwgLyBfX3wgICAgICAKLyAvX1xcICBfXy8gfCB8IHwgIF9fLyB8IHwgKF98IHwgfCB8IHx8IChfKSB8IChfKSB8IFxfXyBcXyBfIF8gClxfX19fL1xfX198X3wgfF98XF9fX3xffCAgXF9fLF98X3wgIFxfX1xfX18vIFxfX18vfF98X19fKF98X3xfKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA=" |base64 -d
sleep 2
sudo git clone https://github.com/RUB-NDS/PRET.git
sudo git clone https://github.com/jpillora/chisel.git
cd chisel
sudo make linux && sudo make windows
cd ..
#PEASS scripts and binaries
sudo mkdir PEASS
cd PEASS
curl -s https://api.github.com/repos/carlospolop/peass-ng/releases/latest |grep "browser_download_url.*linpeas.sh" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O linpeas.sh
curl -s https://api.github.com/repos/carlospolop/peass-ng/releases/latest |grep "browser_download_url.*winPEAS.bat" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O winPEAS.bat
curl -s https://api.github.com/repos/carlospolop/peass-ng/releases/latest |grep "browser_download_url.*winPEASany.exe" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O winPEASany.exe
curl -s https://api.github.com/repos/carlospolop/peass-ng/releases/latest |grep "browser_download_url.*winPEASx64.exe" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O winPEASx64.exe
curl -s https://api.github.com/repos/carlospolop/peass-ng/releases/latest |grep "browser_download_url.*winPEASx86.exe" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O winPEASx86.exe
curl -s https://api.github.com/repos/carlospolop/peass-ng/releases/latest |grep "browser_download_url.*winPEASx86.exe" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O winPEASx86.exe
sudo wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1 -O winPEAS.ps1
cd ..
sudo git clone https://github.com/andrew-d/static-binaries.git
sudo git clone --recurse-submodules https://github.com/xct/xc.git
sudo chown -R $username:$username xc/
cd xc
GO111MODULE=off go get golang.org/x/sys/...
GO111MODULE=off go get golang.org/x/text/encoding/unicode
GO111MODULE=off go get github.com/hashicorp/yamux
GO111MODULE=off go get github.com/libp2p/go-reuseport
python3 build.py
cd ..
sudo git clone https://github.com/lgandx/PCredz.git


sudo chown -R $username:$username /opt/Tools
sudo chmod -R 755 /opt/Tools


#gef
echo "ICAgICAgICAgICAgIF9fICAgICAgCiAgX18gXyAgX19fIC8gX3wgICAgIAogLyBfYCB8LyBfIFwgfF8gICAgICAKfCAoX3wgfCAgX18vICBffCBfIF8gCiBcX18sIHxcX19ffF98KF98X3xfKQogfF9fXy8gICAgICAgICAgICAgICA=" |base64 -d
cd
sleep 2
wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py
echo source ~/.gdbinit-gef.py >> ~/.gdbinit


sudo apt autoremove
echo "X19fX19fIF8gICAgICAgXyAgICAgXyAgICAgICAgICAgICAgXyAgIF8gCnwgIF9fXyhfKSAgICAgKF8pICAgfCB8ICAgICAgICAgICAgfCB8IHwgfAp8IHxfICAgXyBfIF9fICBfIF9fX3wgfF9fICAgX19fICBfX3wgfCB8IHwKfCAgX3wgfCB8ICdfIFx8IC8gX198ICdfIFwgLyBfIFwvIF9gIHwgfCB8CnwgfCAgIHwgfCB8IHwgfCBcX18gXCB8IHwgfCAgX18vIChffCB8IHxffApcX3wgICB8X3xffCB8X3xffF9fXy9ffCB8X3xcX19ffFxfXyxffCAoXyk=" |base64 -d
