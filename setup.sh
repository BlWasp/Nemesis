#!/bin/bash

echo "Enter the user who will use this installation"
read username
echo "Will you use this installation for pentest or CTF ? CTF choice will install additionnal tools for pwn, stego,... (pentest/ctf)"
read usage
path=$(pwd)
cd

#Environment
echo "CiBfX19fXyAgICAgICAgICAgXyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBfICAgICBfICAgICAgICAgICBfICAgICAgICBfIF8gICAgICAgXyAgIF8gICAgICAgICAgICAgCnwgIF9fX3wgICAgICAgICAoXykgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHwgfCAgIChfKSAgICAgICAgIHwgfCAgICAgIHwgfCB8ICAgICB8IHwgKF8pICAgICAgICAgICAgCnwgfF9fIF8gX19fXyAgIF9fXyBfIF9fIF9fXyAgXyBfXyAgIF9fXyBfIF9fIF9fXyAgIF9fXyBfIF9fIHwgfF8gICBfIF8gX18gIF9fX3wgfF8gX18gX3wgfCB8IF9fIF98IHxfIF8gIF9fXyAgXyBfXyAgCnwgIF9ffCAnXyBcIFwgLyAvIHwgJ19fLyBfIFx8ICdfIFwgLyBfIFwgJ18gYCBfIFwgLyBfIFwgJ18gXHwgX198IHwgfCAnXyBcLyBfX3wgX18vIF9gIHwgfCB8LyBfYCB8IF9ffCB8LyBfIFx8ICdfIFwgCnwgfF9ffCB8IHwgXCBWIC98IHwgfCB8IChfKSB8IHwgfCB8ICBfXy8gfCB8IHwgfCB8ICBfXy8gfCB8IHwgfF8gIHwgfCB8IHwgXF9fIFwgfHwgKF98IHwgfCB8IChffCB8IHxffCB8IChfKSB8IHwgfCB8ClxfX19fL198IHxffFxfLyB8X3xffCAgXF9fXy98X3wgfF98XF9fX3xffCB8X3wgfF98XF9fX3xffCB8X3xcX198IHxffF98IHxffF9fXy9cX19cX18sX3xffF98XF9fLF98XF9ffF98XF9fXy98X3wgfF98Cg==" |base64 -d
sleep 2

sudo apt update --fix-missing
sudo apt dist-upgrade
sudo apt -y install golang-go
sudo apt -y install gem
#python2 pip installation
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
python2 get-pip.py
python2 -m pip install --upgrade pip
sudo apt -y install python3-pip
python3 -m pip install --upgrade pip


#Softwares
echo "IF9fX19fICAgICAgICBfXyBfICAgICAgICAgICAgICAgICAgICAgICAgICAgIF8gICAgICAgICAgIF8gICAgICAgIF8gXyAgICAgICBfICAgXyAgICAgICAgICAgICAKLyAgX19ffCAgICAgIC8gX3wgfCAgICAgICAgICAgICAgICAgICAgICAgICAgKF8pICAgICAgICAgfCB8ICAgICAgfCB8IHwgICAgIHwgfCAoXykgICAgICAgICAgICAKXCBgLS0uICBfX18gfCB8X3wgfF9fXyAgICAgIF9fX18gXyBfIF9fIF9fXyAgIF8gXyBfXyAgX19ffCB8XyBfXyBffCB8IHwgX18gX3wgfF8gXyAgX19fICBfIF9fICAKIGAtLS4gXC8gXyBcfCAgX3wgX19cIFwgL1wgLyAvIF9gIHwgJ19fLyBfIFwgfCB8ICdfIFwvIF9ffCBfXy8gX2AgfCB8IHwvIF9gIHwgX198IHwvIF8gXHwgJ18gXCAKL1xfXy8gLyAoXykgfCB8IHwgfF8gXCBWICBWIC8gKF98IHwgfCB8ICBfXy8gfCB8IHwgfCBcX18gXCB8fCAoX3wgfCB8IHwgKF98IHwgfF98IHwgKF8pIHwgfCB8IHwKXF9fX18vIFxfX18vfF98ICBcX198IFxfL1xfLyBcX18sX3xffCAgXF9fX3wgfF98X3wgfF98X19fL1xfX1xfXyxffF98X3xcX18sX3xcX198X3xcX19fL3xffCB8X3wKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA=" |base64 -d
sleep 2

#apt packages
echo "ICAgICAgICAgICAgIF8gICAgICAgICAKICBfXyBfIF8gX18gfCB8XyAgICAgICAKIC8gX2AgfCAnXyBcfCBfX3wgICAgICAKfCAoX3wgfCB8XykgfCB8XyBfIF8gXyAKIFxfXyxffCAuX18vIFxfXyhffF98XykKICAgICAgfF98ICAgICAgICAgICAgICA=" |base64 -d
sleep 2
#Usefull stuff
sudo apt -y install libpq-dev libmariadb-dev-compat libmariadb-dev libcairo2-dev libgmp3-dev libmpc-dev
sudo apt -y install python2-dev python-dev-is-python3
sudo apt -y install python3.10-venv
sudo apt -y install seahorse
sudo apt -y install terminator
sudo apt -y install powershell
sudo apt -y install rlwrap
sudo apt -y install docker docker.io
sudo apt -y install ewf-tools
sudo apt -y install squidclient
sudo apt -y install sshuttle iptables
sudo apt -y install fcrackzip
sudo apt -y install pdfcrack
#Fish shell
sudo apt -y install fish
chsh -s $(which fish)

#Microsoft stuff
#CME apt install is usefull to obtain all the SMB modules
sudo apt -y install crackmapexec
sudo wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
sudo echo 'deb https://debian.neo4j.com stable 4.0' > /etc/apt/sources.list.d/neo4j.list
sudo apt update
sudo apt -y install apt-transport-https
sudo apt -y install neo4j
sudo apt -y install bloodhound
#Kerberos and NTLM
sudo apt install -y libkrb5-dev krb5-user libpam-krb5 libpam-ccreds gss-ntlmssp

if [ "$usage" = "ctf" ]; then
	#PWN stuff
	sudo apt -y install gdb
	sudo apt -y install gdbserver
	sudo apt -y install seclists
	sudo apt -y install qemu-user
	sudo apt -y install qemu-system
	sudo apt -y install gdb-multiarch
	sudo apt -y install patchelf

	#Crypto stuff
	sudo apt -y install zstd
	sudo apt -y install osslsigncode
	
	#Stego stuff
	sudo apt -y install steghide
fi

#Sublime Text
wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | sudo apt-key add -
echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list
sudo apt-get update
sudo apt-get install sublime-text


#pip packets
echo "ICAgICAgIF8gICAgICAgICAgICAKIF8gX18gKF8pXyBfXyAgICAgICAKfCAnXyBcfCB8ICdfIFwgICAgICAKfCB8XykgfCB8IHxfKSB8IF8gXyAKfCAuX18vfF98IC5fXyhffF98XykKfF98ICAgICB8X3wgICAgICAgICA=" |base64 -d
sleep 2
#Usefull stuff
pip install --upgrade setuptools
pip install dnspython
pip install pandas
pip install prettytable

#Microsoft stuff
pip install py2neo
pip install ldap3
pip install kerberos
pip install bloodhound
pip install aclpwn
pip install minikerberos
pip install kerberoast
pip install pypykatz
pip install roadrecon
pip install coercer
pip install masky

#Web stuff
pip install git+https://github.com/lobuhi/byp4xx.git
pip install pycryptodomex

if [ "$usage" = "ctf" ]; then
	#PWN stuff
	python2 -m pip install pwntools
	pip install pwntools
	pip install ropper
	pip install capstone
	pip install keystone-engine
	pip install filebytes

	#Crypto stuff
	python -m pip install pycrypto
	python -m pip install z3-solver
fi

echo "Update all pip packets"
for x in $(python2 -m pip list -o --format=columns | sed -n '3,$p' | cut -d' ' -f1); do python2 -m pip install $x --upgrade; done
for x in $(pip3 list -o --format=columns | sed -n '3,$p' | cut -d' ' -f1); do pip3 install $x --upgrade; done


#gem packages
echo "ICBfXyBfICBfX18gXyBfXyBfX18gICAgICAgIAogLyBfYCB8LyBfIFwgJ18gYCBfIFwgICAgICAgCnwgKF98IHwgIF9fLyB8IHwgfCB8IHxfIF8gXyAKIFxfXywgfFxfX198X3wgfF98IHxfKF98X3xfKQogfF9fXy8gICAgICAgICAgICAgICAgICAgICAg" |base64 -d
sleep 2
sudo gem install evil-winrm
sudo gem install one_gadget
sudo gem install wpscan


#go packages
echo "ICBfXyBfICBfX18gICAgICAgCiAvIF9gIHwvIF8gXCAgICAgIAp8IChffCB8IChfKSB8IF8gXyAKIFxfXywgfFxfX18oX3xffF8pCiB8X19fLyAgICAgICAgICAgIA==" |base64 -d
sleep 2
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
#ffuf installed by default on Kali now
go install github.com/OJ/gobuster/v3@latest
go install github.com/drk1wi/Modlishka@latest
#For ScarCrow
go install github.com/fatih/color@latest
go install github.com/yeka/zip@latest
go install github.com/josephspurrier/goversioninfo@latest
#For PEzor
go install github.com/EgeBalci/sgn@latest

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

#To get the last version of impacket
echo "Impacket"
pip3 uninstall impacket
sudo git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
python3 -m pip install -r requirements.txt
sudo python3 setup.py install
cd ..

echo "Recon tools"
sudo git clone https://github.com/ropnop/windapsearch.git
sudo git clone https://github.com/411Hall/JAWS.git
sudo git clone https://github.com/kaluche/bloodhound-quickwin.git
#Last CME binary to obtain the last modules
curl -s https://api.github.com/repos/Porchetta-Industries/CrackMapExec/releases/latest |grep "browser_download_url.*cme-ubuntu.*zip" | cut -d : -f 2,3 | tr -d \" | head -1 | wget -qi - -O cme.zip
sudo unzip cme.zip && sudo chmod 755 cme && sudo rm cme.zip
sudo git clone https://github.com/franc-pentest/ldeep.git
cd ldeep
python3 -m pip install -r requirements.txt
sudo python3 setup.py install
cd ..
# PrintNightmare scanner
sudo git clone https://github.com/byt3bl33d3r/ItWasAllADream
cd ItWasAllADream && docker build -t itwasalladream .
cd ..

echo "Brute Force tools"
curl -s https://api.github.com/repos/ropnop/kerbrute/releases/latest |grep "browser_download_url.*linux_amd64" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O kerbrute
sudo chmod 755 kerbrute
sudo git clone https://github.com/Greenwolf/Spray.git

echo "Relay/NTLM tools"
sudo git clone https://github.com/Tw1sm/RITM.git
cd RITM
sudo pip3 install .
cd ..
sudo wget https://gist.githubusercontent.com/3xocyte/cfaf8a34f76569a8251bde65fe69dccc/raw/7c7f09ea46eff4ede636f69c00c6dfef0541cd14/dementor.py -O dementor.py
sudo chmod 755 dementor.py
sudo git clone https://github.com/topotam/PetitPotam.git
sudo git clone https://github.com/evilmog/ntlmv1-multi.git
sudo git clone https://github.com/dirkjanm/mitm6.git
cd mitm6
python3 -m pip install -r requirements.txt
sudo python3 setup.py install
cd ..
sudo git clone https://github.com/Kevin-Robertson/Inveigh.git
sudo git clone https://github.com/dirkjanm/krbrelayx.git
sudo git clone https://github.com/Hackndo/WebclientServiceScanner.git
cd WebclientServiceScanner
sudo python3 setup.py install
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
cd ..

echo "Mimikatz"
sudo wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.7z -O mimikatz.7z
sudo wget https://github.com/gentilkiwi/kekeo/releases/download/2.2.0-20211214/kekeo.zip -O kekeo.zip

echo "ADCS tools"
sudo git clone https://github.com/dirkjanm/PKINITtools
cd PKINITtools
python3 -m pip install -r requirements.txt
cd ..
sudo git clone https://github.com/ly4k/Certipy.git
cd Certipy
sudo python3 setup.py install
cd ..

echo "Obfuscation tools"
sudo git clone https://github.com/CBHue/PyFuscation.git
sudo git clone https://github.com/Genetic-Malware/Ebowla.git
curl -s https://api.github.com/repos/optiv/ScareCrow/releases/latest |grep "browser_download_url.*linux_amd64" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O ScareCrow
sudo git clone https://github.com/phra/PEzor.git
cd PEzor
sudo bash install.sh
#Cause I'm using fish. Adapte this command to your shell solution
set -Ua fish_user_paths $fish_user_paths ~/go/bin/ /opt/Tools/Windows/PEzor /opt/Tools/Windows/PEzor/deps/donut/ /opt/Tools/Windows/PEzor/deps/wclang/_prefix_PEzor_/bin/
cd ..

echo "Specific tools : SQL/SCCM/WSUS/Backup"
sudo git clone https://github.com/NetSPI/PowerUpSQL.git
#Personal fork with CMScripts deployement (PR still open)
sudo git clone https://github.com/BlWasp/PowerSCCM.git
sudo git clone https://github.com/GoSecure/pywsus.git
sudo git clone https://github.com/giuliano108/SeBackupPrivilege.git

echo "Azure/ADFS tools"
#ADFSDump is in the SharpCollection repo
sudo git clone https://github.com/mandiant/ADFSpoof.git
cd ADFSpoof
python3 -m pip install -r requirements.txt
cd ..
sudo git clone https://github.com/Gerenios/AADInternals.git
sudo git clone https://github.com/LMGsec/o365creeper.git
sudo git clone https://github.com/morRubin/PrtToCert.git
cd PrtToCert
python3 -m pip install -r requirements.txt
cd ..
sudo git clone https://github.com/morRubin/AzureADJoinedMachinePTC.git
cd AzureADJoinedMachinePTC
python3 -m pip install -r requirements.txt
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
sudo git clone https://github.com/cube0x0/CVE-2021-1675.git
sudo git clone https://github.com/SecuraBV/CVE-2020-1472.git
# cd CVE-2020-1472
# python3 -m pip install -r requirements.txt
# cd ..


#Linux
cd ..
echo "ICAgX18gXyAgICAgICAgICAgICAgICAgICAgICAgIAogIC8gLyhfKV8gX18gIF8gICBfX18gIF9fICAgICAgCiAvIC8gfCB8ICdfIFx8IHwgfCBcIFwvIC8gICAgICAKLyAvX198IHwgfCB8IHwgfF98IHw+ICA8IF8gXyBfIApcX19fXy9ffF98IHxffFxfXyxfL18vXF8oX3xffF8pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA=" |base64 -d
sleep 2
sudo mkdir Linux
cd Linux
sudo wget https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar -O yso.jar
sudo wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 -O pspy32
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
sudo git clone git@github.com:dolevf/graphw00f.git
sudo git clone https://github.com/arthaud/git-dumper.git
sudo git clone https://github.com/mxrch/webwrap.git
sudo git clone https://github.com/WhiteWinterWolf/wwwolf-php-webshell.git
sudo git clone https://github.com/epinna/tplmap.git
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
	sudo wget http://didierstevens.com/files/software/XORSearch_V1_11_3.zip -O XORSearch.zip
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
sudo mkdir Android
cd Android
sudo git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
./setup.sh
cd ..


#General tools
cd ..
echo "ICAgX19fICAgICAgICAgICAgICAgICAgICAgICAgICBfICAgXyAgICAgICAgICAgICAgXyAgICAgICAgICAgCiAgLyBfIFxfX18gXyBfXyAgIF9fXyBfIF9fIF9fIF98IHwgfCB8XyBfX18gICBfX18gfCB8X19fICAgICAgIAogLyAvX1wvIF8gXCAnXyBcIC8gXyBcICdfXy8gX2AgfCB8IHwgX18vIF8gXCAvIF8gXHwgLyBfX3wgICAgICAKLyAvX1xcICBfXy8gfCB8IHwgIF9fLyB8IHwgKF98IHwgfCB8IHx8IChfKSB8IChfKSB8IFxfXyBcXyBfIF8gClxfX19fL1xfX198X3wgfF98XF9fX3xffCAgXF9fLF98X3wgIFxfX1xfX18vIFxfX18vfF98X19fKF98X3xfKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA=" |base64 -d
sleep 2
sudo git clone https://github.com/RUB-NDS/PRET.git
sudo mkdir Chisel
cd Chisel
curl -s https://api.github.com/repos/jpillora/chisel/releases/latest |grep "browser_download_url.*windows_amd64.gz" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O chiselWin.gz
curl -s https://api.github.com/repos/jpillora/chisel/releases/latest |grep "browser_download_url.*linux_amd64.gz" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O chiselLinux.gz
sudo gunzip -d chiselWin.gz
sudo gunzip -d chiselLinux.gz
sudo chmod 755 chiselLinux
cd ..
#PEASS scripts and binaries
sudo mkdir PEASS
cd PEASS
curl -s https://api.github.com/repos/carlospolop/peass-ng/releases/latest |grep "browser_download_url.*linpeas.sh" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O linpeas.sh
curl -s https://api.github.com/repos/carlospolop/peass-ng/releases/latest |grep "browser_download_url.*winPEAS.bat" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O winPEAS.bat
curl -s https://api.github.com/repos/carlospolop/peass-ng/releases/latest |grep "browser_download_url.*winPEASany.exe" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O winPEASany.exe
curl -s https://api.github.com/repos/carlospolop/peass-ng/releases/latest |grep "browser_download_url.*winPEASx64.exe" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O winPEASx64.exe
curl -s https://api.github.com/repos/carlospolop/peass-ng/releases/latest |grep "browser_download_url.*winPEASx86.exe" | cut -d : -f 2,3 | tr -d \" | sudo wget -qi - -O winPEASx86.exe
cd ..
sudo git clone https://github.com/andrew-d/static-binaries.git
sudo git clone --recurse-submodules https://github.com/xct/xc.git
sudo sudo chown -R $username:$username xc/
cd xc
GO111MODULE=off go get golang.org/x/sys/...
GO111MODULE=off go get golang.org/x/text/encoding/unicode
GO111MODULE=off go get github.com/hashicorp/yamux
GO111MODULE=off go get github.com/libp2p/go-reuseport
python3 build.py
cd ..


sudo chown -R $username:$username /opt/Tools
sudo chmod -R 755 /opt/Tools


#ropstar (TODO : verify validity after XCT's installation modifications)
#echo "ICAgICAgICAgICAgICAgICAgICAgXyAgICAgICAgICAgICAgICAKIF8gX18gX19fICBfIF9fICBfX198IHxfIF9fIF8gXyBfXyAgICAKfCAnX18vIF8gXHwgJ18gXC8gX198IF9fLyBfYCB8ICdfX3wgICAKfCB8IHwgKF8pIHwgfF8pIFxfXyBcIHx8IChffCB8IHxfIF8gXyAKfF98ICBcX19fL3wgLl9fL3xfX18vXF9fXF9fLF98XyhffF98XykKICAgICAgICAgIHxffCAgICAgICAgICAgICAgICAgICAgICAgICA=" |base64 -d
#sleep 2
#cd
#git clone https://github.com/BlWasp/setupRopstar.git
#cd setupRopstar
#chmod +x ./setup.sh
#./setup.sh


#gef
echo "ICAgICAgICAgICAgIF9fICAgICAgCiAgX18gXyAgX19fIC8gX3wgICAgIAogLyBfYCB8LyBfIFwgfF8gICAgICAKfCAoX3wgfCAgX18vICBffCBfIF8gCiBcX18sIHxcX19ffF98KF98X3xfKQogfF9fXy8gICAgICAgICAgICAgICA=" |base64 -d
cd
sleep 2
wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py
echo source ~/.gdbinit-gef.py >> ~/.gdbinit
