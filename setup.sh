#!/bin/bash

echo "Enter the user who will use this installation"
read username

echo "Environement installation"
sudo apt -y install golang
sudo apt -y install gem
#sudo apt -y install python-pip
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
python -m pip install --upgrade pip
sudo apt -y install python3-pip
python3 -m pip install --upgrade pip

echo "Update all pip packets"
for x in $(pip list -o --format=columns | sed -n '3,$p' | cut -d' ' -f1); do pip install $x --upgrade; done
for x in $(pip3 list -o --format=columns | sed -n '3,$p' | cut -d' ' -f1); do pip3 install $x --upgrade; done


echo "Software installation"
echo "apt..."
#apt -y install crackmapexec
sudo apt -y install python-dev
sudo apt -y install docker docker.io
sudo apt -y install gdb
sudo apt -y install gdbserver
sudo apt -y install seclists
sudo apt -y install terminator
sudo wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
sudo echo 'deb https://debian.neo4j.com stable 4.0' > /etc/apt/sources.list.d/neo4j.list
sudo apt update
sudo apt -y install apt-transport-https
sudo apt -y install neo4j
sudo apt -y install bloodhound
sudo apt -y install patchelf
sudo apt -y install fcrackzip
sudo apt -y install steghide
sudo apt -y install pdfcrack
sudo apt -y install qemu
sudo apt -y install qemu-user
sudo apt -y install qemu-system
sudo apt -y install gdb-multiarch
sudo apt -y install volatility
sudo apt -y install rlwrap
sudo apt -y install libgmp3-dev libmpc-dev
sudo apt -y install seahorse
sudo apt -y install powershell

sudo apt -y install fish
sudo chsh -s /usr/bin/fish
#sudo apt install sshuttle iptables

echo "pip..."
python -m pip install pycrypto
python -m pip install pwntools
python3 -m pip install pwntools
python -m pip install ldap3
python -m pip install dnspython
python -m pip install impacket
python -m pip install bloodhound
python -m pip install aclpwn
python -m pip install capstone
python -m pip install filebytes
python3 -m pip install keystone-engine
python -m pip install ropper
python3 -m pip install z3-solver
sudo python -m pip install sshuttle

echo "gem..."
sudo gem install evil-winrm
sudo gem install one_gadget

echo "go..."
go get github.com/ffuf/ffuf
go get github.com/OJ/gobuster

#echo "docker http3..."
#docker run -it --rm ymuski/curl-http3 curl -ILv https://10.10.10.186/ --http3

echo "Scripts installation"
sudo mkdir /opt/Tools
cd /opt/Tools

echo "Windows..."
sudo mkdir Windows
cd Windows
sudo mkdir SharpHound
sudo wget https://github.com/BloodHoundAD/BloodHound/raw/master/Ingestors/SharpHound.exe -O SharpHound/SharpHound.exe
sudo wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1 -O SharpHound/SharpHound.ps1
sudo wget https://github.com/byt3bl33d3r/CrackMapExec/releases/download/v5.0.2dev/cme-ubuntu-latest.zip -O cme.zip
sudo unzip cme.zip
sudo rm cme.zip
sudo git clone https://github.com/ropnop/windapsearch.git
sudo git clone https://github.com/PowerShellMafia/PowerSploit.git -b dev
sudo wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O kerbrute
sudo chmod 755 kerbrute
sudo git clone https://github.com/CBHue/PyFuscation.git
sudo git clone https://github.com/giuliano108/SeBackupPrivilege.git
sudo git clone https://github.com/Genetic-Malware/Ebowla.git
sudo wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe -O JuicyPotato.exe
sudo git clone https://github.com/Kevin-Robertson/Powermad.git
sudo wget https://gist.githubusercontent.com/3xocyte/cfaf8a34f76569a8251bde65fe69dccc/raw/7c7f09ea46eff4ede636f69c00c6dfef0541cd14/dementor.py -O dementor.py
sudo chmod 755 dementor.py
sudo git clone https://github.com/evilmog/ntlmv1-multi.git
sudo git clone https://github.com/411Hall/JAWS.git
sudo git clone https://github.com/Greenwolf/Spray.git

cd ..
echo "Linux..."
sudo mkdir Linux
cd Linux
sudo wget https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar -O yso.jar
sudo wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 -O pspy32
sudo wget https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.jar -O jd-gui.jar
sudo git clone https://github.com/mxrch/snmp-shell.git

cd ..
echo "Web..."
sudo mkdir Web
cd Web
sudo git clone https://github.com/WhiteWinterWolf/wwwolf-php-webshell.git
sudo git clone https://github.com/robertdavidgraham/masscan
cd masscan
sudo make -j
cd ..
sudo git clone https://github.com/AonCyberLabs/PadBuster.git
sudo git clone https://github.com/ticarpi/jwt_tool
pip3 install pycryptodomex
sudo git clone https://github.com/arthaud/git-dumper.git
sudo git clone https://github.com/mxrch/webwrap.git
sudo git clone https://github.com/epinna/tplmap.git
sudo git clone https://github.com/cnotin/SplunkWhisperer2.git

cd ..
echo "Crypto..."
sudo mkdir Crypto
cd Crypto
sudo git clone https://github.com/Ganapati/RsaCtfTool.git
cd RsaCtfTool
pip3 install -r "requirements.txt"
cd ..
sudo wget https://github.com/nccgroup/featherduster/archive/v0.2.zip -O feather.zip
sudo unzip feather.zip
rm feather.zip
cd featherduster-0.2
sudo python3 setup.py install
cd ..

cd ..
echo "Stego..."
sudo mkdir Stego
cd Stego
sudo git clone https://github.com/Va5c0/Steghide-Brute-Force-Tool.git
sudo mkdir stegsolve
cd stegsolve
sudo wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
cd ..
#For stego docker futur use
sudo mkdir data
sudo service docker start
sudo docker pull dominicbreuker/stego-toolkit


cd ..
echo "PWN..."
sudo mkdir pwn
cd pwn
sudo git clone https://github.com/Diefunction/Canary.git
sudo git clone https://github.com/sashs/ropper.git
cd ropper
sudo git submodule init
sudo git submodule update
cd ..


cd ..
echo "General tools..."
sudo git clone https://github.com/RUB-NDS/PRET.git
sudo mkdir Chisel
cd Chisel
sudo wget https://github.com/jpillora/chisel/releases/download/v1.4.0/chisel_1.4.0_windows_386.gz -O chiselWin.gz
sudo wget https://github.com/jpillora/chisel/releases/download/v1.4.0/chisel_1.4.0_linux_386.gz -O chiselLinux.gz
sudo gunzip -d chiselWin.gz
sudo gunzip -d chiselLinux.gz
sudo chmod 755 chiselLinux
cd ..
sudo git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git
sudo git clone https://github.com/andrew-d/static-binaries.git
sudo mkdir XORSearch
cd XORSearch
sudo wget http://didierstevens.com/files/software/XORSearch_V1_11_3.zip -O XORSearch.zip
sudo unzip XORSearch.zip
sudo rm XORSearch.zip
cd ..
sudo git clone https://github.com/xct/xc.git
cd xc
go get golang.org/x/sys/windows
go get golang.org/x/text/encoding/unicode
go get github.com/hashicorp/yamux
go get github.com/ropnop/go-clr
make
go build
cd ..


sudo chown -R $username:$username /opt/Tools
sudo chmod -R 755 /opt/Tools


echo "ropstar..."
cd
git clone https://github.com/BlWasp/setupRopstar.git
cd setupRopstar
chmod +x ./setup.sh
./setup.sh


echo "gef..."
cd
wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py
echo source ~/.gdbinit-gef.py >> ~/.gdbinit
