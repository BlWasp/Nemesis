#!/bin/bash

echo "Enter the user who will use this installation"
read username

echo "Environement installation"
sudo apt -y install golang
sudo apt -y install gem
sudo apt -y install python-pip
python -m pip install --upgrade pip
sudo apt -y install python3-pip
python3 -m pip install --upgrade pip

echo "Update all pip packets"
for x in $(pip list -o --format=columns | sed -n '3,$p' | cut -d' ' -f1); do pip install $x --upgrade; done
for x in $(pip3 list -o --format=columns | sed -n '3,$p' | cut -d' ' -f1); do pip3 install $x --upgrade; done


echo "Software installation"
echo "apt..."
#apt -y install crackmapexec
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

echo "pip..."
pip install pwntools
pip3 install pwntools
pip install ldap3
pip install dnspython
pip install impacket
pip install bloodhound
pip install aclpwn
pip install capstone
pip install filebytes
pip3 install keystone-engine
pip install ropper
pip3 install z3-solver

echo "gem..."
gem install evil-winrm

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
sudo git clone https://github.com/ropnop/windapsearch.git
sudo git clone https://github.com/PowerShellMafia/PowerSploit.git
sudo wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O kerbrute
sudo chmod 755 kerbrute
sudo git clone https://github.com/CBHue/PyFuscation.git
sudo git clone https://github.com/giuliano108/SeBackupPrivilege.git

cd ..
echo "Linux..."
sudo mkdir Linux
cd Linux
sudo wget https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar -O yso.jar
sudo wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 -O pspy32
sudo wget https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.jar -O jd-gui.jar

cd ..
echo "Web..."
sudo mkdir Web
cd Web
sudo git clone https://github.com/WhiteWinterWolf/wwwolf-php-webshell.git
sudo git clone https://github.com/robertdavidgraham/masscan
sudo cd masscan
sudo make -j
cd ..
sudo git clone https://github.com/AonCyberLabs/PadBuster.git
sudo git clone https://github.com/ticarpi/jwt_tool
pip3 install pycryptodomex
sudo git clone https://github.com/arthaud/git-dumper.git

cd ..
echo "Crypto..."
sudo mkdir Crypto
cd Crypto
sudo git clone https://github.com/Ganapati/RsaCtfTool.git
cd RsaCtfTool
pip3 install -r "requirements.txt"
cd ..
sudo wget https://github.com/nccgroup/featherduster/archive/v0.2.zip -O feather.zip
unzip feather.zip
rm feather.zip
cd featherduster-0.2
python setup.py install
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
