#!/bin/bash

sudo su

echo "Environement installation"
apt -y install golang
apt -y install gem
apt -y install python-pip
apt -y install python3-pip


echo "Software installation"
echo "apt..."
#apt -y install crackmapexec
apt -y install docker docker.io
apt -y install gdb
apt -y install gdbserver
apt -y install seclists
apt -y install terminator
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable 4.0' > /etc/apt/sources.list.d/neo4j.list
apt update
apt -y install apt-transport-https
apt -y install neo4j
apt -y install bloodhound
apt -y install patchelf
apt -y install fcrackzip
apt -y install steghide
apt -y install pdfcrack
apt -y install qemu
apt -y install qemu-user
apt -y install qemu-system
apt -y install gdb-multiarch
apt -y install volatility
apt -y install rlwrap
apt -y install libgmp3-dev libmpc-dev

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
exit
go get github.com/ffuf/ffuf
go get github.com/OJ/gobuster

#echo "docker http3..."
#docker run -it --rm ymuski/curl-http3 curl -ILv https://10.10.10.186/ --http3

sudo su
echo "Scripts installation"
mkdir /opt/Tools
cd /opt/Tools

echo "Windows..."
mkdir Windows
cd Windows
mkdir SharpHound
wget https://github.com/BloodHoundAD/BloodHound/raw/master/Ingestors/SharpHound.exe -O SharpHound/SharpHound.exe
wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1 -O SharpHound/SharpHound.ps1
git clone https://github.com/ropnop/windapsearch.git
git clone https://github.com/PowerShellMafia/PowerSploit.git
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O kerbrute
chmod 755 kerbrute
git clone https://github.com/CBHue/PyFuscation.git

cd ..
echo "Linux..."
mkdir Linux
cd Linux
wget https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar -O yso.jar
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 -O pspy32
wget https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.jar -O jd-gui.jar

cd ..
echo "Web..."
mkdir Web
cd Web
git clone https://github.com/WhiteWinterWolf/wwwolf-php-webshell.git
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make -j
cd ..
git clone https://github.com/AonCyberLabs/PadBuster.git
git clone https://github.com/ticarpi/jwt_tool
pip3 install pycryptodomex

cd ..
echo "Crypto..."
mkdir Crypto
cd Crypto
git clone https://github.com/Ganapati/RsaCtfTool.git
cd RsaCtfTool
pip3 install -r "requirements.txt"
cd ..

cd ..
echo "Stego..."
mkdir Stego
cd Stego
git clone https://github.com/Va5c0/Steghide-Brute-Force-Tool.git
mkdir stegsolve
cd stegsolve
wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
cd ..
#For stego docker futur use
mkdir data
service docker start
docker pull dominicbreuker/stego-toolkit


cd ..
echo "PWN..."
mkdir pwn
cd pwn
git clone https://github.com/Diefunction/Canary.git
git clone https://github.com/sashs/ropper.git
cd ropper
git submodule init
git submodule update
cd ..


cd ..
mkdir Chisel
cd Chisel
wget https://github.com/jpillora/chisel/releases/download/v1.4.0/chisel_1.4.0_windows_386.gz -O chiselWin.gz
wget https://github.com/jpillora/chisel/releases/download/v1.4.0/chisel_1.4.0_linux_386.gz -O chiselLinux.gz
gunzip -d chiselWin.gz
gunzip -d chiselLinux.gz
chmod 755 chiselLinux
cd ..
git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git
mkdir XORSearch
cd XORSearch
wget http://didierstevens.com/files/software/XORSearch_V1_11_3.zip -O XORSearch.zip
unzip XORSearch.zip
rm XORSearch.zip
cd ..

chmod -R 755 /opt/Tools


echo "ropstar..."
exit
cd
mkdir tools
cd tools
git clone https://github.com/JonathanSalwan/ROPgadget.git
git clone https://github.com/niklasb/libc-database.git
cd libc-database
./get
cd ..
git clone https://github.com/xct/ropstar.git
cd ropstar
pip3 install -r requirements.txt
cd ..

LIBCDATABASE_DIR=~/tools/libc-database/
LINK_NAME=libc.so.6

for libname in $(ls ${LIBCDATABASE_DIR}/db/*.so); do
	if [[ ! -d ${LIBCDATABASE_DIR}/libs/$(basename "${libname%.*}") ]];then
		mkdir ${LIBCDATABASE_DIR}/libs/$(basename "${libname%.*}")
	fi
    if [[ ! -L ${LIBCDATABASE_DIR}/libs/$(basename "${libname%.*}")/${LINK_NAME} || ! -f ${LIBCDATABASE_DIR}/libs/$(basename "${libname%.*}")/${LINK_NAME} ]]; then
        ln -s $(realpath ${libname}) ${LIBCDATABASE_DIR}/libs/$(basename "${libname%.*}")/${LINK_NAME}
    fi  
done


echo "gef..."
cd
wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py
echo source ~/.gdbinit-gef.py >> ~/.gdbinit
