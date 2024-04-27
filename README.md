# Nemesis

## Why ?

Kali is good, but did you find everything you were looking for in it ? This script permits to install some very usefull tools on a Kali machine which are missing by default and yet essential.

It is essentially based on my Hack The Box, certifications, and pentest experiences, and it is non-exhaustive.

## How ?

Just run `./setup.sh`.

At the beginning of the install, the script will ask for `pentest/ctf` : 

* **pentest** will only install the tools and libraries that are usefull in real life engagements. Flameshot and wireless attacks tools will be also added
* **ctf** will install everything with stuff for PWN, crypto, forensics, and so on. Flameshot and wireless tools will be skipped

If you don't want to use some tools, you just have to comment the lines.

**BloodHound CE won't be installed** because the docker installation never returns the hand and blocks the rest of the script (and the initial password is lost somewhere in the infinite output). Think about installing it manually when this script will finish: `curl -L https://ghst.ly/getbhce | sudo docker compose -f - up`

Additionally, think about cloning and compiling [CoercedPotato](https://github.com/Prepouce/CoercedPotato) manually, the best potato!

## Future

I will update it regularly when I discover new tools.

Feel free to pull request some new tools !
