# Nemesis

## Why ?

Kali is good, but did you find everything you were looking for in it ? This script permits to install some very usefull tools on a Kali machine which are missing by default and yet essential.

It is essentially based on my Hack The Box, certifications, and pentest experiences, and it is non-exhaustive.

## How ?

Just run `./setup.sh`.

At the beginning of the install, the script will ask for `pentest/ctf` : 

* **pentest** will only install the tools and libraries that are usefull in real life engagements. Flameshot and wireless attacks tools will be also added
* **ctf** will install everything with stuff for PWN, crypto, forensics, and so on. Flameshot and wireless tools will be skipped

I will update it regularly when I discover new tools.

## Future

If you don't want to use some tools, you just have to comment the lines.

Feel free to pull request some new tools !
