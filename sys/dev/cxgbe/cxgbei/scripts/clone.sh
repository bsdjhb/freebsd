#!/bin/sh
#setenv ASSUME_ALWAYS_YES yes
export ASSUME_ALWAYS_YES=yes
pkg install mercurial
pkg install screen
pkg install netserver
pkg install netperf
pkg install vim

ls /usr/bin/vi_orig
if [ "$?" == 1 ]
then
cp /usr/bin/vi /usr/bin/vi_orig
fi
cp /usr/local/bin/vim /usr/bin/vi
cp /usr/local/share/vim/vim74/vimrc_example.vim ~/.vimrc
echo "set mouse-=a
color desert
if &diff
    colorscheme evening
set cc=81
set tags=tags
set cursorline
set hlsearch
set viminfo='20,<1000
endif" >>~/.vimrc
echo alias vi='vim'>> ~/.profile
cp /usr/local/bin/vim /usr/bin/vi

( echo search asicdesigners.com ; echo nameserver 10.193.180.20 ; echo nameserver 10.192.160.5 ) >> /etc/resolv.conf

( echo WITH_OFED='yes' ) >>/etc/src.conf

#dont know why for 9600 (in bios, and in netcosole) is only working for now.....(echo comconsole_speed="115200"; => add this below)
( echo boot_multicons="YES"; echo boot_serial="YES";echo console="\"vidconsole,comconsole\"" ) >> /boot/loader.conf


#bash installation
pkg install bash
echo "fdesc  /dev/fd    fdescfs  rw    0  0" >> /etc/fstab
chsh -s /usr/local/bin/bash root
( echo export VISUAL=vim; echo export EDITOR="$VISUAL" ) >> ~/.bashrc
cp /usr/local/bin/vim /usr/bin/vi

mv /usr/src /usr/src_bkp
hg clone http://10.193.184.119/hg/freebsd/base /usr/src

