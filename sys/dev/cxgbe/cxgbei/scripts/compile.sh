#"world" as an argument will build user and kernel.
#"ckern" as an argument will build only kernel. CLEAN build.
#Without any argument, it will build only kernel. Will build only the changes. No clean build. 

mv bo bo_bkp
cd /usr/src/
rm /usr/src/sys/amd64/conf/MYKERNEL

perl -i -pe 's/DEBUG\=\-g/DEBUG\=\"\-g \-O0\"/g' /usr/src/sys/amd64/conf/GENERIC

echo "include GENERIC
ident MYKERNEL

nooptions       VIMAGE
#for BPF jitter support
options         BPF_JITTER
# KTR suport----> For KTR traces support
options         KTR
options         KTR_COMPILE=KTR_SPARE3
options         KTR_MASK=KTR_SPARE3
options         KTR_ENTRIES=165536

options         KSTACK_PAGES=16
options         RATELIMIT
# DDB for serial----> To break to ddb
options         BREAK_TO_DEBUGGER" > /usr/src/sys/amd64/conf/MYKERNEL

#build wrold
#--------------
if [ "$1" == "world" ]
then
make -j8 buildworld
if [ "$?" != 0 ]
then
echo "error while building:make  buildworld                " >/root/bo
exit
fi
echo "success building:make  buildworld                " >/root/bo
fi

#build kernel
#--------------
if [ "$1" == "world" ] || [ "$1" == "ckern" ]
then
make -j8 buildkernel KERNCONF=MYKERNEL
else
make -j8 buildkernel -DNO_KERNELCLEAN KERNCONF=MYKERNEL
fi
if [ "$?" != 0 ]
then
echo "error while building:make buildkernel -DNO_KERNELCLEAN " >/root/bo
exit
fi
echo "success building:make buildkernel -DNO_KERNELCLEAN " >/root/bo

#install kernel
#--------------
make installkernel KERNCONF=MYKERNEL
if [ "$?" != 0 ]
then
echo "error while building:make installkernel" >/root/bo
exit
fi

#install world
#--------------
if [ "$1" == "world" ]
then
make installworld
if [ "$?" != 0 ]
then
echo "error while building:make installworld               " >/root/bo
exit
fi
fi


echo "Build successfull" > /root/bo


#check for rping latest binary available
#check for cxgbetool latest binary available
shutdown -r now
