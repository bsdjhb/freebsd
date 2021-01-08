mv /root/buildresult.txt /root/buildresult_bkp.txt
cd /usr/src/
rm /usr/src/sys/amd64/conf/MYKERNEL

#Kernel configuration file:
#add or delete any kernel configurable options here, instead
#of adding directly to /usr/src/sys/amd64/conf/MYKERNEL.
#This is because there is chance of custom config file
#getting removed while "hg pull -C"
#------------------------------------------------------
perl -i -pe 's/DEBUG\=\-g/DEBUG\=\"\-g \-O0\"/g' /usr/src/sys/amd64/conf/GENERIC

echo "include GENERIC
ident MYKERNEL
 
# KTR support----> cxgbe driver uses KTR_SPARE3 for KTR traces
options         KTR
options         KTR_COMPILE=KTR_SPARE3
options         KTR_MASK=KTR_SPARE3
options         KTR_ENTRIES=165536

#Below allocates more kernel space as we increased stack pages, lesser number may result in stack overflow
options         KSTACK_PAGES=16

#Frequently used options
#options        NUMA
#nooptions      VIMAGE
#options        RATELIMIT

 
# DDB for serial----> To break to ddb, Ctrl+Alt+Esc  (or) Ctrl+z  => to manually break into ddb prompt(kernel will freeze)
options         BREAK_TO_DEBUGGER" > /usr/src/sys/amd64/conf/MYKERNEL

#To build RDMA sourcecode(both kernel and userspace):
#--------------
grep "WITH_OFED=yes" /etc/src.conf
if [ "$?" != 0 ]
then
echo "Adding 'WITH_OFED=yes' in /etc/src.conf"
echo "WITH_OFED=yes" >> /etc/src.conf
fi

#build world
#--------------
if [ "$1" == "world" ]
then
echo "building World:make  buildworld   " >/root/buildresult.txt
make -j8 buildworld
if [ "$?" != 0 ]
then
echo "error while building:make  buildworld  " >/root/buildresult.txt
exit
fi
echo "make  buildworld          =>completed successfully  " >/root/buildresult.txt
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
echo "error while building:make buildkernel -DNO_KERNELCLEAN " >/root/buildresult.txt
exit
fi
echo "make buildkernel -DNO_KERNELCLEAN         =>completed successfully" >/root/buildresult.txt

#install kernel
#--------------
make installkernel KERNCONF=MYKERNEL
if [ "$?" != 0 ]
then
echo "error while building:make installkernel" >/root/buildresult.txt
exit
fi
#install world
#--------------
if [ "$1" == "world" ]
then
#Keep /etc config in sync with the kernel+world
etcupdate -p
make installworld
if [ "$?" != 0 ]
then
echo "error while building:make installworld " >/root/buildresult.txt
exit
fi
fi 


echo "Build successfull" > /root/buildresult.txt

#Reboot such that the installed binaries will take effect
#shutdown -r now
