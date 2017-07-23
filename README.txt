This source file is RaSCSI Ethernet driver for NetBSD.
Originally this is made for connecting X68030 to net without using Nereid.

There are 2 files,  "if_ras.c" is source and "scsi_ras_ether.h" is headerfile.
These source is modified from if_se.c, SCSI ethernet driver conteined in 
source tree of NetBSD.

To use this, Locate these 2files into /usr/src/sys/dev/scsipi  directory.


2017/07/13 JR9QNJ/h-fujita 

How to compile with if_ras.c

----------------------------------------------------------------------------------------
To compile if_ras.c, add following 3 lines into  /usr/src/sys/dev/scsipifiles.scsipi.

--------------
device  ras: ifnet, ether, arp
attach  ras at scsibus
file    dev/scsipi/if_ras.c             ras                     needs-flag
--------------


And copy /usr/src/sys/arch/x68k/conf/GENERC to /usr/src/sys/arch/x68k/conf/RASCSI.
then add following these lines

----------
ras*  at scsibus? target ? lun ?      # SCSI ETH
----------




