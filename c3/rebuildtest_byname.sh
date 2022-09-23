#!/bin/sh
# rm *.b64.txt
#python c3main.py makesignerselfsigned --name=root1
python c3main.py makesignerusingsignerbyname --name=inter3 --using=root1
python c3main.py signpayload --name=payload.txt --using=inter3
