#!/bin/sh
#rm *.b64.txt
python c3main.py makesignerselfsigned --name=root2
python c3main.py makesignerusingsignerappended --name=inter7 --using=root2
python c3main.py signpayload --name=payload.txt --using=inter7
