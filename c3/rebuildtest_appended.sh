#!/bin/sh
#rm *.b64.txt
python c3main.py makesignerselfsigned --name=root3  --using=self
python c3main.py makesignerusingsignerappended --name=inter8 --using=root3
python c3main.py signpayload --name=payload2.txt --using=inter8
