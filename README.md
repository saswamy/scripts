# scripts


1) to add NSG rules to 1 or more NSGs  - create a file "/tmp/ip.txt" below format . 

1.1)
INGRESS:<Description>:CIDR-Addr:Port
EGRESS:<Description>:CIDR-Addr:Port
INGRESS: RFC 3-DG05HAG Ingress from customer CIDR 147.154.0.0/19 for soadev pub LB on 443 :147.154.0.0/19:443

1.2) 
In code : Uncomment code 
	add_nsg_rules_per_nsg_wrapper(nsg_list_multiple)
1.3) 
In code provide list of NSG names --- case insensitive 
E.g: 
	nsg_list_multiple=['NSG-DR-DESJCTMPR2ODR-PvtLBAAS001','NSG-DR-DESJCTMPRDODR-PvtLBAAS001']  

1.4) run 
	python nsg_manage.py

2) to delete Rules 
	2 steps process ---- 
	step-1) run code to get all rules for specified NSG into file "/tmp/1_build_delete"
	    	- In code provide list of NSG names --- case insensitive
		- uncomment and run code below 
			build_delete_nsg_rules(nsg_list_multiple)
	step-2) based on "/tmp/1_build_delete" prepare file "/tmp/delete.txt" in below format 

e.g :  /tmp/delete.txt
NSG-Prod-PROTWCIPRDNDR-DB:45E297
NSG-Prod-PROTWCIPRD-PvtMT:B7D016
NSG-Prod-PROTWCIPRD-PvtMT:F22446
	        - In code provide list of NSG names --- case insensitive
		- Uncomment and run code below to delete 
			delete_nsg_rules()	
