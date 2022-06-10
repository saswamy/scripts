# scripts

Add Rules
-----------
1. Inside code - 
        Update "nsg_list_multiple" with your NSG name (case insensitive) 
	e.g: 
	        "nsg_list_multiple"=['NSG-DR-DESJCTMPR2ODR-PvtLBAAS001','NSG-DR-DESJCTMPRDODR-PvtLBAAS001']

2. create a file “/tmp/ip.txt” below format .
	e.g: 
	INGRESS: RFC 3-DG05HAG Ingress from customer CIDR 147.154.0.0/19 for soadev pub LB on 443 :147.154.0.0/19:443
	INGRESS:<Description>:CIDR-Addr:Port
	EGRESS:<Description>:CIDR-Addr:Port

3. Uncomment add_nsg_rules_per_nsg_wrapper(nsg_list_multiple)
4) run 
	python nsg_manage.py


Delete Rules Steps:
-------------------—
1. Inside code - 
	Update "nsg_list_multiple" with your NSG name (case insensitive) and uncomment/run with "build_delete_nsg_rules"("nsg_list_multiple")
2. Review output from Step 1
3. Comment "build_delete_nsg_rules"("nsg_list_multiple")
4. Based on info from Step-3 output file ( "/tmp/1_build_delete*)- Create /tmp/delete.txt as per example below 
	e.g :  /tmp/delete.txt
	NSG-Prod-PROTWCIPRDNDR-DB:45E297
	NSG-Prod-PROTWCIPRD-PvtMT:B7D016
	NSG-Prod-PROTWCIPRD-PvtMT:F22446
5. In Code - Uncomment delete_nsg_rules()
6. run python3 nsg_manage.py
