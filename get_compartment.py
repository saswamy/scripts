
import oci
import datetime

from oci.config import from_file
from oci.config import validate_config




def get_tenancy_info(config):
    validate_config(config)
    print('Hello world - 1 ')
    print(config)
    tenant_id=config['tenancy']
#    print('Hello world - 1 '+ str(tenant_id))
    return(tenant_id)

def get_identity_info(config):
    print('Hello world - 2 ')
    identity = oci.identity.IdentityClient(config)
    user = identity.get_user(config["user"]).data
    root_id = user.compartment_id
    print(root_id)
    return(identity)

def list_all_compartments(config):
    list_compartments = oci.pagination.list_call_get_all_results(get_identity_info(config).list_compartments,
                                                                 get_tenancy_info(config)).data
    for compt_name in list_compartments:
        print(compt_name.name)
    return(list_compartments)


def get_compartment_id(list_compartments,find_compartment):
    for compt_name in list_compartments:
        if compt_name.name.upper() == find_compartment.upper():
            print("In function ..." +compt_name.name.upper())
            print(compt_name)
    return(compt_name.id)


def get_nsg_all(core_client,find_compartment_id):
#    core_client = oci.core.VirtualNetworkClient(config)

    list_network_security_groups_response = core_client.list_network_security_groups(
        compartment_id=str(find_compartment_id))
    print("nsg id type : " + str(type(list_network_security_groups_response)))
    print("nsg id type : " + str(type(list_network_security_groups_response.data)))
#    print(list_network_security_groups_response.data)

#    nsg_name_list=[]
    for nsg_data in list_network_security_groups_response.data:
        print('NSG - OCID : ' + nsg_data.id + ' ---> : ' + nsg_data.display_name)
#        if 'FTG' in nsg_data.display_name:
#                print('NSG - OCID : ' + nsg_data.id + ' ---> : ' + nsg_data.display_name)
    #    nsg_name_list.append(nsg_data.display_name)
    #
    #    print(nsg_name_list)
    #    print(type(nsg_name_list))
#    print("','".join(nsg_name_list))

def get_nsg_matching_all_list(nsg_list_check):
    #core_client = oci.core.VirtualNetworkClient(config)

    list_network_security_groups_response = core_client.list_network_security_groups(
        compartment_id=str(find_compartment_id))
#    print("nsg id type : " + str(type(list_network_security_groups_response)))
    #    print("nsg id type : " + str(type(list_network_security_groups_response.data)))
    #    print(list_network_security_groups_response.data)

    nsg_all_list_of_dict=[]

    while True:
        for nsg_data in list_network_security_groups_response.data:
            if nsg_data.display_name.lower() in nsg_list_check:
                nsg_all_list_of_dict.append({ 'name':nsg_data.display_name , 'ocid':nsg_data.id})
#            return(nsg_data.id)
        if 'opc-next-page' not in list_network_security_groups_response.headers:
            break
        page_val = list_network_security_groups_response.headers['opc-next-page']
        list_network_security_groups_response = core_client.list_network_security_groups(compartment_id=str(find_compartment_id), page=page_val)


    print(nsg_all_list_of_dict)
    return(nsg_all_list_of_dict)


def get_nsg_specific_id(core_client,find_compartment_id,nsg_list_check):
    #core_client = oci.core.VirtualNetworkClient(config)

    list_network_security_groups_response = core_client.list_network_security_groups(
        compartment_id=str(find_compartment_id))
#    print("nsg id type : " + str(type(list_network_security_groups_response)))
    #    print("nsg id type : " + str(type(list_network_security_groups_response.data)))
    #    print(list_network_security_groups_response.data)

#    nsg_name_list=[]
    for nsg_data in list_network_security_groups_response.data:
        if nsg_data.display_name in nsg_list_check:
            #print('NSG - OCID : ' + nsg_data.id + ' ---> : ' + nsg_data.display_name)
            return(nsg_data.id)

#def get_nsg_specific(core_client,find_compartment_id,nsg_list_check):
def get_nsg_specific(nsg_list_check):
    #core_client = oci.core.VirtualNetworkClient(config)
#    print('inside - def get_nsg_specific ')
    list_network_security_groups_response = core_client.list_network_security_groups(
        compartment_id=str(find_compartment_id))
#    print("nsg id type : " + str(type(list_network_security_groups_response)))
#    print("nsg id type : " + str(type(list_network_security_groups_response.data)))

    while True:
#        print(f'inside - def get_nsg_specific nsg_list_check -- {nsg_list_check}')
        for nsg_data in list_network_security_groups_response.data:
 #           print(f'inside - def get_nsg_specific {nsg_data.display_name}')
            if nsg_data.display_name.lower() in nsg_list_check :
                print('NSG - OCID : ' + nsg_data.id + ' ---> : ' + nsg_data.display_name)
                get_nsg_rules_ingress(nsg_data.id,nsg_data.display_name)

        if 'opc-next-page' not in list_network_security_groups_response.headers:
            break
        page_val = list_network_security_groups_response.headers['opc-next-page']
        list_network_security_groups_response = core_client.list_network_security_groups(compartment_id=str(find_compartment_id), page=page_val)

def delete_nsg_rules():

    #nsg_data_id=get_nsg_specific_id(core_client,find_compartment_id,nsg_list_check):

    f_read = open(delete_nsgruleid_file, "r")
#    f_write = open(delete_nsgruleid_file+"_b4", "w+")
    for cnt,ln_read in enumerate(f_read):
        var_extract_list=ln_read.split(':')
        v_nsg_name=var_extract_list[0].lower()
        v_nsg_ruleid=var_extract_list[1]

        nsg_all_list_of_dict = get_nsg_matching_all_list(v_nsg_name.split())
        for nsg_lp_1 in nsg_all_list_of_dict:

            if v_nsg_name == nsg_lp_1['name'].lower():
                #v_nsg_data_id = get_nsg_specific_id(core_client, find_compartment_id, v_nsg_name )

                v_nsg_data_id = nsg_lp_1['ocid']
                print('v_nsg_name -> '+v_nsg_name)
                print('v_nsg_ruleid -->'+v_nsg_ruleid)
                print('v_nsg_data_id --> '+v_nsg_data_id)

                #get_nsg_specific(v_nsg_name)
#                print('-------->>>>>check if Try reached ')
                try:
                    remove_network_security_group_security_rules_response = core_client.remove_network_security_group_security_rules(network_security_group_id=v_nsg_data_id,
                            remove_network_security_group_security_rules_details=oci.core.models.RemoveNetworkSecurityGroupSecurityRulesDetails(security_rule_ids=[v_nsg_ruleid.strip()]))
                #            remove_network_security_group_security_rules_details=oci.core.models.RemoveNetworkSecurityGroupSecurityRulesDetails(security_rule_ids=["''"+v_nsg_ruleid+"'"]))

                    print('\tREMOVED ---> NSG Rule Removal Status ---> '+v_nsg_name +':'+v_nsg_ruleid)
 #                   print(remove_network_security_group_security_rules_response.headers)
                except oci.exceptions.ServiceError as e :
                    print('\t\t EXCEPTION --- In Exception Handling ---> Raised oci.exceptions.ServiceError')
                    print('\t\t'+v_nsg_name +':'+v_nsg_ruleid)
                    print('\t\t Status -> '+str(e.status) )
#                    print('\t Status -> '+remove_network_security_group_security_rules_response.status+' \t request :'+remove_network_security_group_security_rules_response.request)




def remove_this_delete_nsg_rules():

    #nsg_data_id=get_nsg_specific_id(core_client,find_compartment_id,nsg_list_check):

    f_read = open(delete_nsgruleid_file, "r")
#    f_write = open(delete_nsgruleid_file+"_b4", "w+")
    for cnt,ln_read in enumerate(f_read):
        var_extract_list=ln_read.split(':')
        v_nsg_name=var_extract_list[0].lower()
        v_nsg_ruleid=var_extract_list[1]

        nsg_all_list_of_dict = get_nsg_matching_all_list(v_nsg_name.split())
        for nsg_lp_1 in nsg_all_list_of_dict:

            if v_nsg_name == nsg_lp_1:
                #v_nsg_data_id = get_nsg_specific_id(core_client, find_compartment_id, v_nsg_name )

                v_nsg_data_id = nsg_lp_1['ocid']
                print(v_nsg_name)
                print(v_nsg_ruleid)
                print(v_nsg_data_id)

                #get_nsg_specific(v_nsg_name)
                remove_network_security_group_security_rules_response = core_client.remove_network_security_group_security_rules(network_security_group_id=v_nsg_data_id,
                    remove_network_security_group_security_rules_details=oci.core.models.RemoveNetworkSecurityGroupSecurityRulesDetails(security_rule_ids=[v_nsg_ruleid.strip()]))
        #            remove_network_security_group_security_rules_details=oci.core.models.RemoveNetworkSecurityGroupSecurityRulesDetails(security_rule_ids=["''"+v_nsg_ruleid+"'"]))

                print("NSG Rule Removal Status ---> ")
                print(remove_network_security_group_security_rules_response.headers)


#def add_nsg_rules_per_nsg(core_client,nsg_data_id,nsg_display_name):
#def add_nsg_rules_per_nsg(nsg_display_name):
def add_nsg_rules_per_nsg_wrapper(nsg_list_multiple):
    print('--> Inside add_nsg_rules_per_nsg')
    nsg_all_list_of_dict = get_nsg_matching_all_list(nsg_list_multiple)

    print(f' --->>>> {nsg_all_list_of_dict}')
    for nsg_lp_1 in nsg_all_list_of_dict:
        add_nsg_rules_per_nsg(nsg_lp_1['name'],nsg_lp_1['ocid'])
#        print('Last :  OCID:' + nsg_lp_1['name'] + 'NSG Name:' + nsg_lp_1['ocid'])
#        if (check_ifexists_nsg_rules_ingress(nsg_lp_1['ocid'],check_src_addr,check_dst_port)):
#            print('\n \t Rule Exists : NSG Name:' + nsg_lp_1['name'] + 'NSG OCID:' + nsg_lp_1['ocid'] + "\n\t SrcAddr : " + check_src_addr+ "\t DstPort: "+check_dst_port)
#            #return 1
#        else:
#            print('\n \t Rule MISSING and Hence Adding : \nNSG Name:' + nsg_lp_1['name'] + 'NSG OCID:' + nsg_lp_1['ocid'] + "\n\t SrcAddr : " + check_src_addr+ "\t DstPort: "+check_dst_port)
#            add_nsg_rules_per_nsg(nsg_lp_1['ocid'])
#            #return 0

def add_nsg_rules_per_nsg(nsg_name,nsg_data_id):
    print('--> Inside add_nsg_rules_per_nsg')
    #nsg_data_id = get_nsg_specific_id(core_client, find_compartment_id, nsg_display_name )
    f_read=open(input_fname,"r")
    v_protocol='TCP'
    v_protocol=str(6 if (v_protocol == 'TCP') else 1 if (v_protocol == 'ICMP' ) else 17 if (v_protocol == 'UDP') else v_port)
    v_ipaddr_type='CIDR_BLOCK'
    for cnt,ln_read in enumerate(f_read):
#        print(str(cnt)+" - " + ln_read+" - " + str(type(ln_read.split(':'))))
        var_extract_list=ln_read.split(':')


        v_direction = var_extract_list[0]
        v_description=var_extract_list[1]
        v_ipaddr = var_extract_list[2]
        v_port = var_extract_list[3]

        print(v_description)
        print(v_ipaddr_type)
        print(v_ipaddr)
        print(v_port)
        print(v_protocol)

        if v_direction=='INGRESS':
            if (check_ifexists_nsg_rules_ingress(nsg_data_id,v_ipaddr,v_port)):
                print('\n \t Rule Exists : NSG Name:' + nsg_name + 'NSG OCID:' + nsg_data_id + "\n\t SrcAddr : " + v_ipaddr+ "\t DstPort: "+v_port)
            else:
                print('\n \t Rule MISSING - Hence Adding \n : NSG Name:' + nsg_name + 'NSG OCID:' + nsg_data_id + "\n\t SrcAddr : " + v_ipaddr+ "\t DstPort: "+v_port)

                add_network_security_group_security_rules_response = core_client.add_network_security_group_security_rules(nsg_data_id,
                add_network_security_group_security_rules_details=oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(
                        security_rules=[
                            oci.core.models.AddSecurityRuleDetails(
                                direction=v_direction,
                                protocol=v_protocol,
                                description=v_description,
                                source=v_ipaddr,
                                source_type=v_ipaddr_type,
                                tcp_options=oci.core.models.TcpOptions(
                                    destination_port_range=oci.core.models.PortRange(
                                        max=int(v_port),
                                        min=int(v_port) ))
                            )
                        ]
                    )
                )
                print(add_network_security_group_security_rules_response.data)
        elif v_direction == 'EGRESS':
            if (check_ifexists_nsg_rules_egress(nsg_data_id, v_ipaddr, v_port)):
                print(
                    '\n \t Rule Exists : NSG Name:' + nsg_name + 'NSG OCID:' + nsg_data_id + "\n\t DstAddr : " + v_ipaddr + "\t DstPort: " + v_port)
            else:
                print(
                    '\n \t EGRESS Rule MISSING - Hence Adding \n : NSG Name:' + nsg_name + 'NSG OCID:' + nsg_data_id + "\n\t DstAddr : " + v_ipaddr + "\t DstPort: " + v_port)
#                v_port = int(v_port) if int(v_port)>0 else None
                add_network_security_group_security_rules_response = core_client.add_network_security_group_security_rules(
                    nsg_data_id,
                    add_network_security_group_security_rules_details=oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(
                        security_rules=[
                            oci.core.models.AddSecurityRuleDetails(
                                direction=v_direction,
                                protocol=v_protocol,
                                description=v_description,
                                destination=v_ipaddr,
                                destination_type=v_ipaddr_type,
                                tcp_options=oci.core.models.TcpOptions(
                                    destination_port_range=oci.core.models.PortRange(
#                                        max=v_port,
#                                        min=v_port))
                                        max=int(v_port),
                                        min=int(v_port)))
                            )
                        ]
                    )
                    )
                print(add_network_security_group_security_rules_response.data)

    f_read.close()


def get_nsg_rules_testing(core_client,nsg_data_id,display_name):
    list_network_security_group_security_rules_response = core_client.list_network_security_group_security_rules(nsg_data_id,direction="INGRESS",limit=4000)
#    print(list_network_security_group_security_rules_response.data)
    rule_data=list_network_security_group_security_rules_response.data
    print("RESULTS O/p : Pagination : ")
    print(str(list_network_security_group_security_rules_response.headers))
    print("Type ---" + str(type(rule_data) )+" length: "+str(len(rule_data)))

    page=1
#    while page:
    while 'opc-next-page' in list_network_security_group_security_rules_response.headers:
        page+=1
        print('==>>> \t In Still fetching Rules'+str(page)+'... Page :'+str(list_network_security_group_security_rules_response.headers))
        page_val= list_network_security_group_security_rules_response.headers['opc-next-page']
        list_network_security_group_security_rules_response = core_client.list_network_security_group_security_rules(nsg_data_id, direction="INGRESS",page=page_val)
        print('==>>> \t In Still AFTER fetching Rules'+str(page)+'... Page :'+str(list_network_security_group_security_rules_response.headers))




def check_ifexists_nsg_rules_ingress_wrapper(nsg_list_multiple,check_src_addr,check_dst_port):
    nsg_all_list_of_dict = get_nsg_matching_all_list(nsg_list_multiple)

#    print(' Inside -1 - check_ifexists_nsg_rules_ingress_wrapper')

    for nsg_lp_1 in nsg_all_list_of_dict:
        print('Last : NSG Name:' + nsg_lp_1['name'] + 'NSG OCID:' + nsg_lp_1['ocid'])

        if (check_ifexists_nsg_rules_ingress(nsg_lp_1['ocid'],check_src_addr,check_dst_port)):
            print('\n \t Rule Exists : NSG Name:' + nsg_lp_1['name'] + 'NSG OCID:' + nsg_lp_1['ocid'] + "\n\t SrcAddr : " + check_src_addr+ "\t DstPort: "+check_dst_port)
            #return 1
        else:
            print('\n \t Rule MISSING : NSG Name:' + nsg_lp_1['name'] + 'NSG OCID:' + nsg_lp_1['ocid'] + "\n\t SrcAddr : " + check_src_addr+ "\t DstPort: "+check_dst_port)
            #return 0

def check_ifexists_nsg_rules_ingress(nsg_data_id,check_src_addr,check_dst_port):
    list_network_security_group_security_rules_response = core_client.list_network_security_group_security_rules(nsg_data_id,direction="INGRESS")

    while True:

        rule_data=list_network_security_group_security_rules_response.data
        #print(str(list_network_security_group_security_rules_response.headers))

        # sorting fir list of dict    rule_data_1=sorted( rule_data, key=lambda i: i['source_type'] )
        for ind,r_data in enumerate(rule_data):
#            var_1=str(r_data.direction) + "\t : Id : " + str(r_data.id)

            var_2 = "\t" + "Source Type : " + "\n\t" + "Source Addr: "
            if (r_data.source is not None) and  (r_data.tcp_options.destination_port_range is not None):
#                print('\t\t Before Comparing To Match : '+check_src_addr+" -- " + check_dst_port)
#                print('\t\t Before Comparing Fetched  : ' + str(r_data.source) + " -- " + str(r_data.tcp_options.destination_port_range.min))
                if (str(r_data.source) == check_src_addr ) and (str(r_data.tcp_options.destination_port_range.min) == check_dst_port):
                    return 1

        if 'opc-next-page' not in list_network_security_group_security_rules_response.headers:
            break
        page_val = list_network_security_group_security_rules_response.headers['opc-next-page']
        list_network_security_group_security_rules_response = core_client.list_network_security_group_security_rules(nsg_data_id, direction="INGRESS", page=page_val)

    return 0


def check_ifexists_nsg_rules_egress(nsg_data_id,check_dst_addr,check_dst_port):
    list_network_security_group_security_rules_response = core_client.list_network_security_group_security_rules(nsg_data_id,direction="EGRESS")

    while True:

        rule_data=list_network_security_group_security_rules_response.data
        #print(str(list_network_security_group_security_rules_response.headers))

        # sorting fir list of dict    rule_data_1=sorted( rule_data, key=lambda i: i['source_type'] )
        for ind,r_data in enumerate(rule_data):
#            var_1=str(r_data.direction) + "\t : Id : " + str(r_data.id)

            var_2 = "\t" + "Dest Type : " + "\n\t" + "Dest Addr: "
#            if (r_data.destination is not None) and  (r_data.tcp_options.destination_port_range is not None):
            if ((r_data.destination is None) or  (r_data.tcp_options is None) or (r_data.tcp_options.destination_port_range is None)):
                pass
            else:
#                print('\t\t Before Comparing To Match : '+check_src_addr+" -- " + check_dst_port)
#                print('\t\t Before Comparing Fetched  : ' + str(r_data.source) + " -- " + str(r_data.tcp_options.destination_port_range.min))
                if (str(r_data.destination) == check_dst_addr ) and (str(r_data.tcp_options.destination_port_range.min) == check_dst_port):
                    return 1

        if 'opc-next-page' not in list_network_security_group_security_rules_response.headers:
            break
        page_val = list_network_security_group_security_rules_response.headers['opc-next-page']
        list_network_security_group_security_rules_response = core_client.list_network_security_group_security_rules(nsg_data_id, direction="EGRESS", page=page_val)

    return 0


#def get_nsg_rules_ingress(core_client,nsg_data_id,display_name):
def get_nsg_rules_ingress(nsg_data_id,display_name):

    print("\t\t\t\t" + display_name)
    now = datetime.datetime.now()
    f_bkp=open("/tmp/1_"+display_name.lower()+"_"+now.strftime("%d%m_%H%M%S")+"_bkp.txt","w+")
    f_bkp.write('\t\t\t\t\ NSG Name ----> \t' +display_name+'\n')
    f_bkp.write('\t\t\t\t\ NSG OCID ----> \t' +nsg_data_id+'\n')

    list_network_security_group_security_rules_response = core_client.list_network_security_group_security_rules(nsg_data_id,direction="INGRESS")
    #while 'opc-next-page' in list_network_security_group_security_rules_response.headers:
    while True:

        rule_data=list_network_security_group_security_rules_response.data
        print(str(list_network_security_group_security_rules_response.headers))

        # sorting fir list of dict    rule_data_1=sorted( rule_data, key=lambda i: i['source_type'] )
        for ind,r_data in enumerate(rule_data):
    #        if (r_data.source or r_data.destination) :
#            f_bkp.write('\t\t\t\t  TEST INDEX  ---->  '+str(ind)+'\n')
            var_1=str(r_data.direction) + "\t : Id : " + str(r_data.id)
            var_2 = "\t" + "Source Type : " + "\n\t" + "Source Addr: "
            if (r_data.source is not None):
                var_2="\t" + "Source Type : " + str(r_data.source_type) + "\n\t" + "Source Addr: " + str(r_data.source)


            var_2_1="\t" + "Source Port : "
            if (r_data.tcp_options is not None and r_data.tcp_options.source_port_range is not None):
                var_2_1="\t" + "Source Port : " + str(r_data.tcp_options.source_port_range.min) + " - " + str(r_data.tcp_options.source_port_range.max)


            var_3 = "\t" + "Dest Type : "+ "\n\t" + "Dest  Addr: "
            if (r_data.destination is not None):
                var_3="\t" + "Dest Type : " + str(r_data.destination_type) + "\n\t" + "Dest  Addr: " + str(r_data.destination)

            var_3_1="\t" + "Dest Port : "
            if (r_data.tcp_options is not None and r_data.tcp_options.destination_port_range is not None):
                var_3_1="\t" + "Dest Port : " + str(r_data.tcp_options.destination_port_range.min) + " - " + str(r_data.tcp_options.destination_port_range.max)
            var_5="\t" + "Protocol : " + str('TCP' if (int(r_data.protocol) == 6) else 'ICMP' if (int(r_data.protocol) == 1) else 'UDP' if (int(r_data.protocol) == 17) else r_data.protocol)
            var_6="\t" + "Description : " + str(r_data.description)

            f_bkp.write(var_1+"\n")
            f_bkp.write(var_2+"\n")
            f_bkp.write(var_2_1+"\n")
            f_bkp.write(var_3+"\n")
            f_bkp.write(var_3_1+"\n")
            f_bkp.write(var_5+"\n")
            f_bkp.write(var_6+"\n")

        if 'opc-next-page' not in list_network_security_group_security_rules_response.headers:
            break
        page_val = list_network_security_group_security_rules_response.headers['opc-next-page']
        list_network_security_group_security_rules_response = core_client.list_network_security_group_security_rules(nsg_data_id, direction="INGRESS", page=page_val)



    list_network_security_group_security_rules_response = core_client.list_network_security_group_security_rules(nsg_data_id,direction="EGRESS")
    #while 'opc-next-page' in list_network_security_group_security_rules_response.headers:
    while True:

        rule_data=list_network_security_group_security_rules_response.data
        print(str(list_network_security_group_security_rules_response.headers))

        # sorting fir list of dict    rule_data_1=sorted( rule_data, key=lambda i: i['source_type'] )
        for ind,r_data in enumerate(rule_data):
    #        if (r_data.source or r_data.destination) :
#            f_bkp.write('\t\t\t\t  TEST INDEX  ---->  '+str(ind)+'\n')
            var_1=str(r_data.direction) + "\t : Id : " + str(r_data.id)
            var_2 = "\t" + "Source Type : " + "\n\t" + "Source Addr: "
            if (r_data.source is not None):
                var_2="\t" + "Source Type : " + str(r_data.source_type) + "\n\t" + "Source Addr: " + str(r_data.source)


            var_2_1="\t" + "Source Port : "
#            if (r_data.tcp_options.source_port_range is not None):
#            print('Type r_data.tcp_options.source_port_range -> '+str(type(r_data.tcp_options.source_port_range)))
#           print('Type r_data.tcp_options  -> '+str(type(r_data.tcp_options)))
#           print('Type r_data.destination  -> ' + str(type(r_data.destination)))
#           print('Type r_data.destination  -> ' + str((r_data.destination)))
#            if (r_data.tcp_options is not None):
            if ((r_data.tcp_options is None) or (r_data.tcp_options.source_port_range is None)):
                pass
            else:
#                print('var_2_1'+str(r_data.tcp_options))
#                print('var_2_1' + str(type(r_data.tcp_options.source_port_range)))
                var_2_1="\t" + "Source Port : " + str(r_data.tcp_options.source_port_range.min) + " - " + str(r_data.tcp_options.source_port_range.max)


            var_3 = "\t" + "Dest Type : "+ "\n\t" + "Dest  Addr: "
            if (r_data.destination is not None):
                var_3="\t" + "Dest Type : " + str(r_data.destination_type) + "\n\t" + "Dest  Addr: " + str(r_data.destination)

            var_3_1="\t" + "Dest Port : "
            if ( (r_data.tcp_options is None) or (r_data.tcp_options.destination_port_range is None) ):
                pass
            else:
                var_3_1="\t" + "Dest Port : " + str(r_data.tcp_options.destination_port_range.min) + " - " + str(r_data.tcp_options.destination_port_range.max)
            var_5="\t" + "Protocol : " + str('TCP' if (int(r_data.protocol) == 6) else 'ICMP' if (int(r_data.protocol) == 1) else 'UDP' if (int(r_data.protocol) == 17) else r_data.protocol)
            var_6="\t" + "Description : " + str(r_data.description)

            f_bkp.write(var_1+"\n")
            f_bkp.write(var_2+"\n")
            f_bkp.write(var_2_1+"\n")
            f_bkp.write(var_3+"\n")
            f_bkp.write(var_3_1+"\n")
            f_bkp.write(var_5+"\n")
            f_bkp.write(var_6+"\n")

        if 'opc-next-page' not in list_network_security_group_security_rules_response.headers:
            break
        page_val = list_network_security_group_security_rules_response.headers['opc-next-page']
        list_network_security_group_security_rules_response = core_client.list_network_security_group_security_rules(nsg_data_id, direction="EGRESS", page=page_val)

    f_bkp.close()


def build_delete_nsg_rules(nsg_display_name):
#    nsg_data_id = get_nsg_specific_id(core_client, find_compartment_id, nsg_display_name)

    nsg_all_list_of_dict = get_nsg_matching_all_list(nsg_display_name)



#    f_bkp = open("/tmp/1_build_delete_" + nsg_display_name + "_" + now.strftime("%d%m_%H%M%S") + ".txt", "w+")


    for nsg_lp_1 in nsg_all_list_of_dict:
    ####  nsg_lp_1['name'],nsg_lp_1['ocid']

        print("\t\t\t\t" + nsg_lp_1['name'])
        now = datetime.datetime.now()

        f_bkp = open(build_fname_prefix +'_' + nsg_lp_1['name'] + '_' + now.strftime("%d%m_%H%M%S") + '.txt', "w+")

        list_network_security_group_security_rules_response = core_client.list_network_security_group_security_rules(nsg_lp_1['ocid'])
        rule_data = list_network_security_group_security_rules_response.data

    # sorting fir list of dict    rule_data_1=sorted( rule_data, key=lambda i: i['source_type'] )
        for ind, r_data in enumerate(rule_data):
            f_bkp.write(nsg_lp_1['name']+" : ID - " +str(r_data.id)+ "\n")
            f_bkp.write(nsg_lp_1['name']+":" +str(r_data.id)+ "\n")

            f_bkp.write("\t\t SrcIP : " +str('' if r_data.source is None else r_data.source ) +     " SrcPort: "+ str('' if r_data.tcp_options  is None else ('' if r_data.tcp_options.source_port_range is None else r_data.tcp_options.source_port_range.min) )  + "\n")
#            f_bkp.write("\t\t SrcIP : " +str(r_data.source) +     " SrcPort: "+ str('' if r_data.tcp_options.source_port_range is None else r_data.tcp_options.source_port_range.min )  + "\n")
            f_bkp.write("\t\t DstIP : " +str(r_data.destination) +" DstPort: "+ str('' if r_data.tcp_options  is None else ('' if r_data.tcp_options.destination_port_range is None else r_data.tcp_options.destination_port_range.min)) + "\n")
#            f_bkp.write("\t\t DstIP : " +str(r_data.destination) +" DstPort: "+ str('' if r_data.tcp_options.destination_port_range is None else r_data.tcp_options.destination_port_range.min) + "\n")
            f_bkp.write("\t\t" + ('' if r_data.description is None else r_data.description) + "\n")

        f_bkp.close()


input_fname="/tmp/ip.txt"
delete_nsgruleid_file="/tmp/delete.txt"
build_fname_prefix='/tmp/1_build_delete'

# PROTEGO
config = from_file(profile_name="PROT")
# DESJARDINS - DR - Montreal
#config = from_file(profile_name="aucdesj01_yyz")
#config = from_file(profile_name="aucdesj01_yul")

print(get_tenancy_info(config))
core_client = oci.core.VirtualNetworkClient(config)
#list_compartments = oci.pagination.list_call_get_all_results(identity.list_compartments, root_id).data


#print(list_compartments)
#print(type(list_compartments))

# Use if needed ti List -->
list_compartments=list_all_compartments(config)

#for compt_name in list_compartments:
#    print(compt_name.name)
deflt_comp_name='OMCS-SHARED'
find_compartment ='OMCS-SHARED'
find_compartment = input("Provide Compartment Name:[OMCS-SHARED] ?") or "OMCS-SHARED"
print('After Input ' + find_compartment)
find_compartment_id=get_compartment_id(list_compartments,find_compartment)
print("Compartment name : "+find_compartment+" and OCID : " + str(find_compartment_id))
print("Compartment OCID :---> " + str(find_compartment_id))
#Works .... get_nsg_all(core_client,find_compartment_id)

#nsg_list_multiple='NSG-Prod-PROTOASPRDNDR-DB','NSG-Prod-PROTOASPRDNDR-WintMT','NSG-Prod-PROTOASPRDNDR-PvtMT','NSG-Prod-PROTOASPRDNDR-PvtLB','NSG-nonProd-PROTFDXDE1-PvtLB','NSG-nonProd-PROTFDXDE1-PvtMT','NSG-nonProd-PROTFDXDE1-DB','NSG-nonProd-PROTFDXDE1-PvtMTOHS','NSG-nonProd-PROTFUBDE1-PvtMT','NSG-NonProd-PROTSOATST-PE-INGRESS','NSG-NonProd-PROTFCCTST-PE-INGRESS','NSG-NonProd-PROTFCCTST-PE-INGRESS','NSG-NonProd-PROTFDXTST-PE-INGRESS','NSG-Prod-PROTFCCPRD-PvtLB','NSG-Prod-PROTFCCPRD-PvtMT','NSG-Prod-PROTFCCPRD-DB','NSG-NonProd-PROTFUBTST-PE-INGRESS','NSG-Prod-PROTFUBPRD-PvtLB','NSG-Prod-PROTFUBPRD-PvtMT','NSG-Prod-PROTFUBPRD-DB','NSG-Prod-PROTODIPRD-WintMT','NSG-Prod-PROTODIPRD-PvtLB','NSG-Prod-PROTODIPRD-PvtMT','NSG-Prod-PROTODIPRD-DB','NSG-Prod-PROTSOAPRD-DB','NSG-Prod-PROTSOAPRD-PvtMT','NSG-Prod-PROTSOAPRD-PvtLB','NSG-nonProd-PROTFCCTST-PvtLB','NSG-nonProd-PROTFCCTST-DB','NSG-nonProd-PROTFCCDEV-DB','NSG-nonProd-PROTFCCDEV-PvtLB','NSG-nonProd-PROTFCCDE1-PvtLB','NSG-nonProd-PROTFCCDE1-PvtMT','NSG-nonProd-PROTFCCDE1-DB','NSG-nonProd-PROTSOADE1-PvtLB','NSG-nonProd-PROTSOADE1-PvtMT','NSG-nonProd-PROTSOADE1-DB','NSG-nonProd-PROTFDXTST-PvtMTOHS','NSG-nonProd-PROTFDXDEV-PvtMTOHS','NSG-nonProd-PROTFUBDE1-DB','NSG-nonProd-PROTFUBDE1-PvtLB','NSG-nonProd-PROTFCCDEV-PvtMT','NSG-nonProd-PROTFCCTST-PvtMT','NSG-nonProd-PROTFDXTST-DB','NSG-nonProd-PROTFDXTST-PvtMT','NSG-nonProd-PROTFDXTST-PvtLB','NSG-Prod-PROTOASPRD-WintMT','NSG-Prod-PROTOASPRD-PvtLB','NSG-Prod-PROTOASPRD-PvtMT','NSG-Prod-PROTOASPRD-DB','NSG-Prod-PROTWCIPRD-PvtLB','NSG-Prod-PROTWCIPRD-PvtMT','NSG-Prod-PROTWCIPRD-DB','NSG-nonProd-PROTFDXDEV-PvtLB','NSG-nonProd-PROTFDXDEV-PvtMT','NSG-nonProd-PROTFDXDEV-DB','NSG-nonProd-PROTFUBDEV-PvtLB','NSG-nonProd-PROTFUBDEV-PvtMT','NSG-nonProd-PROTFUBDEV-DB','NSG-nonProd-PROTSOADEV-DB','NSG-nonProd-PROTSOADEV-PvtMT','NSG-nonProd-PROTSOADEV-PvtLB','NSG-nonProd-PROTODITST-WintMT','NSG-nonProd-PROTODITST-DB','NSG-nonProd-PROTODITST-PvtMT','NSG-nonProd-PROTODITST-PvtLB','NSG-nonProd-PROTAPGTST-PvtMT02','NSG-nonProd-PROTAPGTST-PvtMT01','NSG-nonProd-PROTSOATST-PvtLB','NSG-nonProd-PROTSOATST-PvtMT','NSG-nonProd-PROTSOATST-DB','NSG-nonProd-PROTFUBTST-DB','NSG-nonProd-PROTFUBTST-PvtMT','NSG-nonProd-PROTFUBTST-PvtLB','NSG-nonProd-PROTOASTST-WintMT','NSG-NonProd-PROTWCITST-PvtLB','NSG-NonProd-PROTWCITST-PvtMT','NSG-NonProd-PROTWCITST-DB','NSG-nonProd-PROTOASTST-PvtLB','NSG-nonProd-PROTOASTST-DB')
#nsg_list_onlyone='NSG-nonProd-PROTFUBTST-PvtMT'

#nsg_list_multiple=('NSG-Prod-PROTOASPRDNDR-WintMT','NSG-Prod-PROTODIPRD-WintMT','NSG-Prod-PROTOASPRD-WintMT','NSG-nonProd-PROTODITST-WintMT','NSG-nonProd-PROTOASTST-WintMT')

#Allow DB 1521 for All
#--->  nsg_list_multiple=['NSG-Prod-PROTOASPRDNDR-DB','NSG-Prod-PROTFCCPRD-DB','NSG-Prod-PROTFUBPRD-DB','NSG-Prod-PROTODIPRD-DB','NSG-Prod-PROTSOAPRD-DB','NSG-Prod-PROTWCIPRD-DB','NSG-Prod-PROTOASPRD-DB','NSG-nonProd-PROTFDXDE1-DB','NSG-nonProd-PROTFCCTST-DB','NSG-nonProd-PROTFCCDEV-DB','NSG-nonProd-PROTFCCDE1-DB','NSG-nonProd-PROTSOADE1-DB','NSG-nonProd-PROTFUBDE1-DB','NSG-nonProd-PROTFDXTST-DB','NSG-nonProd-PROTFDXDEV-DB','NSG-nonProd-PROTFUBDEV-DB','NSG-nonProd-PROTSOADEV-DB','NSG-nonProd-PROTODITST-DB','NSG-nonProd-PROTSOATST-DB','NSG-nonProd-PROTFUBTST-DB','NSG-NonProd-PROTWCITST-DB','NSG-nonProd-PROTOASTST-DB','NSG-nonProd-PROTMFTTST-PvtMT']
#nsg_list_multiple=['NSG-nonProd-PROTSOADEV-DB','NSG-nonProd-PROTODITST-DB','NSG-nonProd-PROTSOATST-DB','NSG-nonProd-PROTFUBTST-DB','NSG-NonProd-PROTWCITST-DB','NSG-nonProd-PROTOASTST-DB']
#nsg_list_multiple=['NSG-NonProd-PROTWCITST-DB','NSG-nonProd-PROTOASTST-DB']

#nsg_list_multiple=['NSG-Prod-PROTOASPRDNDR-PvtMT','NSG-nonProd-PROTFDXDE1-PvtMT','NSG-nonProd-PROTFDXDE1-PvtMTOHS','NSG-nonProd-PROTFUBDE1-PvtMT','NSG-Prod-PROTFCCPRD-PvtMT','NSG-Prod-PROTFUBPRD-PvtMT','NSG-Prod-PROTODIPRD-PvtMT','NSG-Prod-PROTSOAPRD-PvtMT','NSG-nonProd-PROTFCCDE1-PvtMT','NSG-nonProd-PROTSOADE1-PvtMT','NSG-nonProd-PROTFDXTST-PvtMTOHS','NSG-nonProd-PROTFDXDEV-PvtMTOHS','NSG-nonProd-PROTFCCDEV-PvtMT','NSG-nonProd-PROTFCCTST-PvtMT','NSG-nonProd-PROTFDXTST-PvtMT','NSG-Prod-PROTOASPRD-PvtMT','NSG-Prod-PROTWCIPRD-PvtMT','NSG-nonProd-PROTFDXDEV-PvtMT','NSG-nonProd-PROTFUBDEV-PvtMT','NSG-nonProd-PROTSOADEV-PvtMT','NSG-nonProd-PROTODITST-PvtMT','NSG-nonProd-PROTSOATST-PvtMT','NSG-nonProd-PROTFUBTST-PvtMT','NSG-NonProd-PROTWCITST-PvtMT','NSG-Shared-Bastion01']
#nsg_list_multiple=['NSG-Prod-PROTWCIPRD-PvtLB']
#nsg_list_multiple='NSG-nonProd-PROTOASTST-WintMT'

#FORTIGATE PULB COMMON ONE --->
#1 nsg_list_multiple=['NSG-NonProd-PROTFTGNONPRD-PubLB01']  #< Fortigate Public LB NSG For whitelist
#--> nsg_list_multiple=['NSG-NonProd-PROTFTGNONPRD-PubLB01']

#For texas Win 3389
#nsg_list_multiple=['NSG-nonProd-PROTOASTST-WintMT','NSG-nonProd-PROTODITST-WintMT','NSG-Prod-PROTOASPRDNDR-WintMT','NSG-Prod-PROTOASPRD-WintMT','NSG-Prod-PROTODIPRDNDR-WinMT','NSG-Prod-PROTODIPRD-WintMT']
#For texas Port 443

#
nsg_list_multiple=['NSG-nonProd-PROTFDXTST-PvtLB','NSG-nonProd-PROTFCCDE1-PvtLB','NSG-nonProd-PROTFCCDEV-PvtLB','NSG-nonProd-PROTFCCTST-PvtLB','NSG-nonProd-PROTFDXDE1-PvtLB','NSG-nonProd-PROTFDXDEV-PvtLB','NSG-nonProd-PROTFUBDE1-PvtLB','NSG-nonProd-PROTFUBDEV-PvtLB','NSG-nonProd-PROTFUBTST-PvtLB','NSG-nonProd-PROTMFTTST-PvtLB','NSG-nonProd-PROTOASTST-PvtLB','NSG-nonProd-PROTSOADE1-PvtLB','NSG-nonProd-PROTSOADEV-PubLB','NSG-nonProd-PROTSOADEV-PvtLB','NSG-nonProd-PROTODITST-PvtLB','NSG-nonProd-PROTSOATST-PvtLB','NSG-NonProd-PROTWCITST-PvtLB','NSG-Prod-PROTOASPRDNDR-PvtLB','NSG-Prod-PROTWCIPRD-PvtLB','NSG-Prod-PROTSOAPRD-PvtLB','NSG-Prod-PROTSOAPRDNDR-PvtLB','NSG-Prod-PROTODIPRD-PvtLB','NSG-Prod-PROTODIPRDNDR-PvtLB','NSG-Prod-PROTOASPRD-PvtLB','NSG-Prod-PROTMFTPRD-PvtLB','NSG-Prod-PROTFUBPRD-PvtLB','NSG-Prod-PROTFCCPRD-PvtLB']

#For texas Port 1521
# nsg_list_multiple=['NSG-nonProd-PROTFUBDE1-DB', 'NSG-nonProd-PROTFUBDEV-DB', 'NSG-nonProd-PROTFUBTST-DB', 'NSG-nonProd-PROTMFTTST-DB',
#  'NSG-nonProd-PROTOASTST-DB', 'NSG-nonProd-PROTODITST-DB', 'NSG-nonProd-PROTSOADE1-DB', 'NSG-nonProd-PROTSOADEV-DB',
#  'NSG-nonProd-PROTSOATST-DB', 'NSG-NonProd-PROTWCITST-DB', 'NSG-Prod-PROTFCCPRD-DB', 'NSG-Prod-PROTFUBPRD-DB',
#  'NSG-Prod-PROTMFTPRD-DB', 'NSG-Prod-PROTOASPRD-DB', 'NSG-Prod-PROTOASPRDNDR-DB', 'NSG-Prod-PROTODIPRD-DB',
#  'NSG-Prod-PROTODIPRDNDR-DB', 'NSG-Prod-PROTWCIPRD-DB', 'NSG-Prod-PROTWCIPRDNDR-DB', 'NSG-Prod-PROTSOAPRD-DB',
#  'NSG-Prod-PROTSOAPRDNDR-DB', 'NSG-nonProd-PROTFCCDE1-DB', 'NSG-nonProd-PROTFCCDEV-DB', 'NSG-nonProd-PROTFCCTST-DB',
#  'NSG-nonProd-PROTFDXDE1-DB', 'NSG-nonProd-PROTFDXDEV-DB', 'NSG-nonProd-PROTFDXTST-DB']

#For texas Port 22
#nsg_list_multiple=['NSG-nonProd-PROTAPGTST-PvtMT01','NSG-nonProd-PROTAPGTST-PvtMT02','NSG-nonProd-PROTFCCDE1-PvtMT','NSG-nonProd-PROTFCCDEV-PvtMT','NSG-NonProd-PROTFCCTST-PE-INGRESS','NSG-nonProd-PROTFCCTST-PvtMT','NSG-nonProd-PROTFDXDE1-PvtMT','NSG-nonProd-PROTFDXDE1-PvtMTOHS','NSG-nonProd-PROTFDXDEV-PvtMT','NSG-nonProd-PROTFDXDEV-PvtMTOHS','NSG-NonProd-PROTFDXTST-PE-INGRESS','NSG-nonProd-PROTFDXTST-PvtMT','NSG-nonProd-PROTFDXTST-PvtMTOHS','NSG-nonProd-PROTFUBDE1-PvtMT','NSG-nonProd-PROTFUBDEV-PvtMT','NSG-NonProd-PROTFUBTST-PE-INGRESS','NSG-nonProd-PROTFUBTST-PvtMT','NSG-nonProd-PROTMFTTST-PvtMT','NSG-nonProd-PROTOASTST-PvtMT','NSG-nonProd-PROTODITST-PvtMT','NSG-nonProd-PROTSOADE1-PvtMT','NSG-nonProd-PROTSOADEV-PvtMT','NSG-NonProd-PROTSOATST-PE-INGRESS','NSG-nonProd-PROTSOATST-PvtMT','NSG-NonProd-PROTWCITST-PvtMT','NSG-Prod-PROTAPGPRD-PvtMT01','NSG-Prod-PROTAPGPRD-PvtMT02','NSG-Prod-PROTFCCPRD-PE-INGRESS','NSG-Prod-PROTFCCPRD-PvtMT','NSG-Prod-PROTFDXPRD-PE-INGRESS','NSG-Prod-PROTFDXPRD-PvtMT','NSG-Prod-PROTFUBPRD-PE-INGRESS','NSG-Prod-PROTFUBPRD-PvtMT','NSG-Prod-PROTMFTPRD-PvtMT','NSG-Prod-PROTOASPRDNDR-PvtMT','NSG-Prod-PROTOASPRD-PvtMT','NSG-Prod-PROTODIPRDNDR-PvtMT','NSG-Prod-PROTODIPRD-PvtMT','NSG-Prod-PROTSOAPRDNDR-PvtMT','NSG-Prod-PROTSOAPRD-PE-INGRESS','NSG-Prod-PROTSOAPRD-PvtMT','NSG-Prod-PROTWCIPRD-PvtMT','NSG-nonProd-PROTFUBDE1-DB','NSG-nonProd-PROTFUBDEV-DB','NSG-nonProd-PROTFUBTST-DB','NSG-nonProd-PROTMFTTST-DB','NSG-nonProd-PROTOASTST-DB','NSG-nonProd-PROTODITST-DB','NSG-nonProd-PROTSOADE1-DB','NSG-nonProd-PROTSOADEV-DB','NSG-nonProd-PROTSOATST-DB','NSG-NonProd-PROTWCITST-DB','NSG-Prod-PROTFCCPRD-DB','NSG-Prod-PROTFUBPRD-DB','NSG-Prod-PROTMFTPRD-DB','NSG-Prod-PROTOASPRD-DB','NSG-Prod-PROTOASPRDNDR-DB','NSG-Prod-PROTODIPRD-DB','NSG-Prod-PROTODIPRDNDR-DB','NSG-Prod-PROTWCIPRD-DB','NSG-Prod-PROTWCIPRDNDR-DB','NSG-Prod-PROTSOAPRD-DB','NSG-Prod-PROTSOAPRDNDR-DB','NSG-nonProd-PROTFCCDE1-DB','NSG-nonProd-PROTFCCDEV-DB','NSG-nonProd-PROTFCCTST-DB','NSG-nonProd-PROTFDXDE1-DB','NSG-nonProd-PROTFDXDEV-DB','NSG-nonProd-PROTFDXTST-DB']
#---- nsg_list_multiple=['NSG-nonProd-PROTFCCDE1-DB']
#SOADEV Public
#nsg_list_multiple=['NSG-nonProd-PROTSOADEV-PubLB']
#--->
nsg_list_multiple=['NSG-Prod-PROTMFTPRD-PvtMT']

#nsg_list_multiple=['NSG-Prod-PROTSOAPRDNDR-DB']
#nsg_list_multiple=['NSG-prod-protwciprdndr-db']

#nsg_list_multiple=['NSG-nonProd-PROTSOADEV-PubLB']
# For cust bastn
#nsg_list_multiple=['NSG-Shared-Bastion01']

#nsg_list_multiple=['NSG-DR-DESJCTMPR2ODR-PvtLBAAS001','NSG-DR-DESJCTMPRDODR-PvtLBAAS001']   nsg_list_multiple=['NSG-DR-DESJCTMPR2ODR-PvtMT01']

#2 MFT Alone          nsg_list_multiple=['NSG-nonProd-PROTMFTTST-PvtMT']
#< Fortigate Public LB NSG For whitelist
# Multiple NSG    get_nsg_specific(core_client,find_compartment_id,nsg_list_multiple)
#specific NSG Works -  get_nsg_specific(core_client,find_compartment_id,nsg_list_onlyone)
#specific NSG Works new - get_nsg_specific(nsg_list_onlyone)

            #----
# --->
nsg_list_multiple=[x.lower() for x in nsg_list_multiple]
print(nsg_list_multiple)

# Works USE this  ...
#--->
get_nsg_specific(nsg_list_multiple)
#Works
#
# --->build_delete_nsg_rules(nsg_list_multiple)
#Works DELETE ---
#---> delete_nsg_rules()
#Works


# DONT Use  ...
#get_nsg_specific(nsg_list_multiple)
#add_nsg_rules_per_nsg(nsg_list_onlyone)
#specific NSG Works new -


#nsg_list_multiple='NSG-nonProd-PROTFUBTST-PvtLB','NSG-nonProd-PROTFUBDEV-PvtLB'
#nsg_list_multiple='NSG-NonProd-PROTFTGNONPRD-PubLB01'  #< Fortigate Public LB NSG For whitelist
#

# Add rules calls check_ifexists_nsg_rules_ingress directly to Check and not the wrapper ....
# WORKS
#---> add_nsg_rules_per_nsg_wrapper(nsg_list_multiple)

#get_nsg_specific(nsg_list_multiple)
#-x-x-x-x-x-x-x-x-x-x-


#check_src_addr=''
#check_dst_port=
#print('calling - check_ifexists_nsg_rules_ingress_wrapper')
#check_ifexists_nsg_rules_ingress_wrapper(nsg_list_multiple, check_src_addr, str(check_dst_port))

