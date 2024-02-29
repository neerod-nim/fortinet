import ipaddress
import csv
import json
import re
import io
from itertools import chain
import pandas as pd
import multiprocessing

def mask_to_cidr(subnet_mask):
    octets = subnet_mask.split('.')    
    binary_representation = ''.join([bin(int(octet))[2:].zfill(8) for octet in octets])
    cidr = '/' + str(binary_representation.count('1'))
    return cidr
    

def read_text_between(file_path, start_marker, end_marker):
    with open(file_path, 'r', encoding='utf-8') as file:
        file_content = file.read()
        start_index = file_content.find(start_marker)
        end_index = file_content.find(end_marker, start_index + len(start_marker))
        if start_index != -1 and end_index != -1:
            return file_content[start_index + len(start_marker):end_index]
    return None


def parse_ip_range(ip_range_str):
    s = ''
    try:
        start_ip, end_ip = ip_range_str.split('-')
        start_ip_obj = ipaddress.IPv4Address(start_ip.strip())
        end_ip_obj = ipaddress.IPv4Address(end_ip.strip())

        for ip_address in range(int(start_ip_obj), int(end_ip_obj) + 1):
            s += str(ipaddress.IPv4Address(ip_address)) + " "
    except ValueError as e:
        print(f"Error: {e}")
    return s


def addr_in_tuple(str1, tuple1):#check if it has any member in addrgrp
    str2 = str1.split()
    for i in str2:
        if i in tuple1:
            return True
    return False


def query_member(str1, tuple1, dict1):
    str2 = str1.split()#break str1 into a list of address
    str3 = ''
    l1 = len(str2)#count the no. of addresses
    for c1, i in enumerate(str2):#loop the addr mems 
        if not addr_in_tuple(i, tuple1):#if i is addrgrp 
            str3+=i+" "#add the addrgrp
            continue
        str3+=dict1[i]+' '#add the looked-up addr in fw addr 
    return str3
    

def extract_double_quoted_content(input_string):#extract any thing in "" e.g. 'set member "GRP_DBS_NET" "GRP_O365_NET"' etc
    pattern = r'"([^"]*)"'
    matches = re.findall(pattern, input_string)
    return matches
    

def prcslist1(list1):#remove the space in e.g. '   set type fqdn', '   edit "login.microsoft.com"  ' etc
    for i in list1:
        l = len(i)
        for j in range(l):
            i[j]=i[j].strip()           
    return list1


'''
read files;
change file path in your env;
'''

content = read_text_between('C:/temp/appcode_pcs/s04.conf', 'config firewall address', 'next\nend')#read&extract fw addr from config 
contentg = read_text_between('C:/temp/appcode_pcs/s04.conf', 'config firewall addrgrp', 'next\nend')#read&extract fw addrgrp from config 

csv_file_path = 'C:/temp/appcode_pcs/nocodepol.csv'#read the csv file with src and pol id
selected_columns = ['Source', 'ID']
df1 = pd.read_csv(csv_file_path, usecols=selected_columns)


'''
process pol with src and polid
'''

tuple_df1 = tuple(df1.to_dict(orient='records'))
lendf = len(tuple_df1)

tuple_df2 = tuple(list(d.values()) for d in tuple_df1)#a tuple of list with src&id

tuple_df1_src = tuple(d[0] for d in tuple_df2)#a tuple of src
tuple_df1_id = tuple(d[1] for d in tuple_df2)#a tuple of src
list_df1_src_1 = list(tuple_df1_src)
list_df1_src_2 = ' '.join(list_df1_src_1)
list_df1_src = list_df1_src_2.split()# a list of breakdown src in string


'''
process addr
'''

mylist = content.split("    next")
mylist1 = [x.split('\n') for x in mylist]
for i in mylist1:
    for x in i:
        x1 = x.strip()
        if not bool(x1):
            i.remove(x)
        else:
            continue

mylist2 = [x for x in mylist1 if x]

mylist3_1 = prcslist1(mylist2)
mylist3 = [[x for x in sublist if 'set uuid ' not in x] for sublist in mylist3_1]
mydict1 = {}

for i in mylist3:
    addrname1 = extract_double_quoted_content(i[0])#extract the 'edit xxx', which is the src
    k = ''.join(addrname1)
    if 'set type iprange' in i:#if src ip is the ip range type
        x1 = i[-2].replace("set start-ip ", "")
        x2 = i[-1].replace("set end-ip ", "")
        x3 = x1 + "-" + x2
        v = parse_ip_range(x3).strip()#return a range of IPs with each single IPs listed
    elif i[-1].startswith('set subnet'):#if src ip is the subnet type
        x1 = i[-1].split()
        if x1[-1] == '255.255.255.255':
            v = x1[-2]#it gives the exact host ip
        else:
            v = x1[-2] + mask_to_cidr(x1[-1])#it gives the subnet 
    elif i[-1].startswith('set fqdn'):
        v1 = i[-1]
        v2 = v1.replace("set fqdn ", "")
        v = ' '.join(extract_double_quoted_content(v2))#it gives the fqdn

    else:
        continue

    mydict1[k] = v#mydict1 contains all the fw address and its content

mydict2 = {x: x for x in list(mydict1.keys()) if x in list_df1_src}#tuple_df1_src is the sum of the src addr or addrgrp used in the server policy


'''
process addrgrp
'''

mylistg = contentg.split("    next")
mylistg1 = [x.split('\n') for x in mylistg]
for i in mylistg1:
    for x in i:
        x1 = x.strip()
        if not bool(x1):
            i.remove(x)
        else:
            continue

mylistg2 = [x for x in mylistg1 if x]

mylistg3_1 = prcslist1(mylistg2)
mylistg3 = [[x for x in sublist if 'set uuid ' not in x] for sublist in mylistg3_1]

mydictg1 = {}

for i in mylistg3:
    k1 = i[0].replace("edit ", "")
    k2 = extract_double_quoted_content(k1)
    k3 = " ".join(k2)
    v1 = i[1].replace("set member ", "")
    v2 = extract_double_quoted_content(v1)
    v3 = " ".join(v2)
    mydictg1[k3] = v3#mydictg1 contains all addressgrp and its content


mydictg2 = {x: x for x in list(mydictg1.keys()) if x in list_df1_src} #tuple_df1_src is the sum of the src addr or addrgrp used in the server policy

tupleaddrg = tuple(mydictg1)

for k, v in mydictg2.items():
    while addr_in_tuple(v, tupleaddrg):#check if each addrgrp obj used in the policy is addrgrp type, make recursive query until it gets all members in addr type than addgrp type
        v1 = query_member(v, tupleaddrg, mydictg1)#query the members of all the src addresses until it's all fw addr type
        v = v1
    mydictg2[k] = v

mydictg3 = mydictg2#a dict of addrgrp used in server policy

for k, v in mydictg3.items():
    v1 = v.split()
    for c3, i in enumerate(v1):#numerate each addrgrp objects(level1, all can break into addresses)
        i1 = mydict1[i]#mydict1 is the dict of all fw address and its content
        v1[c3] = i1#further query each addrgrp obj content, to make it all fw addr
    v2 = ' '.join(v1)
    mydictg3[k] = v2

mydictsum = {**mydictg3, **mydict1}#merge the svr policy addrgrp and addr objects in a single dict


'''
break the src address into objects 
'''

list_df1_src_new = []
for n, i1 in enumerate(tuple_df1_src):
    src1 = i1
    src2 = src1.split()#split the src objects in a list 
    src3 = ''


    for j in src2:
        if j in tuple(mydictsum.keys()):
            src3+=mydictsum[j]+' '

    src4 = src3.split()
    src4_list = list(set(src4))
    src5 = ' '.join(src4_list)
    list_df1_src_new.append(src5)


nocodepol=[]
for i in range(lendf):
    dict1={}
    dict1['Source'] = list_df1_src_new[i]
    dict1['ID'] = tuple_df1_id[i]
    nocodepol.append(dict1)


csv_file ='C:/temp/appcode_pcs/nocodepol_ds.csv'
with open(csv_file, mode='w', newline='') as file:
    fieldnames = nocodepol[0].keys()
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    
    writer.writeheader()
    for row in nocodepol:
        writer.writerow(row)
 
