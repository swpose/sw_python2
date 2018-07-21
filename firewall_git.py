import re
import datetime
import time
import csv
import pymysql

#if you want insert direct DB
def inputDB(sql_list, count):
    conn = pymysql.connect(host='localhost', user='root', password='', db='f_log', charset='utf8')

    curs = conn.cursor()
    sql = """insert into firewall(timestamp,srcmac,dstmac,srcip,dstip,length,srcport,dstport) values (%s, %s, %s, %s, %s, %s, %s, %s )"""

    for i in range(0, len(sql_list)):
        curs.execute(sql, (sql_list[i][0],sql_list[i][1],sql_list[i][2],sql_list[i][3],sql_list[i][4],sql_list[i][5]),sql_list[i][6],sql_list[i][7])
    conn.commit()
    conn.close()

# IP to int in python2
def IP2Int(ip):
    o = map(int, ip.split('.'))
    res = (16777216 * o[0]) + (65536 * o[1]) + (256 * o[2]) + o[3]
    return res

with open("E:/SW/firewall.log",'r') as f:

    while True:
        raw_data = f.read(100000)
        list = []
        a = []
        chk_time = re.findall("[0-9]+\-[0-9]+\-[0-9]+ [0-9]+\:[0-9]+\:[0-9]+",raw_data)
        chk_srcmac = re.findall("src_mac=[a-zA-Z0-9]+\:[a-zA-Z0-9]+\:[a-zA-Z0-9]+\:[a-zA-Z0-9]+\:[a-zA-Z0-9]+\:[a-zA-Z0-9]+",raw_data)
        chk_dstmac = re.findall("dst_mac=[a-zA-Z0-9]+\:[a-zA-Z0-9]+\:[a-zA-Z0-9]+\:[a-zA-Z0-9]+\:[a-zA-Z0-9]+\:[a-zA-Z0-9]+",raw_data)
        chk_srcip = re.findall("src_ip=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]",raw_data)
        chk_dstip = re.findall("dst_ip=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]",raw_data)
        chk_lengh = re.findall("length=[0-9]+",raw_data)
        chk_srcport = re.findall("srcport=[0-9]+",raw_data)
        chk_dstport = re.findall("dst_port=[0-9]+",raw_data)
        try :
            for i in range(0, len(chk_dstport)):
                chk_time[i] = int(time.mktime(datetime.datetime.strptime(str(chk_time[i]), "%Y-%m-%d %H:%M:%S").timetuple()))
                a.append(chk_time[i])
                a.append(chk_srcmac[i].replace('src_mac=',''))
                a.append(chk_dstmac[i].replace('dst_mac=',''))
                a.append(IP2Int(chk_srcip[i].replace('src_ip=','')))
                a.append(IP2Int(chk_dstip[i].replace('dst_ip=','')))
                a.append(chk_lengh[i].replace('length=',''))
                a.append(chk_srcport[i].replace('srcport=',''))
                a.append(chk_dstport[i].replace('dst_port=',''))
                list.append(a)

                t = open('C:/AAA/log_output.csv', 'a')
                wr = csv.writer(t,lineterminator='\n')
                wr.writerow([str(a[0]), a[1], a[2], a[3], a[4], str(a[5]), str(a[6]), str(a[7])],)
                t.close()

                a = []
        except Exception as e :
            pass