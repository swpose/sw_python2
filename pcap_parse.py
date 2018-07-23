def Int2IP(ipnum):
    o1 = int(ipnum / 16777216) % 256
    o2 = int(ipnum / 65536) % 256
    o3 = int(ipnum / 256) % 256
    o4 = int(ipnum) % 256
    return '%(o1)s.%(o2)s.%(o3)s.%(o4)s' % locals()

def Layer_2(f):
    sig = f.read(4).encode('hex')
    f.seek(40)
    dst = f.read(6).encode('hex')
    src = f.read(6).encode('hex')
    type = f.read(2).encode('hex')
    print '-----------------Layer 2-----------------'
    print "File signature =  %s" % sig
    print "Destination MAC Address = ",
    for i in range(0,12,2):
        print dst[i:i+2],
        if (i==10):
            break
        print ':',
    print "\nSource MAC Address = ",
    for i in range(0,12,2):
        print src[i:i+2],
        if (i==10):
            break
        print ':',
    if (type == '0800'):
        print '\nType = IPv4'

def Layer_3(f):
    f.seek(66)
    src = f.read(4).encode('hex')
    dst = f.read(4).encode('hex')
    print '-----------------Layer 3-----------------'
    print "Source ip = %s" %Int2IP(int(src,16))
    print "Destination ip = %s" %Int2IP(int(dst,16))

def Layer_4(f):
    f.seek(74)
    src = f.read(2).encode('hex')
    dst = f.read(2).encode('hex')
    f.seek(16,1)
    data = f.read(16)
    print '-----------------Layer 4-----------------'
    print "Source port = %s" %int(src,16)
    print "Destination port = %s" % int(dst, 16)
    print "Data 16byte = %s" %data


def main():
    with open('C:/AAA/captured.pcap') as f:
        Layer_2(f)
        Layer_3(f)
        Layer_4(f)

if __name__ == '__main__':
    main()