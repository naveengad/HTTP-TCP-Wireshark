import dpkt

class HTTPHeader:
    def __init__(self):
        self.req_type = None
        self.pkt_type = None

class TCPHeader:
    def __init__(self):
        self.srcport = 0
        self.dstport = 0
        self.seqno = 0
        self.ackno = 0
        self.windsize = 0
        self.flag_syn = 0
        self.flag_fin = 0
        self.flag_ack = 0
        self.flag_push = 0
        self.dataoffset = 0
        self.timestmp = 0

class IPHeader:
    def __init__(self):
        self.headerlen = 0
        self.totallen = 0
        self.sourceIPAddr = 0
        self.destIPAddr = 0

class wiresharksamp:
    def __init__(self):
        self.srcports_1080 = []
        self.dstports_1080 = []
        self.flows_1080 = []
        self.srcports_1081 = []
        self.dstports_1081 = []
        self.flows_1081 = []
        self.srcports_1082 = []
        self.dstports_1082 = []
        self.flows_1082 = []

    def collect_packets_1080(self):
        with open('http_1080.pcap', 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            packets = []
            i = 0
            for ts, buf in pcap:
                i += 1
                IP = IPHeader()
                TCP = TCPHeader()
                HTTP = HTTPHeader()
                IP.headerlen = (buf[14] & 0x0f) * 4
                IP.totallen = (buf[16] *256) + buf[17]
                IP.sourceIPAddr = str(buf[26]) + '.' + str(buf[27]) + '.' + str(buf[28]) + '.' + str(buf[29])
                IP.destIPAddr = str(buf[30]) + '.' + str(buf[31]) + '.' + str(buf[32]) + '.' + str(buf[33])
                TCP.buflen = len(buf)
                TCP.srcport = (buf[34] * 256) + buf[35]
                TCP.dstport = (buf[36] * 256) + buf[37]
                TCP.seqno = (buf[38] * 256 * 256 * 256) + (buf[39] * 256 * 256) + (buf[40] * 256) + buf[41]
                TCP.ackno = (buf[42] * 256 * 256 * 256) + (buf[43] * 256 * 256) + (buf[44] * 256) + buf[45]  
                TCP.dataoffset = int(hex(buf[46])[:3], 16) * 4
                ack_syn_fin = buf[47]
                if ack_syn_fin & 2:
                    TCP.flag_syn = 1
                if ack_syn_fin & 1:
                    TCP.flag_fin = 1
                if ack_syn_fin & 16:
                    TCP.flag_ack = 1
                if ack_syn_fin & 8:
                    TCP.flag_push = 1
                TCP.windsize = ((buf[48] * 256) + buf[49])                
                TCP.timestmp = ts
                index = TCP.dataoffset + 34
                if len(buf) > 66:
                    st = chr(buf[index]) + chr(buf[index + 1]) + chr(buf[index + 2]) + chr(buf[index + 3])                    
                    if st.strip() in ['GET', 'POST']:                        
                        HTTP.pkt_type = "REQUEST"
                        HTTP.req_type = st
                    elif st in ['HTTP']:
                        HTTP.pkt_type = "RESPONSE"
                        HTTP.req_type = st
                    else:
                        HTTP.req_type = 'HTTP'
                        HTTP.pkt_type = "RESPONSE"
                packets.append([IP, TCP, HTTP])
            return packets    

    def count_TCP_1080_connections(self, packets):
        ports = {}
        count = 0
        dst = set()
        for ip, tcp, http in packets:
            if tcp.flag_syn and not tcp.flag_ack:
                if tcp.srcport not in ports: 
                    ports[(tcp.srcport,  tcp.dstport)] = [1, 0, 0]
                    self.flows_1080.append([tcp.srcport, tcp.dstport]) 
                    self.srcports_1080.append(tcp.srcport) 
                    dst.add(tcp.dstport)                                                 
            elif tcp.flag_syn and tcp.flag_ack:
                if tcp.dstport in ports:
                    ports[(tcp.dstport, tcp.srcport)][1] = 1
            elif tcp.flag_fin:
                if tcp.srcport in ports:
                    ports[(tcp.srcport,  tcp.dstport)][2] = 1        
        self.dstports_1080 = list(set(dst))               
        print(self.flows_1080)              
        print('Total Flows in 1080', len(self.flows_1080))
        print('\n')

    def reassemble_pkts(self, packets):
        req_resp = {}
        for ip, tcp, http in packets:            
            if http.req_type and http.req_type.strip() in ['GET', 'POST']:
                req_resp[(ip.sourceIPAddr, ip.destIPAddr, tcp.srcport, tcp.dstport)] = [['REQUEST', tcp.seqno, tcp.ackno]]
            elif http.req_type and http.req_type.strip() == 'HTTP':
                if (ip.destIPAddr, ip.sourceIPAddr, tcp.dstport, tcp.srcport) in req_resp:
                    req_resp[(ip.destIPAddr, ip.sourceIPAddr, tcp.dstport, tcp.srcport)].append(['RESPONSE', tcp.seqno, tcp.ackno])
        
        i = 0
        for k, items in req_resp.items():
            i += 1
            print("HTTP REQ/RESP ", str(i), '<Packet Type, Source, Destination, Seq Number, Ack Number>')
            for v in items:
                print(v[0], str(k[0]) + ':' + str(k[2]), str(k[1]) + ':' + str(k[3]), str(v[1]), str(v[2]))
            print('\n')

    def get_protocol(self, packets, srcports):
        pacs = {}
        for ip, tcp, http in packets:
            if tcp.srcport in srcports:
                if (tcp.srcport, tcp.dstport) not in pacs:
                    pacs[(tcp.srcport, tcp.dstport)] = [tcp]
                else:
                    pacs[(tcp.srcport, tcp.dstport)].append(tcp)
            else:                
                pacs[(tcp.dstport, tcp.srcport)].append(tcp)
        requests = {}
        for k, v in pacs.items():
            for t in v:
                if t.srcport in srcports and t.buflen > 66:
                    if t.srcport not in requests:
                        requests[t.srcport] = [t.seqno]
                    else:
                        requests[t.srcport].append(t.seqno)
        if len(requests) == 1:            
            print("Protocol is HTTPS 2")
        else:
            http1 = True
            for k, v in requests.items():
                if len(v) > 1:
                    http1 = False
                    break
            if http1:
                print("Protocol is HTTP 1")
            else:
                print("Protocol is HTTPS 1.1")
        print('\n')

    def get_loadtime(self, p1, p2, p3):
        http1 = p1[-1][1].timestmp - p1[0][1].timestmp
        http11 = p2[-1][1].timestmp - p2[0][1].timestmp
        http2 = p3[-1][1].timestmp - p3[0][1].timestmp
        print('HTTP 1: ', http1, ' sec')
        print('HTTPS 1.1: ', http11, ' sec')
        print('HTTPS 2: ', http2, ' sec')
        print('\n')

    def get_len_count_pkts(self, p1, p2, p3, srcports):        
        #print(srcports)
        i = 0
        for packets in [p1, p2, p3]:
            i += 1
            count = 0
            tl = 0
            for ip, tcp, http in packets:
                if tcp.srcport in srcports:
                    count += 1
                    tl += tcp.buflen
            if i == 1:
                print("HTTP 1")
                
            elif i == 2:
                print("HTTPS 1.1")
            else:
                print("HTTPS 2")
            print("Total number of packets: ", count)
            print("Total number of bytes: ", tl, ' bytes')
            print('\n')
        print('\n')

    def collect_packets_1081(self):
        with open('tcp_1081.pcap', 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            packets = []
            i = 0
            for ts, buf in pcap:
                i += 1
                IP = IPHeader()
                TCP = TCPHeader()
                HTTP = HTTPHeader()
                IP.headerlen = (buf[14] & 0x0f) * 4
                IP.totallen = (buf[16] *256) + buf[17]
                IP.sourceIPAddr = str(buf[26]) + '.' + str(buf[27]) + '.' + str(buf[28]) + '.' + str(buf[29])
                IP.destIPAddr = str(buf[30]) + '.' + str(buf[31]) + '.' + str(buf[32]) + '.' + str(buf[33])
                TCP.buflen = len(buf)
                TCP.srcport = (buf[34] * 256) + buf[35]
                TCP.dstport = (buf[36] * 256) + buf[37]
                TCP.seqno = (buf[38] * 256 * 256 * 256) + (buf[39] * 256 * 256) + (buf[40] * 256) + buf[41]
                TCP.ackno = (buf[42] * 256 * 256 * 256) + (buf[43] * 256 * 256) + (buf[44] * 256) + buf[45]  
                TCP.dataoffset = int(hex(buf[46])[:3], 16) * 4
                ack_syn_fin = buf[47]
                if ack_syn_fin & 2:
                    TCP.flag_syn = 1
                if ack_syn_fin & 1:
                    TCP.flag_fin = 1
                if ack_syn_fin & 16:
                    TCP.flag_ack = 1
                if ack_syn_fin & 8:
                    TCP.flag_push = 1
                TCP.windsize = ((buf[48] * 256) + buf[49])                
                TCP.timestmp = ts                
                packets.append([IP, TCP, HTTP])
            return packets    

    def count_TCP_1081_connections(self, packets):
        ports = {}
        count = 0
        dst = set()
        for ip, tcp, http in packets:
            if tcp.flag_syn and not tcp.flag_ack:
                if tcp.srcport not in ports: 
                    ports[(tcp.srcport,  tcp.dstport)] = [1, 0, 0]
                    self.flows_1081.append([tcp.srcport, tcp.dstport]) 
                    self.srcports_1081.append(tcp.srcport) 
                    dst.add(tcp.dstport)                                                 
            elif tcp.flag_syn and tcp.flag_ack:
                if tcp.dstport in ports:
                    ports[(tcp.dstport, tcp.srcport)][1] = 1
            elif tcp.flag_fin:
                if tcp.srcport in ports:
                    ports[(tcp.srcport,  tcp.dstport)][2] = 1        
        self.dstports_1081 = list(set(dst)) 
        print(self.flows_1081)              
        print('Total Flows in 1081', len(self.flows_1081))
        print('\n')

    def collect_packets_1082(self):
        with open('tcp_1082.pcap', 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            packets = []
            i = 0
            for ts, buf in pcap:
                i += 1
                IP = IPHeader()
                TCP = TCPHeader()
                HTTP = HTTPHeader()
                IP.headerlen = (buf[14] & 0x0f) * 4
                IP.totallen = (buf[16] *256) + buf[17]
                IP.sourceIPAddr = str(buf[26]) + '.' + str(buf[27]) + '.' + str(buf[28]) + '.' + str(buf[29])
                IP.destIPAddr = str(buf[30]) + '.' + str(buf[31]) + '.' + str(buf[32]) + '.' + str(buf[33])
                TCP.buflen = len(buf)
                TCP.srcport = (buf[34] * 256) + buf[35]
                TCP.dstport = (buf[36] * 256) + buf[37]
                TCP.seqno = (buf[38] * 256 * 256 * 256) + (buf[39] * 256 * 256) + (buf[40] * 256) + buf[41]
                TCP.ackno = (buf[42] * 256 * 256 * 256) + (buf[43] * 256 * 256) + (buf[44] * 256) + buf[45]  
                TCP.dataoffset = int(hex(buf[46])[:3], 16) * 4
                ack_syn_fin = buf[47]
                if ack_syn_fin & 2:
                    TCP.flag_syn = 1
                if ack_syn_fin & 1:
                    TCP.flag_fin = 1
                if ack_syn_fin & 16:
                    TCP.flag_ack = 1
                if ack_syn_fin & 8:
                    TCP.flag_push = 1
                TCP.windsize = ((buf[48] * 256) + buf[49])                
                TCP.timestmp = ts                
                packets.append([IP, TCP, HTTP])
            return packets    

    def count_TCP_1082_connections(self, packets):
        ports = {}
        count = 0
        dst = set()
        for ip, tcp, http in packets:
            if tcp.flag_syn and not tcp.flag_ack:
                if tcp.srcport not in ports: 
                    ports[(tcp.srcport,  tcp.dstport)] = [1, 0, 0]
                    self.flows_1082.append([tcp.srcport, tcp.dstport]) 
                    self.srcports_1082.append(tcp.srcport) 
                    dst.add(tcp.dstport)                                                 
            elif tcp.flag_syn and tcp.flag_ack:
                if tcp.dstport in ports:
                    ports[(tcp.dstport, tcp.srcport)][1] = 1
            elif tcp.flag_fin:
                if tcp.srcport in ports:
                    ports[(tcp.srcport,  tcp.dstport)][2] = 1        
        self.dstports_1082 = list(set(dst)) 
        print(self.flows_1082)              
        print('Total Flows in 1082', len(self.flows_1082))
        print('\n')

def main():
    wr = wiresharksamp()
    packets_1080 = wr.collect_packets_1080()    
    wr.count_TCP_1080_connections(packets_1080)
    wr.reassemble_pkts(packets_1080)    
    wr.get_protocol(packets_1080, wr.srcports_1080)
    packets_1081 = wr.collect_packets_1081()    
    wr.count_TCP_1081_connections(packets_1081)
    wr.get_protocol(packets_1081, wr.srcports_1081)
    packets_1082 = wr.collect_packets_1082()    
    wr.count_TCP_1082_connections(packets_1082)
    wr.get_protocol(packets_1082, wr.srcports_1082)
    wr.get_loadtime(packets_1080, packets_1081, packets_1082)
    wr.get_len_count_pkts(packets_1080, packets_1081, packets_1082, wr.srcports_1080 + wr.srcports_1081 + wr.srcports_1082)

if __name__ == "__main__" :
    main()