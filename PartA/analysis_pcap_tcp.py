import dpkt

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
        self.srcports = []
        self.dstports = []
        self.flows = []

    def collect_packets(self):
        with open('assignment2.pcap', 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            packets = []
            i = 0
            for ts, buf in pcap:
                i += 1
                IP = IPHeader()
                TCP = TCPHeader()
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
                TCP.windsize = ((buf[48] * 256) + buf[49]) #* 16384
                if buf[54] != 1:
                    TCP.mss = (buf[56] * 256) + buf[57]
                TCP.timestmp = ts
                packets.append([IP, TCP])
                # print(TCP.buflen)          
                # break
            return packets

    def count_TCP_connections(self, packets):
        ports = {}
        count = 0
        dst = set()
        for ip, tcp in packets:
            if tcp.flag_syn and not tcp.flag_ack:
                if tcp.srcport not in ports: 
                    ports[(tcp.srcport,  tcp.dstport)] = [1, 0, 0]
                    self.flows.append([tcp.srcport, tcp.dstport]) 
                    self.srcports.append(tcp.srcport) 
                    dst.add(tcp.dstport)                                                 
            elif tcp.flag_syn and tcp.flag_ack:
                if tcp.dstport in ports:
                    ports[(tcp.dstport, tcp.srcport)][1] = 1
            elif tcp.flag_fin:
                if tcp.srcport in ports:
                    ports[(tcp.srcport,  tcp.dstport)][2] = 1
        self.dstports = list(set(dst))        
        print("Total TCP flows are ", len(self.flows))    
        print('\n')    

    def seq_ack_nums_windsize(self, packets):
        data = {}
        ack = {}
        for ip, tcp in packets:
            if tcp.flag_push and tcp.flag_ack and tcp.srcport not in data:
                data[tcp.srcport] = [[tcp.seqno, tcp.ackno, tcp.windsize * 16384]]
            elif tcp.flag_ack and not tcp.flag_syn and not tcp.flag_fin:
                if tcp.srcport in data and len(data[tcp.srcport]) == 1:
                    data[tcp.srcport].append([tcp.seqno, tcp.ackno, tcp.windsize * 16384])
                if tcp.dstport not in ack and tcp.dstport in data:
                    ack[tcp.dstport] = [[tcp.seqno, tcp.ackno, tcp.windsize * 16384]]
                elif tcp.dstport in ack and tcp.dstport in data and len(ack[tcp.dstport]) == 1:
                        ack[tcp.dstport].append([tcp.seqno, tcp.ackno, tcp.windsize * 16384])
        for k, v in data.items():
            print('For First Transmission')
            print('<Source Port, Destination Port, [SeqNum, Ack Num, Window Size]>')
            print('<', k, ', 80, ', v[0], '>')
            print('<', '80', k, ack[k][0], '>')
            print('For Second Transmission')
            print('<', k, ', 80, ', v[1], '>')
            print('<', '80, ', k, ', ', ack[k][1], '>')
            print('\n')        

    def cal_lossrate(self, packets):
        count = {}
        uniq_seq = {}
        loss_rate = {}
        for ip, tcp in packets:
            if tcp.srcport in self.srcports:
                if tcp.srcport not in uniq_seq:
                    count[tcp.srcport] = 1
                    uniq_seq[tcp.srcport] = { tcp.seqno }
                else:
                    count[tcp.srcport] += 1
                    uniq_seq[tcp.srcport].add(tcp.seqno)                              
        for k, v in uniq_seq.items():
            #print(len(uniq_seq[k]))
            #print(count[k])
            ratio = (len(uniq_seq[k]) + 1) / count[k]
            loss_rate[k] = 1 - ratio
        for k, v in loss_rate.items():
            print('Loss Rate')
            print('<src port, dst port, loss rate>')
            print('<', k, ', 80, ', v, '>')
            print('\n')
        #print(loss_rate)

    def cal_throughput(self, packets):
        throughput = {}
        res = {}
        for ip, tcp in packets:
            if tcp.srcport in self.srcports:
                if (tcp.srcport, tcp.dstport) not in throughput:
                    throughput[(tcp.srcport, tcp.dstport)] = [tcp.buflen, tcp.timestmp, 0] 
                else:
                    throughput[(tcp.srcport, tcp.dstport)][0] += tcp.buflen
                    throughput[(tcp.srcport, tcp.dstport)][2] = tcp.timestmp
        #print(throughput)
        for k, v in throughput.items():
            val = throughput[k][0] / ((throughput[k][2] - throughput[k][1]) * (10 ** 6))
            res[k] = val
        for k, v in res.items():
            print('Through Put')
            print('<src port, dst port, through put>')
            print('<', k[0], ', 80, ', v, 'bytes/msec', '>')
            print('\n')

    def cal_RTT(self, packets):
        flow = {}
        for ip, tcp in packets:
            if tcp.srcport in self.srcports:
                if (tcp.srcport, tcp.dstport) not in flow:
                    flow[(tcp.srcport, tcp.dstport)] = [[tcp.seqno, tcp.timestmp, True]]
                else:
                    flow[(tcp.srcport, tcp.dstport)].append([tcp.seqno, tcp.timestmp, True])
            if tcp.srcport in self.dstports:                
                flow[(tcp.dstport, tcp.srcport)].append([tcp.ackno, tcp.timestmp, False])
        #print(sent)
        #print(ack)
        rtts = {}
        for k, v in flow.items():
            #print(k)
            i = 0
            j = 0
            t = 0
            c = 0
            while j < len(v):
                #print(j)
                while j < len(v) and v[j][2]:
                    j += 1
                if j == len(v):
                    break
                while i < len(v) and (not v[i][2] or v[i][0] < v[j][0]):                    
                    i += 1                
                if i == len(v):
                    break
                c += 1
                t += v[j][1] - v[i - 1][1]                    
                i += 1                    
                j += 1                 
            rtts[k] = (t / c)
            #print(t)
            #print(c)
            #print(t / c)
        for k, v in rtts.items():
            print('RTT')
            print('<src port, dst port, RTT>')
            print('<', k, ', 80, ', v, 'sec', '>')
            print('\n')

    def cal_congestionwindsize(self, packets):        
        pacs = {}
        for ip, tcp in packets:
            if tcp.srcport in self.srcports:
                if (tcp.srcport, tcp.dstport) not in pacs:
                    pacs[(tcp.srcport, tcp.dstport)] = [tcp]
                else:
                    pacs[(tcp.srcport, tcp.dstport)].append(tcp)
            else:                
                pacs[(tcp.dstport, tcp.srcport)].append(tcp)
        for k, v in pacs.items():            
            print("\nCongestion window for flow: ", k)
            acks = {}
            sent = {}
            icwnd = 1                       
            mss = v[0].mss
            cwnd = icwnd
            i = 1
            rwnd = v[1].windsize // mss
            ssthresh = rwnd // 2
            for t in v[3:]:
                #print("threshold value is " + str(ssthresh))                
                if t.flag_ack and t.srcport in self.dstports:
                    if t.ackno not in acks:
                        acks[t.ackno] = 1
                    else:
                        acks[t.ackno] += 1
                    if acks[t.ackno] == 3 and sent[t.ackno] < 2:
                        #print('thriple ack', str(ssthresh), str(cwnd))
                        #print('triple duplicate' + str(t.ackno))
                        ssthresh = cwnd // 2
                        cwnd //= 2
                    else:                        
                        if cwnd > rwnd:
                            cwnd = ssthresh
                            #print(cwnd * mss, rwnd)
                        elif cwnd < rwnd:
                            if cwnd < ssthresh:
                                #print(cwnd, ssthresh)
                                cwnd = min(2 * cwnd, ssthresh)
                            else:
                                #print(cwnd, ssthresh)
                                cwnd += 1
                    print(str(i) + ' congest window size: ' + str(cwnd))
                    i += 1
                    if i > 10:
                        break
                elif t.flag_ack and t.srcport in self.srcports:
                    if t.seqno not in sent:
                        sent[t.seqno] = 1
                    else:
                        sent[t.seqno] += 1
                    if sent[t.seqno] == 2:
                        if (t.seqno in acks and acks[t.seqno] < 3) or (t.seqno not in acks):
                            #print('retransmission due to time out', str(t.seqno))
                            ssthresh = cwnd / 2
                            cwnd = icwnd                        
                            print(str(i) + ' congest window size: ' + str(cwnd))
                            i += 1
                            if i > 10:
                                break            
        print('\n')

    def cal_retransmissions(self, packets):
        pacs = {}
        for ip, tcp in packets:
            if tcp.srcport in self.srcports:
                if (tcp.srcport, tcp.dstport) not in pacs:
                    pacs[(tcp.srcport, tcp.dstport)] = [tcp]
                else:
                    pacs[(tcp.srcport, tcp.dstport)].append(tcp)
            else:                
                pacs[(tcp.dstport, tcp.srcport)].append(tcp)
        acks = {}
        sent = {}
        triple = {}
        timeout = {}
        for k, v in pacs.items():            
            triple[k] = 0
            timeout[k] = 0
            data = False
            for t in v:
                if data == True:
                    if t.flag_fin == 1:
                        break                        
                    if t.flag_ack and t.srcport in self.dstports:
                        if t.ackno not in acks:
                            acks[t.ackno] = 1
                        else:
                            acks[t.ackno] += 1                    
                    elif t.flag_ack and t.srcport in self.srcports:
                        if t.seqno not in sent:
                            sent[t.seqno] = 1
                        else:
                            sent[t.seqno] += 1
                        if sent[t.seqno] == 2 and (t.seqno not in acks or (t.seqno in acks and acks[t.seqno] < 3)):
                            timeout[k] += 1
                        elif sent[t.seqno] == 2 and t.seqno in acks and acks[t.seqno] >= 3:
                            triple[k] += 1                      
                else:
                    if t.flag_push == 1:
                        data = True                         
                        sent[t.seqno] = 1  
        print('Retransmissions due to triple duplicate acks')                     
        print(triple)
        print('\n')
        print('Retransmissions due to time out')
        print(timeout)        

def main():
    wr = wiresharksamp()
    packets = wr.collect_packets()
    wr.count_TCP_connections(packets)
    # print(TCP_flows_count)
    wr.seq_ack_nums_windsize(packets)
    wr.cal_throughput(packets)
    wr.cal_lossrate(packets)
    wr.cal_RTT(packets)
    wr.cal_congestionwindsize(packets)
    wr.cal_retransmissions(packets)

if __name__ == "__main__" :
    main()