//
//  main.cpp
//  PacketCapture
//
//  Created by 李世豪 on 2021/6/1.
//
#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
//#define DISPLAY_MODE          //打印每个接收到的数据包信息
//#define LINKLIST_STRORE_MODE  //用链表将不同MAC地址的数据包的mac地址进行存储，来获得来自不同MAC地址的数据包的长度（每个MAC地址只接收一次）
#define STATISTIC_MODE          //统计接收来自不同MAC和ip的数据总长度，以及发送到不同MAC和IP的数据总长度

struct csv_record_form{
    char local_time[20];
    u_char src_mac[6];
    u_char src_ip[4];
    u_char des_mac[6];
    u_char des_ip[4];
    int length;
};

struct mac_ip_list{
    u_char mac[6];
    u_char ip[4];
    mac_ip_list* next;
};

struct mac_ip_list* des_list=new mac_ip_list();
struct mac_ip_list* src_list=new mac_ip_list();
struct mac_ip_list* des_p=des_list;
struct mac_ip_list* src_p=src_list;
char err_buff[PCAP_ERRBUF_SIZE];
long send_size=0;
long recv_size=0;
time_t start_sec;
u_char host_mac[6];
u_char host_ip[4];

pcap_t* device_fp=pcap_open_live("en0", 1526, 0, 0, err_buff);


void log_record(struct csv_record_form& record){
    FILE* log_file=fopen("./log_Packet_capture.csv", "a");
    fprintf(log_file, "%s,",record.local_time);
    fprintf(log_file, "%02x-%02x-%02x-%02x-%02x-%02x,",record.src_mac[0],record.src_mac[1],record.src_mac[2],record.src_mac[3],record.src_mac[4],record.src_mac[5]);
    fprintf(log_file, "%d.%d.%d.%d,",record.src_ip[0],record.src_ip[1],record.src_ip[2],record.src_ip[3]);
    fprintf(log_file, "%02x-%02x-%02x-%02x-%02x-%02x,",record.src_mac[0],record.src_mac[1],record.src_mac[2],record.src_mac[3],record.src_mac[4],record.src_mac[5]);
    fprintf(log_file, "%03d.%03d.%03d.%03d,",record.des_ip[0],record.des_ip[1],record.des_ip[2],record.des_ip[3]);
    fprintf(log_file, "%d\n",record.length);
    fclose(log_file);
}



int get_IP_header_length(const u_char* data){
    u_char size=*(data+14);
    size<<=4;
    size>>=4;
    return (int)size*4;
}



int get_TCP_header_length(const u_char* data,int ip_header_size){
    u_char size=*(data+14+ip_header_size+12);
    printf("%0x",size);
    size>>=4;
    return (int)size*4;
}

void handle_packets(u_char* arg,const struct pcap_pkthdr* pkthdr,const u_char* packet_data){
    //int *count=(int*)arg;
    char l_time[20];
    strftime(l_time, 20, "%Y-%m-%d %H:%M:%S", localtime(&pkthdr->ts.tv_sec));
    csv_record_form record;
    bcopy(l_time, record.local_time, sizeof(l_time));
    bcopy(packet_data,record.des_mac, sizeof(record.des_mac));
    bcopy(packet_data+6,record.src_mac, sizeof(record.src_mac));
    bcopy(packet_data+30,record.des_ip , sizeof(record.des_ip));
    bcopy(packet_data+26,record.src_ip , sizeof(record.src_ip));
    record.length=pkthdr->caplen;
    log_record(record);
#ifdef DISPLAY_MODE
    printf("Packet num:%d\n",++(*count));
    printf("Packet captured size:%d\n",record.length);
    printf("Packet size:%d\n",pkthdr->len);
    printf("Packet Arrival time:%s\n",record.local_time);
    printf("Packet Src_Mac:%02x-%02x-%02x-%02x-%02x-%02x\n",record.src_mac[0],record.src_mac[1],record.src_mac[2],record.src_mac[3],record.src_mac[4],record.src_mac[5]);
    printf("Packet Src_IP:%d.%d.%d.%d\n",record.src_ip[0],record.src_ip[1],record.src_ip[2],record.src_ip[3]);
    printf("Packet Des_Mac:%02x-%02x-%02x-%02x-%02x-%02x\n",record.des_mac[0],record.des_mac[1],record.des_mac[2],record.des_mac[3],record.des_mac[4],record.des_mac[5]);
    printf("Packet Des_IP:%d.%d.%d.%d\n",record.des_ip[0],record.des_ip[1],record.des_ip[2],record.des_ip[3]);
    printf("\n\n");
#endif
#ifdef STATISTIC_MODE

    if (strncmp((const char*)record.des_mac, (const char*)host_mac,6)==0) {
        recv_size+=record.length;
    }
    if (strncmp((const char*)record.src_mac, (const char*)host_mac,6)==0) {
        send_size+=record.length;
    }
#endif
#ifdef LINKLIST_GROUP_MODE
    bool same_src=true;
    mac_ip_list* tp_src=src_list->next;
    while (tp_src!=NULL) {
        if (strncmp((char*)tp_src->mac, (char*)record.src_mac,6)==0) {
            same_src=false;
            break;
        }
        tp_src=tp_src->next;
    }

    if (!same_src) {
        //用链表记录Src_Mac地址
        struct mac_ip_list* tmp_src=new mac_ip_list();
        memcpy(tmp_src->mac, record.src_mac, sizeof(record.src_mac));
        memcpy(tmp_src->ip, record.src_ip, sizeof(record.src_ip));
        src_p->next=tmp_src;
        src_p=tmp_src;
        send_size+=record.length;
    }

    bool flag_des=true;
    mac_ip_list* tp_des=des_list->next;
    while (tp_des!=NULL) {
        if (strncmp((char*)tp_des->mac, (char*)record.des_mac,6)==0) {
            flag_des=false;
            break;
        }
        tp_des=tp_des->next;
    }

    if (!flag_des) {//用链表记录Des_Mac地址
        struct mac_ip_list* tmp_des=new mac_ip_list();
        memcpy(tmp_des->mac, record.des_mac, sizeof(record.des_mac));
        memcpy(tmp_des->ip, record.des_ip, sizeof(record.des_ip));
        des_p->next=tmp_des;
        des_p=tmp_des;
        recv_size+=record.length;
    }
#endif
}

void print_result(int arg){
    time_t now_sec=time(NULL);
    char t[20];
    strftime(t, 20, "%Y-%m-%d %H:%M:%S", localtime(&now_sec));
    printf("Data stream statistic until %s\n",t);
    printf("Data size send to different Mac: %lu\n",recv_size);
    printf("Data size recv from different Mac: %lu\n",send_size);
    printf("\n\n");
    alarm(5);
}

bool get_host_mac(){
    struct pcap_pkthdr pkthdr;
    const unsigned char * data=pcap_next(device_fp, &pkthdr);
    if (data==NULL) {
        printf("fail to get host mac.\n");
        exit(-1);
    }
    memcpy(host_mac, data+6, 6);
    return true;
}


void capture_5_packets(){
    bpf_u_int32 net_ip;
    bpf_u_int32 net_mask;
    pcap_lookupnet("en0", &net_ip, &net_mask, err_buff);
    if (device_fp==NULL) {
        printf("open en0 interface failed.\nerrortype:%s",err_buff);
        exit(-1);
    }
    int getted=get_host_mac();
    while(!getted){
        getted=get_host_mac();
    }
    int count=0;
    struct bpf_program filter;
#ifdef FTP_ANALYSE_MODE
    //过滤选择FTP命令控制端口
    int ret=pcap_compile(device_fp, &filter, "tcp port 21", 1, 0);
#else
    int ret=pcap_compile(device_fp, &filter, "ip", 1, 0);
#endif
    if (ret==-1) {
        printf("filter gramma error.\n");
        exit(-1);
    }
    pcap_setfilter(device_fp, &filter);
    pcap_loop(device_fp, -1, handle_packets, (u_char*)&count);
}

int main()
{
    signal(SIGALRM, print_result);
    alarm(5);
    capture_5_packets();
    return 0;
}
