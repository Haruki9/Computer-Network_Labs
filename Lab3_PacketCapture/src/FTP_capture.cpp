//
//  FTP_capture.cpp
//  PacketCapture
//
//  Created by 李世豪 on 2021/6/3.
//

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
//#define DISPLAY_MODE
#define FTP_ANALYSE_MODE
struct csv_record_form{
    char local_time[20];
    u_char src_mac[6];
    u_char src_ip[4];
    u_char des_mac[6];
    u_char des_ip[4];
    int length;
};

char err_buff[PCAP_ERRBUF_SIZE];
long send_size=0;
long recv_size=0;
time_t start_sec;
u_char host_mac[6];
u_char host_ip[4];


pcap_t* device_fp=pcap_open_offline("./capture_objects.pcapng", err_buff);

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

u_char* FTP_USER_PASS_appen_record(const u_char* packet_data){
    //    int ip_header_size=get_IP_header_length(packet_data);
    //    int tcp_header_size=get_TCP_header_length(packet_data,ip_header_size);
    //首先要过滤是否是FTP协议，
    //判断方法一：对是否包含命令字段进行判断，如客户端请求一般包含字段（SYST，USER，PASS，CWD，PCWD，FEAT，PASV，PORT，MKD，EPRT，DELET，EPSV，LIST等等），服务器端返回码3字节（200：成功，202:命令未执行，220:服务准备就绪，227:进入被动模式，331，332:账号密码，421:服务器不可用，450:文件不可用，500：无效命令，等等）
    //判断方法二：对端口进行一个过滤选择，命令控制端口为21，数据传输端口为20
    //这里选择使用方法二，设置pcap过滤器对端口进行过滤，这里只保留端口21，进行一个命令控制学习
    //FTP命令报文格式，客户端：CMD 参数        服务器：状态码  参数
    //因为FTP是基于TCP协议，是TCP协议的一部分，而一般包含FTP的TCP协议的报文头长度为32bytes，新增了12bytes可选项描述tcp传输中的状态
    //因此可以认为TCP报文开始后32bytes之后的数据即为FTP命令请求报文
    //判断FTP报文结束，即FTP固定在CMD模式中以\t\n结束，hex分别为0x0d,0x0a;
    u_char FTP_stream[1024];
    memset(&FTP_stream, 0, sizeof(FTP_stream));
    int index=0;
    while (packet_data[index+14+20+32]!=0x0d&&packet_data[index+14+20+32+1]!=0x0a) {
        FTP_stream[index]=packet_data[index+14+20+32];
        index++;
    }
    FTP_stream[index]=0x0d;
    FTP_stream[index+1]=0x0a;
    bool user_ready=false;
    u_char USER[20];
    bzero(USER, 20);
    if (memcmp((u_char*)"USER", FTP_stream,4)==0) {
        pcap_pkthdr pk;
        const u_char* data=pcap_next(device_fp, &pk);
        if(data==NULL){
            printf("not capture.");
            exit(-1);
        }
        if (memcmp(data+14+20+32, (u_char*)"331", 3)==0) {
            user_ready=true;
            int i=5;
            while (FTP_stream[i]!=0x0d&&FTP_stream[i+1]!=0x0a) {
                USER[i-5]=FTP_stream[i];
                i++;
            }
            printf("USER:%s\n",USER);
        }
    }
    
    bool pass_ready=false;
    u_char PASS[20];
    bzero(USER, 20);
    pcap_pkthdr pass_pk;//过滤每次server返回状态后client发送确认tcp协议数据包
    pcap_next(device_fp, &pass_pk);
    const u_char* send_pass=pcap_next(device_fp, &pass_pk);
    if (memcmp(send_pass+14+20+32, (u_char*)"PASS", 4)==0) {
        pcap_pkthdr ret_pk;
        int pass_len=pass_pk.caplen-2-5-14-20-32;
        memcpy(PASS, send_pass+14+20+32+5, pass_len);
        printf("PASS:%s\n",PASS);
        const u_char* ret=pcap_next(device_fp, &ret_pk);
        if (memcmp("230", ret+14+20+32, 3)==0) {
            pass_ready=true;
        }
    }
    char appen[50];
    sprintf(appen, "%s,%s,%s",USER,PASS,pass_ready&&user_ready?"SUCCEED":"FAILED");
    printf("Result:%s\n\n\n",appen);
    return (u_char*)appen;
    
}

void log_ftp_record(struct csv_record_form& record,u_char* append){
    FILE* log_file=fopen("./log_FTP_Packet_capture.csv", "a");
    fprintf(log_file, "%s,",record.local_time);
    fprintf(log_file, "%02x-%02x-%02x-%02x-%02x-%02x,",record.src_mac[0],record.src_mac[1],record.src_mac[2],record.src_mac[3],record.src_mac[4],record.src_mac[5]);
    fprintf(log_file, "%d.%d.%d.%d,",record.src_ip[0],record.src_ip[1],record.src_ip[2],record.src_ip[3]);
    fprintf(log_file, "%02x-%02x-%02x-%02x-%02x-%02x,",record.src_mac[0],record.src_mac[1],record.src_mac[2],record.src_mac[3],record.src_mac[4],record.src_mac[5]);
    fprintf(log_file, "%03d.%03d.%03d.%03d,",record.des_ip[0],record.des_ip[1],record.des_ip[2],record.des_ip[3]);
    fprintf(log_file, "%s\n",append);
    fclose(log_file);
}

void handle_packets(u_char* arg,const struct pcap_pkthdr* pkthdr,const u_char* packet_data){
    int *count=(int*)arg;
    char l_time[20];
    strftime(l_time, 20, "%Y-%m-%d %H:%M:%S", localtime(&pkthdr->ts.tv_sec));
    csv_record_form record;
    bcopy(l_time, record.local_time, sizeof(l_time));
    bcopy(packet_data,record.des_mac, sizeof(record.des_mac));
    bcopy(packet_data+6,record.src_mac, sizeof(record.src_mac));
    bcopy(packet_data+30,record.des_ip , sizeof(record.des_ip));
    bcopy(packet_data+26,record.src_ip , sizeof(record.src_ip));
    record.length=pkthdr->caplen;
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
#ifdef FTP_ANALYSE_MODE
    if (memcmp(packet_data+14+20+32, (u_char*)"USER", 4)==0) {
        u_char* append=FTP_USER_PASS_appen_record(packet_data);
        log_ftp_record(record,append);
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

void capture_5_packets(){
    if (device_fp==NULL) {
        printf("open en0 interface failed.\nerrortype:%s",err_buff);
        exit(-1);
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
//    signal(SIGALRM, print_result);
//    alarm(15);
    printf("Here we will use FTP_USER_PASS_TEST_PCAP_FILE.pcapng file for test on the local direction.\n\n");
    printf("Running evironment: Mac or any Unix System.\n");
    printf("请将pcap文件放在同一目录下运行，并命名为capture_objects.pcapng，否则无法正确运行。\n注意可能需要用管理员权限运行，否则可能出现权限未许可问题。\n");
    printf("Start:\n");
    capture_5_packets();
    return 0;
}
