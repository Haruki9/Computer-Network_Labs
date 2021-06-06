//
//  ServerMethod.cpp
//  LicenseProject
//
//  Created by 李世豪 on 2021/5/26.
//

#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define SERVER_PORT 43999
#define MAX_ONLINES 2
#define TICKET_AVAIL 0
#define SERVER 1
#define CLIENT 0

struct ticket_addr{
    int pid;
    struct sockaddr addr;
};

struct ticket_addr tickets_list[MAX_ONLINES];

//ticket_list: >0 is used, 0 to be available.
int ticket_list[MAX_ONLINES]={0};
static int server_sock_fd=-1;
int avail_ticket_num=MAX_ONLINES;

//购买服务凭证
void creating_license_key(char* response){
    char sequense[10];
    for (size_t i = 0; i < 10; i++)
    {
        srand((int)time(0));
        sequense[i]=48+random()%10;
    }
    sprintf(response,"%s",sequense);
    FILE* key_file=fopen("./auth_key.txt","w");
    fprintf(key_file,"%s",sequense);
    fclose(key_file);
}

int create_UDP_server_socket(char* hostname,int port){
    int fd=socket(AF_INET,SOCK_DGRAM,0);
    if (fd==-1) {
        printf("create server socket fail.\n");
    }
    sockaddr_in addr;
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);
    addr.sin_addr.s_addr=INADDR_ANY;
    //hostent *host=gethostbyname(hostname);
    //bcopy(&host->h_addr_list,&addr.sin_addr,host->h_length);

    if (bind(fd,(sockaddr*)&addr,sizeof(sockaddr))!=0)
    {
        printf("bind function fail.");
        return -1;
    }
    return fd;
}

void log_record(char* record,int server_client){
    //FILE* logfile=fopen("./server_log/server_log.txt","a");
    FILE* logfile=fopen("./server_log.txt","a");
    fprintf(logfile,"%s:%s",server_client?"server":"client",record);
    fclose(logfile);
}


int setup(){
    log_record("[Server]: server start...\n",SERVER);
    char hostname[30];
    gethostname(hostname,30);
    server_sock_fd=create_UDP_server_socket(hostname,SERVER_PORT);
    if (server_sock_fd==-1)
    {
        printf("create server socket fail.\n");
        exit(-1);
    }
    for (size_t i = 0; i < MAX_ONLINES; i++)
    {
        ticket_list[i]=0;
        tickets_list[i].pid=0;
        bzero(&tickets_list[i].addr, sizeof(sockaddr));
    }
    printf("[Server]: server initialize done, waiting for request...\n");
    log_record("[Server]: server initialize done, waiting for request...\n",SERVER);
    return server_sock_fd;
}

void handle_HELLO(char* request,char* response,sockaddr_in &client_addr){
    int pid=atoi(request+5);
    if (avail_ticket_num==0)
    {
        sprintf(response,"FAIL ticket not available");
        return;
    }
    
    for (int i = 0; i < MAX_ONLINES; i++)
    {
        if (ticket_list[i]==0)
        {
            ticket_list[i]=pid;
            tickets_list[i].pid=pid;
            memcpy(&tickets_list[i].addr, &client_addr, sizeof(sockaddr));
            memset(response, 0, 30);
            sprintf(response,"TICK %d.%d",pid,i+1);
            avail_ticket_num--;
            break;
        }
    }
    
}

void handle_COMF(char* request,char* response){
    char key[20];
    char server_key[20];
    strcpy(key, request+5);
    FILE* key_file=fopen("./auth_key.txt","r");
    fscanf(key_file,"%s",server_key);
    if (strncmp(key, server_key,10)==0) {
        memset(response, 0, 30);
        sprintf(response, "PASS");
        return;
    }
    memset(response, 0, 30);
    sprintf(response, "FAIL");
    return;
}

void handle_GOODBYTE(char* request,char* response){
    char* token1=strtok(request+5,".");
    char* token2=strtok(NULL, ".");
    int pid=atoi(token1);
    int number=atoi(token2);
    if (pid==ticket_list[number-1])
    {
        memset(response, 0, 30);
        sprintf(response,"THANX return ticket success");
        ticket_list[number-1]=0;
        tickets_list[number-1].pid=pid;
        bzero(&tickets_list[number-1].addr, sizeof(sockaddr));
        avail_ticket_num++;
        return ;
    }
    memset(response, 0, 30);
    sprintf(response,"THANX return ticket fails");
}

void handle_buy_request(char* response){
    char key[20];
    bzero(&key, 20);
    creating_license_key(key);
    sprintf(response,"RETK %s",key);
}

void deal_with_request(char* request,sockaddr_in &client_addr){
    log_record("begin.",SERVER);
    char response[30];
    memset(response, 0, 30);
    log_record(request,CLIENT);
    printf("[Client]: %s\n",request);
    if (strncmp("KBUY",request,4)==0)
    {
        handle_buy_request(response);
    }
    else if(strncmp(request, "COMF",4)==0){
        handle_COMF(request, response);
    }
    else if (strncmp(request,"HELO",4)==0)
    {
        handle_HELLO(request,response,client_addr);
    }
    else if (strncmp(request,"GBYE",4)==0)
    {
        handle_GOODBYTE(request,response);
    }
    else 
    {
        printf("[Server]: Request not vailed.");
        sprintf(response,"FAIL invalid request");
    }
    socklen_t len=sizeof(client_addr);
    printf("[Server]: %s\n",response);
    int ret=sendto(server_sock_fd,response,sizeof(response),0,(struct sockaddr*)&client_addr,len);
    if (ret==-1)
    {
        printf("[Server]:server send response fail.");
        exit(-1);
    }
    log_record(response,SERVER);
    return;
}

//处理客户端未正常返回：设置定时器，使用signal
//函数，每隔一段时间，服务器对在运行客户端逐个发送确认运行请求，如果客户端返回信息，则认为其仍在运行，
//否则认为该客户端未正常退出。
//客户端响应：这里客户端响应需要使用多线程编程，
//但是本人并不会多线程而且没有那么多的时间，
//因此就不实现客户端响应这个功能先了，同时也就是说并没有完成这个处理客户端崩溃的问题。
void handle_client_lost(int arg){
    char* request="ALIV";
    char response[4];
    for (int i=0; i<MAX_ONLINES; i++) {
        if (ticket_list[i]!=0) {
            int len=sizeof(sockaddr);
            int ret=sendto(server_sock_fd, request, sizeof(response), 0, &tickets_list[i].addr, len);
            if (ret==-1) {
                printf("[Server]: fail to send alive check.\n");
                return;
            }
            
            ret=recvfrom(server_sock_fd, &response, 4, 0, &tickets_list[i].addr, (socklen_t*)&len);
            if (ret==-1) {
                printf("[Server]: fail to recv live response.\n");
                return;
            }
            if (memcmp(&response, "LIVE", 4)!=0) {
                printf("[Server]: reclaim ticket success.\n");
                ticket_list[i]=0;
                tickets_list[i].pid=0;
                bzero(&tickets_list[i].addr,sizeof(sockaddr));
            }
        }
    }
    alarm(30);
}
