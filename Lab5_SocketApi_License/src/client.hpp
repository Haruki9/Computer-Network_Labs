//  ClientMethod.hpp
//  LicenseProject
//
//  Created by 李世豪 on 2021/5/26.
//

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>

static int pid=-1;
static int client_sock_fd=-1;
static struct sockaddr_in server_addr;
static socklen_t server_addr_len;
static char ticket_str[30];
static int have_ticket=0;
static bool have_auth_key=false;

#define SERVER_PORT 43999
#define CLIENT_PORT 38892
#define PEixt(p){perror(p);exit(0);}

void search_local_auth_key(){
    FILE* file=fopen("./auth_key.txt","r");
    if (file==NULL) {
        printf("fail to open auth_key.\n");
        return;
    }
    char key[30];
    fscanf(file,"%s\n",key);
    printf("Get local ticket: %s\n",key);
    if (strlen(key)==0)
    {
        have_auth_key=false;
    }
    int ret=fclose(file);
    if (ret!=0) {
        printf("false to release.\n");
    }
    have_auth_key=true;
    return;
}

bool comfirm_auth_key(char* key){
    char server_key[30];
    char request[30];
    char response[30];
    sprintf(request,"COMF %s",key);
    int ret=sendto(client_sock_fd,request,sizeof(request),0,(struct sockaddr*)&server_addr,server_addr_len);
    if (ret==-1)
    {
        return false;
    }
    ret=recvfrom(client_sock_fd,response,30,0,NULL,NULL);
    if (ret==-1)
    {
        return false;
    }
    if (strncmp(response, "PASS",4)==0) {
        return true;
    }
    return false;
}

bool buy_auth_key(char* key){
    char request[30];
    char response[30];
    sprintf(request,"KBUY %d",getpid());
    int ret=sendto(client_sock_fd,request,sizeof(request),0,(struct sockaddr*)&server_addr,server_addr_len);
    if (ret==-1)
    {
        printf("buy_auth_key request sending fail.\n");
        return false;
    }
    ret=recvfrom(client_sock_fd,response,30,0,NULL,NULL);
    if (ret==-1)
    {
        printf("recv auth_key fail.\n");
        return false;
    }
    memcpy(key,response+5,10);
    FILE* file=fopen("./auth_key.txt","w");
    fprintf(file,"%s\n",key);
    fclose(file);
    return true;
}

int create_UDP_client_socket(char* hostname,int port){
    struct sockaddr_in addr;
    int fd;
    fd=socket(PF_INET,SOCK_DGRAM,0);
    if (fd==-1)
    {
        exit(-1);
    }
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);
    addr.sin_addr.s_addr=INADDR_ANY;
    //bcopy(&addr.sin_addr,hp->h_addr_list,hp->h_length);
    bcopy(&addr, &server_addr, sizeof(server_addr));
    //memcpy(&server_addr,(struct sockaddr*)&addr,sizeof(sockaddr));
    if (bind(fd,(struct sockaddr*)&addr,sizeof(sockaddr))!=0)
    {
        return -1;
    }
    server_addr.sin_port=htons(SERVER_PORT);
    return fd;
}


//发送确认许可证请求，返回
void transfer_info(char* request,char* response){
    sockaddr retaddr;
    int sendLen=sendto(client_sock_fd,request,30,0,(struct sockaddr*)&server_addr,sizeof(server_addr));
    if (sendLen==-1)
    {
        PEixt("send request fail.\n");
        response=NULL;
    }
    int recvLen=recvfrom(client_sock_fd,response,30,0,(struct sockaddr*)&server_addr,&server_addr_len);
    if (recvLen==-1)
    {
        PEixt("recv response fail.\n")
        response=NULL;
    }
}

void setup(){
    char host_name[30]={0};
    pid =getpid();
    gethostname(host_name,sizeof(host_name));
    client_sock_fd=create_UDP_client_socket(host_name,CLIENT_PORT);
    if (client_sock_fd==-1)
    {
        /* code */
        PEixt("create server socket fail.\n");
    }
    server_addr_len=sizeof(server_addr);
}

void shutdown_fd(){
    close(client_sock_fd);
}

//如果该用户没有许可凭证，执行get操作;如有则跳过
int get_ticket(){
    if (have_ticket==1)
    {
        return 0;
    }
    char response[30];
    char requestbuff[30];
    bzero(requestbuff,sizeof(requestbuff));
    sprintf(requestbuff,"HELO %d",pid);
    printf("Send request:HELO pid to Server.\n");
    transfer_info(requestbuff,response);
    if (strlen(response)==0)
    {
        printf("get response from server fail.\n");
        return -1;
    }
    //接下来判断得到的响应信息
    if (strncmp(response,"TICK", 4)==0)
    {
        /* code */
        have_ticket=1;
        strcpy(ticket_str,response+5);
        printf("Get a ticket.\n");
        return 0;
    }
    if (strncmp(response,"FAIL",4))
    {
        printf("Fail to get a ticketed.\n");
        return -1;
    }
    printf("response message form not support.\n");
    return -1;
}

//将空闲的许可证返还
int release_ticket(){
    if (have_ticket==0)
    {
        return 0;
    }
    
    char request[30];
    char response[30];
    memset(request, 0, 30);
    sprintf(request,"GBYE %s",ticket_str);
    transfer_info(request,response);
    if (strlen(response)==0)
    {
        /* code */
        printf("get response from server fail.\n");
        return -1;
    }
    if (strncmp(response,"THANX",5)==0)
    {
        /* code */
        bzero(ticket_str,sizeof(ticket_str));
        have_ticket=0;
        printf("return ticket success.\n");
        return 0;
    }
    printf("return ticket fail.\n");
    return -1;
}
