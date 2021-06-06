//
//  ProxyServer.cpp
//  SocketProxyServer
//  阅读Socks协议RFC文档，实现Socks代理服务器
//  完成步骤：
//  1. 创建连接，实现客户端到Socks代理服务器的连接，这里使用TCP建立可靠的连接
//  2. 进行协议认证（客户端发送认证请求，服务器返回认证响应）（SOCKS协议流程第一步）
//  进行协议认证，首先确认版本号，对于sock4版本，则只需要对方法进行一个确认即可，若符合则进行一个连接并转发数据，而对于sock5版本，首先在确认版本后，需要确认方法类型，这里只提供两种方法，即无需认证和用户密码认证，对于用户密码认证，则进行一个获取用户名参数和密码参数并进行一个认证后即可，认证后即发送响应报文，之后进行一个转发服务。
//  3. 客户端发送连接信息，服务器进行确认并返回响应
//  4. 服务器向目标服务器发送对于信息请求，并返回到客户端
//  认证请求：
//  +---------++---------++-----------+
//  ｜   VER   ｜NMETHOD  ｜ METHODS   |
//  +---------++---------++-----------+
//
//  认证响应：
//  +---------++---------++
//  ｜   VER   ｜ METHOD  ｜
//  +---------++---------++
//
//  连接请求：
//  +------+------+--------+----------+---------+-------------+
//  ｜ VER ｜ CMD ｜   RSV  ｜   ATYP  |   ADDR   |     PORT   |
//  +------+------+--------+----------+---------+-------------+
//
//  连接响应：
//  +------+------+--------+----------+---------+-------------+
//  ｜ VER ｜ REP ｜   RSV  ｜   ATYP  |   B.ADDR |   B.PORT   |
//  +------+------+--------+----------+---------+-------------+
//
//
//Created by Haruki on 2021/5/19.
//
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <pthread/pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netdb.h>


static int proxyServerSock;
enum method_type{
    NoAuth=0x00,
    UserPass=0x02,
    Reject=0xff
};

enum cmd_type{
    Connect=0x01,//TCP
    UDP=0x03
};

enum cmd_sock4{
    OK_DONE=0x5A,
    REJECT=0x5B
};
enum addr_type{
    IPv4=0x01,
    Domain=0x03
};

enum version{
    Ver4=0x04,
    Ver5=0x05
};

enum status{
    success=0x00,
    fail=0xff
};

struct request_sock4{
    char ver;
    char cmd;
    char port[2];
    char ip[4];
    char NF=0x00;
};

struct response_sock4{
    char ver;
    char cmd;
    char port[2];
    char ip[4];
};

struct Lisence_reques{
    char ver;
    char nummethod;
    char methods[255];
};

struct Auth_response{
    char ver;
    char method;
};

struct connect_request{
    char ver;
    char cmd;
    char rsv;
    char type;
    char address[4];
    char port[2];
};

struct connect_response{
    char ver;
    char rep;
    char rsv;
    char type;
    char address[4];
    char port[2];
};


char Ver;
int default_port;
//创建Proxy套接字，绑定本机地址：0.0.0.0:1080 ，并等待客户端发送第一个TCP连接请求
void create_TCP_socket(){
    proxyServerSock=socket(AF_INET, SOCK_STREAM, 0);
    if (proxyServerSock==-1) {
        printf("establish connection failed!\n");
        exit(-1);
    }

    sockaddr_in proxyServer_addr;
    bzero(&proxyServer_addr, sizeof(sockaddr));
    proxyServer_addr.sin_family=AF_INET;
    proxyServer_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    proxyServer_addr.sin_port=htons(default_port);
    int ret=bind(proxyServerSock, (struct sockaddr*)&proxyServer_addr, sizeof(proxyServer_addr));
    if(ret==-1){
        printf("Sock bind failed.\n");
        exit(-1);
    }
    if(listen(proxyServerSock, 50)==-1){
        printf("Sock listen set failed.\n");
        exit(-1);
    }
    
}


//认证成功后，即可进行数据转发，使用select模型
void sock_Transfer(int client_fd,int original_server_fd){
    printf("线程%u正在转发数据\n",pthread_self());
    char recv_buff[1024*512]={0};
    fd_set allsocket;
    struct timeval time_out;//最大时延设置为15秒
    time_out.tv_sec=15;
    time_out.tv_usec=0;
    
    
    while (1) {
        FD_ZERO(&allsocket);
        FD_SET(client_fd,&allsocket);//加入客户端套接字
        FD_SET(original_server_fd,&allsocket);//加入初始服务器套接字
        
        //进行套接字选择，对有响应的套接字进行对应处理，客户端接收请求报文，初始服务器端请求对应目标数据，并进行转发到初始套接字
        int ret=select(client_fd>original_server_fd?client_fd+1:original_server_fd+1, &allsocket, NULL, NULL, NULL);
        //select返回0代表无响应，select返回-1代表套接字出错，一般为中断连接；返回>0代表有响应，并把有响应的套接字加入到fd_read数组中
        if (ret==0) {
            continue;
        }
        else if (ret==-1){
            break;
        }
        //处理有响应的socket
        //处理客户端请求数据报文
        if (FD_ISSET(client_fd,&allsocket)) {
            memset(recv_buff, 0, sizeof(recv_buff));
            //接收请求报文
            ret=recv(client_fd, recv_buff, sizeof(recv_buff), 0);
            if (ret<=0) {
                break;
            }
            else{
                //转发请求信息
                ret=write(original_server_fd, recv_buff, ret);
                if (ret==-1) {
                    break;
                }
            }
        }
        //对服务器发来的信息进行转发
        else if(FD_ISSET(original_server_fd,&allsocket)){
            memset(recv_buff, 0, sizeof(recv_buff));
            //接受目标信息
            ret=recv(original_server_fd, recv_buff, sizeof(recv_buff), 0);
            if (ret<=0) {
                break;
            }
            else{
                //转发目标信息
                ret=write(client_fd, recv_buff, ret);
                if (ret==-1) {
                    break;
                }
            }
        }
    }
    return;
    
}




bool Ver4_Socks(char info[],int client_fd){
    response_sock4 response;
    memcpy(&response, info, sizeof(response_sock4));
    if (response.cmd!=Connect) {
        printf("Reject cmd_type excpt type:Connect.\n");
        response.cmd=REJECT;
    }
    else{
        printf("Cmd-type: Connect.\n");
        response.cmd=OK_DONE;
    }
    response.ver=0x00;
    int ret=write(client_fd, &response, sizeof(response_sock4));
    if (ret<0) {
        printf("返回响应请求失败。\n");
        return false;
    }
    return true;
}


bool UserPassComfirm(int client_fd){
    char buff[40]={0};
    int ret=read(client_fd, buff, sizeof(buff));
    int userLen=(unsigned int)buff[1];
    char *user;
    for (int i=2,j=0; i<userLen+2; i++,j++) {
        user[j]=buff[i];
    }
    int passLen=(unsigned int)buff[userLen+2];
    char *pass;
    for (int i=userLen+1,j=0; i<userLen+1+passLen; i++,j++) {
        pass[j]=buff[i];
    }
    if (strcmp(user, "Haruki")&&strcmp(pass, "123456")) {
        printf("用户密码验证成功。\n");
        return true;
    }
    printf("用户密码验证失败。\n");
    return false;
}

bool Ver5_Socks(char info[],int client_fd){
    Auth_response response;
    for (int i=1; i<=(unsigned int)info[1]; i++) {
        if (info[i+1]==NoAuth) {
            response.method=NoAuth;
        }
        if (info[i+1]==UserPass) {
            response.method=UserPass;
        }
    }
    response.ver=Ver5;
    int ret=write(client_fd, &response, 2);
    if (ret<0) {
        printf("返回响应请求失败。\n");
        return false;
    }
    if(response.method==UserPass){
        return UserPassComfirm(client_fd);
    }
    return true;
}





//comfirm it is a OK request. Connect to the original server and transfer data to client.
void version_comfirm(int fd,struct sockaddr* clientSockAddr,socklen_t len){
    char comfirmInfo[16]={0};
    bzero(&comfirmInfo, sizeof(comfirmInfo));
    read(fd, comfirmInfo, sizeof(comfirmInfo));
    Ver=comfirmInfo[0];
    
    if (Ver==Ver4) {
        if (Ver4_Socks(comfirmInfo,fd)) {
            response_sock4 responseInfo;
            bzero(&responseInfo, sizeof(responseInfo));
            memcpy(&responseInfo, comfirmInfo, sizeof(response_sock4));
            
            //get server address.
            struct sockaddr_in original_server_addr;
            bzero(&original_server_addr, sizeof(sockaddr_in));
            original_server_addr.sin_family=AF_INET;
            memcpy(&original_server_addr.sin_addr, &responseInfo.ip, sizeof(responseInfo.ip));
            memcpy(&original_server_addr.sin_port, &responseInfo.port, sizeof(responseInfo.port));
            
            
            //complete the parameters concreate. start to connect the original server.
            int original_server_fd=socket(AF_INET, SOCK_STREAM, 0);
            if (original_server_fd==-1) {
                printf("create socket faild.\n");
                return;
            }
            
            int ret=connect(original_server_fd, (struct sockaddr*)&original_server_addr, sizeof(original_server_addr));
            
            if (ret==-1) {
                printf("connection to original server fail.\n");
                return;
            }
            
            printf("connect to original server success.\n");
            
            //sock4 start transfer data once it pass the Authorize, without sending back response that successfully connect to the original server.
            //start get info and transfer info to client.
            
            sock_Transfer(fd,original_server_fd);
        }
        
    }
    else if(Ver==Ver5){
        if (Ver5_Socks(comfirmInfo,fd)) {
            char connection_request[200]={0};
            bzero(connection_request, sizeof(connection_request));
            read(fd, connection_request, 200);
            
            connect_request request_1;
            bzero(&request_1, sizeof(request_1));
            memcpy(&request_1, &connection_request, sizeof(connect_request));

            if (request_1.cmd!=Connect) {
                printf("only support connect cmd.\n");
                return;
            }
            
            if (request_1.type!=IPv4&&request_1.type!=Domain) {
                printf("only support IPv4 or Domain protocol.\n");
                return;
            }
            
            //get server address.
            struct sockaddr_in original_server_addr;
            bzero(&original_server_addr, sizeof(sockaddr_in));
            original_server_addr.sin_family=AF_INET;
            if (request_1.type==IPv4) {
                memcpy(&original_server_addr.sin_addr.s_addr, &request_1.address, 4);
                memcpy(&original_server_addr.sin_port, &request_1.port, 2);
            }
            else{
                int dormainLen=request_1.address[0]&0xff;
                char hostname[dormainLen];
                for (int i=0; i<dormainLen; i++) {
                    hostname[i]=connection_request[i+5];
                }
                char port[2]={0};
                port[0]=connection_request[dormainLen+5];
                port[1]=connection_request[dormainLen+6];
                hostent* host=gethostbyname(hostname);
                if (host==NULL) {
                    printf("Get host address fail.\n");
                    return;
                }
                memcpy(&original_server_addr.sin_addr.s_addr, host->h_addr, host->h_length);
                memcpy(&original_server_addr.sin_port, port, 2);
            }
            
            //complete the parameters concreate. start to connect the original server.
            int original_server_fd=socket(AF_INET, SOCK_STREAM, 0);
            if (original_server_fd==-1) {
                printf("create socket faild.\n");
                return;
            }
            
            int ret=connect(original_server_fd, (struct sockaddr*)&original_server_addr, sizeof(original_server_addr));
            
            if (ret==-1) {
                printf("connection to original server fail.\n");
                return;
            }
            
            printf("connect to original server success.\n");
            
            //now connection is done. proxyServer response the client that it connect to the original server successfuly.
            char connect_res[10]={0};
            bzero(connect_res, sizeof(connect_res));
            
            connect_response connect_resp;
            bzero(&connect_resp, sizeof(connect_resp));
            connect_resp.ver=0x05;
            connect_resp.rep=0x00;
            connect_resp.rsv=0x00;
            connect_resp.type=0x01;
            memcpy(&original_server_addr.sin_addr.s_addr, &request_1.address, 4);
            memcpy(&original_server_addr.sin_port, &request_1.port, 2);
            memcpy(&connect_resp.address,&request_1.address , 4);
            memcpy(&connect_resp.port, &request_1.port, 2);
            
            memcpy(connect_res, &connect_resp, sizeof(connect_resp));
            ret=write(fd, &connect_res, 10);
            if (ret==-1) {
                printf("fail to send response.\n");
            }
            printf("complete to send response.\n");
            
            //start get info and transfer info to client.
            
            sock_Transfer(fd,original_server_fd);
        }
    }
    else{
        printf("version not permit or request info wrong or response send fails.\n");
        return;
    }
   
}




void* pthread_connection(void*){
    pthread_t pid=pthread_self();
    printf("线程%u正在运行连接\n",pid);
    struct sockaddr_in clientSockAddr;
    socklen_t len=sizeof(clientSockAddr);
    bzero(&clientSockAddr, len);
    int clientSockFd=accept(proxyServerSock, (struct sockaddr*)&clientSockAddr, &len);
    pthread_t thrId;
    pthread_create(&thrId, NULL, pthread_connection, NULL);
    char Ip[16]={0};
    int port;
    inet_ntop(AF_INET, &clientSockAddr.sin_addr, Ip, len);
    port=ntohs(clientSockAddr.sin_port);
    printf("连接至：%s:%d\n",Ip,port);
    
    version_comfirm(clientSockFd,(struct sockaddr*)&clientSockAddr,len);
    printf("确认连接，线程%u退出\n",pthread_self());
    pthread_kill(pid, 0);
    return NULL;
}

int main(int args,char* argv[]){
    if (args>=1&&argv[1]!=NULL) {
        default_port=atoi(argv[1]);
    }
    else{
        default_port=14301;
    }
    create_TCP_socket();
    printf("完成Socket初始化.\n");
    while (true) {
        pthread_connection(NULL);
    }
}
