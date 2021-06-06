//
//  Server.cpp
//  LicenseProject
//  因为时间和个人能力有限，这里就不再实现一个服务器网页api来对服务器凭证列表进行一个数据监控，
//  这里改用另一种方法，即每过一个时间，让服务器打印凭证列表，然后进行确认，注意：在控制台进行一个打印。
//  Created by 李世豪 on 2021/5/26.
//

#include <stdio.h>
#include <stdlib.h>
#include <istream>
#include "server.hpp"

//给客户发送一个许可证序列，完全随机生成，并存储在服务器本地密钥文件中，
//当用户第一次使用程序时，需要传输密钥，并由服务器进行认证方可使用该程序，
//之后由服务器查看当前凭证是否已经满员，并进行对应结果的回应


//已经大致上完成了主要功能，现在仍然缺少的部分主要是一个客户端崩溃处理，回收异常的凭证。
//这里使用signal函数进行一个信号发出执行向客户端发送问候的功能，若没收到回应，则认为客户端的凭证异常，收回
int main(){
    setup();
    sockaddr_in client_addr;
    char message[30];
    socklen_t len=sizeof(sockaddr);
//    signal(SIGALRM, handle_client_lost);
//    alarm(30);
    while (true)
    {
        memset(message, 0, 30);
        int ret = recvfrom(server_sock_fd,message,sizeof(message),0,(struct sockaddr*)&client_addr,&len);
        if (ret!=-1)
        {
            deal_with_request(message,client_addr);
        }
        else{
            printf("接收请求失败.");
        }
    }
    
}
