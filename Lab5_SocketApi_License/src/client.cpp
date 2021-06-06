//
//  Client.cpp
//  LicenseProject
/*  Client.cpp
    认证服务器的客户端，主要流程如下：
    1. 用户运行目标程序
    2. 该目标程序向服务器发送请求许可
    3. 等待服务器的回应
    4. 收到服务器回应，若允许（TICK ticked），则程序正常打开；若拒绝（FAIL no tickes）,程序拒绝运行并发生警告
 
    主要使用协议：UDP协议，即
    UDP：客户端或者服务器只需要发送请求或者响应即可，不需要确保一个持续连接。
    TCP：若使用TCP，则负荷和消耗太大，且功能过剩，浪费链路资源。
*/
//
//  Created by 李世豪 on 2021/5/26.
//

#include <stdio.h>
#include "client.hpp"

#define Perror(e,x){perror(e);exit(x);}

//main work function
void main_func(){
    printf("Now pass the license and running the program.\nSleeping for 30sec.\n");
    sleep(30);
}

int main(int args,char* argv[]){
    setup();
    if (args>=1&&argv[1]!=NULL)
    {
        char key[30];
        strcpy(key, argv[1]);
        if (comfirm_auth_key(key))
        {
            have_auth_key=true;
        }
        else{
            have_auth_key=false;
        }
    }
    else{
        search_local_auth_key();
    }

    if (!have_auth_key)
    {
        char key[30];
        if(buy_auth_key(key)){
            printf("Buy auth_key: %s\n",key);
            printf("auto-use key next time run this program.\n");
        }
        exit(0);
    }
    if (get_ticket()!=0)
    {
        printf("not ticketed!\n");
        exit(-1);
    }
    main_func();
    release_ticket();
    shutdown_fd();
    printf("program normal done.\n");
    return 0;
}
