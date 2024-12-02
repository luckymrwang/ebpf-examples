#include <stdio.h>
#include <arpa/inet.h>

int main() {
    unsigned short port = 10000;  // 原始端口号
    unsigned short host_port = ntohs(port);  // 转换为主机字节序
    printf("端口号 10000 的主机字节序表示为: %u\n", host_port);

    port = 10001;  // 原始端口号
    host_port = ntohs(port);  // 转换为主机字节序
    printf("端口号 10001 的主机字节序表示为: %u\n", host_port);

    port = 10002;  // 原始端口号
    host_port = ntohs(port);  // 转换为主机字节序
    printf("端口号 10002 的主机字节序表示为: %u\n", host_port);

    return 0;
}