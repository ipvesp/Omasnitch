#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    const int ipv6 = strstr(argv[1], "6") != NULL;
    const int tcp = strstr(argv[1], "tcp") != NULL;
    const int delayed = strcmp(argv[1], "tcp4_delayed") == 0
        || strcmp(argv[1], "tcp6_delayed") == 0;
    const int connected = delayed || strcmp(argv[1], "udp4_connected") == 0
        || strcmp(argv[1], "udp6_connected") == 0
        || strcmp(argv[1], "tcp4_connected") == 0
        || strcmp(argv[1], "tcp6_connected") == 0;
    const int family = ipv6 ? AF_INET6 : AF_INET;
    const int fd = socket(family, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 2; }

    struct sockaddr_storage target = {0};
    socklen_t target_len;
    if (ipv6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&target;
        addr->sin6_family = AF_INET6;
        addr->sin6_port = htons((unsigned short)atoi(argv[2]));
        inet_pton(AF_INET6, "::1", &addr->sin6_addr);
        target_len = sizeof(*addr);
    } else {
        struct sockaddr_in *addr = (struct sockaddr_in *)&target;
        addr->sin_family = AF_INET;
        addr->sin_port = htons((unsigned short)atoi(argv[2]));
        inet_pton(AF_INET, "127.0.0.1", &addr->sin_addr);
        target_len = sizeof(*addr);
    }
    if (connected && !delayed && connect(fd, (struct sockaddr *)&target, target_len) != 0) {
        perror("connect"); return 2;
    }
    puts("READY");
    fflush(stdout);
    if (getchar() == EOF) return 2;
    if (delayed && connect(fd, (struct sockaddr *)&target, target_len) != 0) {
        printf("RESULT -1 %d\n", errno);
        fflush(stdout);
        return 0;
    }
    errno = 0;
    const char payload[] = "omasnitch-regression";
    ssize_t sent;
    if (strstr(argv[1], "sendmmsg") != NULL || strstr(argv[1], "sendmsg") != NULL) {
        struct iovec iov = { .iov_base = (void *)payload, .iov_len = sizeof(payload) };
        struct msghdr msg = {
            .msg_name = &target,
            .msg_namelen = target_len,
            .msg_iov = &iov,
            .msg_iovlen = 1,
        };
        if (strstr(argv[1], "sendmmsg") != NULL) {
            struct mmsghdr batch = { .msg_hdr = msg };
            sent = sendmmsg(fd, &batch, 1, 0);
        } else {
            sent = sendmsg(fd, &msg, 0);
        }
    } else {
        sent = connected
            ? send(fd, payload, sizeof(payload), 0)
            : sendto(fd, payload, sizeof(payload), 0, (struct sockaddr *)&target, target_len);
    }
    printf("RESULT %zd %d\n", sent, errno);
    fflush(stdout);
    close(fd);
    return 0;
}
