#include <arpa/inet.h> // inet_addr()
#include <netdb.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> // bzero()
#include <sys/socket.h>
#include <unistd.h> // read(), write(), close()
#define MAX (132*2)
#define PORT 7000
#define HEADER_SIZE 4
#define CRC_SIZE 2
#define SA struct sockaddr
#include <endian.h>
#include <errno.h>

//#define DEBUG_RAW
#ifdef DEBUG_RAW
#define raw_print(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define raw_print(fmt, ...) do {} while (0)
#endif

#define TYPE 1

uint8_t test_packet[][32] = {
	{ 0xa0, 0x00, 0x18, 0x09, 0x00, 0x08, 0x00, 0x00, 0x40, 0x00, 0xa1, 0x00, 0x41, 0x21, 0xef },
	{ 0xa0, 0x00, 0x17, 0x0f, 0x00, 0x00, 0x40, 0x08, 0x00, 0x00, 0x80, 0x00, 0xef, 0x00, 0x2c, 0x08, 0x00, 0x09, 0x00, 0xaf, 0x88 },
	{ 0xa0, 0x00, 0x10, 0x07, 0x00, 0x08, 0x00, 0x00, 0xfe, 0x00, 0x8a, 0x75, 0x05 },
};

union data_packet {
	uint8_t raw[128];
	struct {
		uint8_t source;
		uint8_t dest;
		uint8_t opcode1;
		uint8_t lenght;
		uint8_t data[124];
	} generic;
} __attribute__((packed));

uint16_t crc16_mcrf4xx(uint16_t crc, uint8_t *data, size_t len)
{
    uint8_t t;
    uint8_t L;
    if (!data || len < 0)
        return crc;

    while (len--) {
        crc ^= *data++;
        L = crc ^ (crc << 4);
        t = (L << 3) | (L >> 5);
        L ^= (t & 0x07);
        t = (t & 0xF8) ^ (((t << 1) | (t >> 7)) & 0x0F) ^ (uint8_t)(crc >> 8);
        crc = (L << 8) | t;
    }
    return crc;
}

int read_packet(int sockfd, unsigned char *buff, int len) {
	int ret, bytes_read = 0;

	bzero(buff, sizeof(buff));
	do {
		ret = read(sockfd, &buff[bytes_read], len - bytes_read);
		if(ret > 0)
			bytes_read += ret;
		else
			return ret;
	} while (bytes_read < len);
	raw_print("read: %d\n", bytes_read);
	return bytes_read;
}

#define PACKET_SIZE 126 /* bytes */
#define ALIGN 12

#define SIZE 3
#define HEADER 2
#define SOURCE 4
#define DESTINATION 7
#define DATA 10

enum opcodes {
	OPCODE_PING = 0x10,
	OPCODE_PARAMETER = 0x11,
	OPCODE_ERROR_HISTORY = 0x15,
	OPCODE_SENSOR_QUERY = 0x17,
	OPCODE_ACK = 0x18,
	OPCODE_SENSOR_VALUE = 0x1A,
	OPCODE_STATUS = 0x1C,
	OPCODE_TEMPERATURE = 0x55,
	OPCODE_EXTENDED_STATUS = 0x58,
	OPCODE_MAX
};

char codes [OPCODE_MAX][22] = {
	[OPCODE_PING] = "PING",
	[OPCODE_PARAMETER] = "PARAMETER",
	[OPCODE_ERROR_HISTORY] = "ERROR_HISTORY",
	[OPCODE_ACK] = "ACK",
	[OPCODE_SENSOR_QUERY] = "QUERY",
	[OPCODE_SENSOR_VALUE] = "VALUE",
	[OPCODE_STATUS] = "STATUS",
	[OPCODE_TEMPERATURE] = "TEMPERATURE",
	[OPCODE_EXTENDED_STATUS] = "EXTENDED_STATS",
};

char * print_header(uint8_t code) {
	if((code >= OPCODE_PING) && (code < OPCODE_MAX)) {
		return &codes[code][0];
	} else {
		return NULL;
	}
}

void decode_tcc2(unsigned char *buff) {
	uint32_t source;
	uint32_t desination;

	memcpy(&source, &buff[SOURCE], 3);
	memcpy(&desination, &buff[DESTINATION], 3);
	source &= 0xFFFFFF;
	desination &= 0xFFFFFF;
	
	printf("opcode: %02x\n type: %s\n source: %06x\n destination: %06x\n", buff[HEADER], print_header(buff[HEADER]), source, desination);

	//for(int i = 0; i < buff[SIZE] + HEADER_SIZE; i++) {
	//	printf("%02x ", buff[i]);
	//}
	//printf("\n");

	for(int i = DATA; i < buff[SIZE] + HEADER_SIZE; i++) {
		printf("%02x ", buff[i]);
	}
	printf("\n");
}

void read_tcc2(unsigned char *buff) {
	uint8_t len = buff[3];
	uint8_t total_len = len + HEADER_SIZE + CRC_SIZE; /* without crc */
	uint8_t buffer[15];
	uint16_t crc; 

	raw_print("len: %d, packet: ", len);
	for(int i = 0; i < total_len; i++) {
		raw_print("%02x ", buff[i]);
	}
	raw_print("\n");

	crc = crc16_mcrf4xx(0xffff, buff, total_len - CRC_SIZE);
	printf("crc: %04x, u8h: %02x, u8l: %02x\n", crc, crc >> 8, crc & 0xff);
	if(((crc >> 8) == buff[total_len-2]) || ((crc & 0xff) == buff[total_len-1])) {
		printf("crc correct, decoding packet\n");
		decode_tcc2(buff);
	} else {
		printf("crc incorect, skipping packet\n, %02x, %02x\n", buff[total_len-2], buff[total_len-1]);
	}
}

void func(int sockfd, int type, int shift, int align, int var, bool collum)
{
	unsigned char buff[MAX];
	int n, ret, index, size, i;
	int sync_bytes, bytes_read;

	for (;;) {
		sync_bytes = 0;
		ret = read_packet(sockfd, buff, MAX);

		/* find sync */
		for(n = 0; n < ret; n++) {
			raw_print("%02x ", buff[n]);
			if((buff[n] == 0xA0) && (buff[n+1] == 0x00)) {
				raw_print("\nsync bytes found at: %d\n", n);
				sync_bytes = 2;
				index = n;
			}

			if((sync_bytes == 2)) {
				/* read remainder to be in sync */
				size = buff[index+3];
				raw_print(", packet size: %d, remainder: %d\n", size, ret - index);
				//raw_print("packet size: %d, crc16c: %04x: ", size, crc16_mcrf4xx(0xffff, &buff[index], size+HEADER_SIZE));
				read_tcc2(&buff[index]);
				sync_bytes = 0;
			}
		}
		raw_print("\n");
	}
}

int main(int argc, char *argv[])
{
	int sockfd, connfd, ret;
	struct sockaddr_in servaddr, cli;
	int option;
	int port = PORT;
	int type = 255;
	char *ip_address = NULL;
	int shift = 0;
	int align = ALIGN;
	int var = 255;
	bool collum = false;
	int test = 0;

	opterr = 0;
	while ( (option=getopt(argc, argv, "i:p:t:hs:a:v:cT:")) != EOF ) {
		switch ( option ) {
			case 'p': port = atoi(optarg);
				  break;
			case 'i': ip_address = optarg;
				  break;
			case 't': type = atoi(optarg);
				  break;
			case 's': shift = atoi(optarg);
				  break;
			case 'a': align = atoi(optarg);
				  break;
			case 'v': var = atoi(optarg);
				  break;
			case 'c': collum = true;
				  break;
			case 'T': test = atoi(optarg);
				  break;
			case 'h': fprintf(stderr,"Unknown option %c\n", optopt);
				  exit(1);
				  break;
		}
	}

	if(test) {
		printf("use test packet: %d\n", test);
		read_tcc2(test_packet[test-1]);
		exit(0);
	}

	if (ip_address) 
		printf("ip address: %s, ", ip_address);
	else {
		fprintf(stderr, "error: no ip address defined\n");
		return -EINVAL;
	}
	if (port)    
		printf("port: %d\n", port);
	if(type != 255)
		printf("type: %d\n", type);

	if(shift)
		printf("shift: %d\n", shift);

	// socket create and verification
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		printf("socket creation failed...\n");
		exit(0);
	}
	else
		printf("Socket successfully created..\n");
	bzero(&servaddr, sizeof(servaddr));

	// assign IP, PORT
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(ip_address);
	servaddr.sin_port = htons(PORT);

	// connect the client socket to server socket
	ret = connect(sockfd, (SA*)&servaddr, sizeof(servaddr));
	if (ret != 0) {
		printf("connection with the server failed...\n");
		exit(0);
	}
	else
		printf("connected to the server..\n");

	// function for chat
	func(sockfd, type, shift, align, var, collum);

	// close the socket
	close(sockfd);
}
