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

#define DEBUG
#ifdef DEBUG
#define dbg_print(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define dbg_print(fmt, ...) do {} while (0)
#endif


#define TYPE 1

uint8_t test_packet[][32] = {
	{ 0xa0, 0x00, 0x18, 0x09, 0x00, 0x08, 0x00, 0x00, 0x40, 0x00, 0xa1, 0x00, 0x41, 0x21, 0xef },
	{ 0xa0, 0x00, 0x17, 0x0f, 0x00, 0x00, 0x40, 0x08, 0x00, 0x00, 0x80, 0x00, 0xef, 0x00, 0x2c, 0x08, 0x00, 0x09, 0x00, 0xaf, 0x88 },
	{ 0xa0, 0x00, 0x10, 0x07, 0x00, 0x08, 0x00, 0x00, 0xfe, 0x00, 0x8a, 0x75, 0x05 },
	{ 0xa0, 0x00, 0x55, 0x09, 0x00, 0x00, 0x40, 0x08, 0x00, 0x03, 0xc6, 0x00, 0x00, 0xae, 0x4c}, 
	{ 0xa0, 0x00, 0x58, 0x19, 0x00, 0x08, 0x00, 0x00, 0xfe, 0x03, 0xc6, 0xc3, 0x84, 0x12, 0x8e, 0x66, 0x66, 0x8e, 0x51, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe9, 0x89, 0x4d, 0x00, 0xaf, 0x4c},
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
#define OPCODE2 10

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

enum opcodes2_master {
	OPCODE2_PONG = 0x0C,
	OPCODE2_STATUS = 0x81,
	OPCODE2_ALIVE  = 0x8A,
	OPCODE2_MODE_MASTER = 0x86,
	OPCODE2_ACK  = 0xA1,
	OPCODE2_MASTER_MAX
};

enum opcodes2_remote {
	OPCODE2_POWER = 0x41,
	OPCODE2_MODE_REMOTE = 0x42,
	OPCODE2_TEMP_FAN = 0x4C,
	OPCODE2_SAVE = 0x54,
	OPCODE2_SENSOR_QUERY  = 0x80,
	OPCODE2_SENSOR_ROOM_TEMP = 0x81,
	OPCODE2_PING = 0x0C81,
	OPCODE2_TIMER = 0x0C82,
	OPCODE2_REMOTE_MAX
};

char codes[OPCODE_MAX][22] = {
	[OPCODE_PING] = "PING",
	[OPCODE_PARAMETER] = "PARAMETER",
	[OPCODE_ERROR_HISTORY] = "ERROR_HISTORY",
	[OPCODE_ACK] = "ACK",
	[OPCODE_SENSOR_QUERY] = "SENSOR_QUERY",
	[OPCODE_SENSOR_VALUE] = "SENSOR_VALUE",
	[OPCODE_STATUS] = "STATUS",
	[OPCODE_TEMPERATURE] = "TEMPERATURE",
	[OPCODE_EXTENDED_STATUS] = "EXTENDED_STATS",
};

char codes2_master[OPCODE2_MASTER_MAX][22] = {
	[OPCODE2_STATUS] = "STATUS",
	[OPCODE2_ALIVE] = "ALIVE",
	[OPCODE2_ACK] = "ACK",
	[OPCODE2_MODE_MASTER] = "MODE",
	[OPCODE2_PONG] = "PONG",
};

char codes2_remote[OPCODE2_REMOTE_MAX][22] = {
	[OPCODE2_POWER] = "POWER",
	[OPCODE2_MODE_REMOTE] = "MODE_REMOTE",
	[OPCODE2_TEMP_FAN] = "TEMP_FAN",
	[OPCODE2_SAVE] = "SAVE",
	[OPCODE2_PING] = "PING",
	[OPCODE2_TIMER] = "TIMER",
	[OPCODE2_PONG] = "PONG",
};

const uint8_t TEMPERATURE_DATA_MASK = 0b11111110;
const float TEMPERATURE_CONVERSION_RATIO = 2.0;
const float TEMPERATURE_CONVERSION_OFFSET = 35.0;

char * print_opcode(uint8_t opcode) {
	if((opcode >= OPCODE_PING) && (opcode < OPCODE_MAX)) {
		return &codes[opcode][0];
	} else {
		return NULL;
	}
}

char * print_opcode2(uint8_t opcode) {
	if((opcode >= OPCODE2_STATUS) && (opcode < OPCODE2_MASTER_MAX)) {
		return &codes2_master[opcode][0];
	} else {
		return NULL;
	}
}

char * print_opcode2_remote(uint8_t opcode) {
	if((opcode >= OPCODE2_POWER) && (opcode < OPCODE2_REMOTE_MAX)) {
		return &codes2_remote[opcode][0];
	} else {
		return NULL;
	}
}

void data_tcc2(uint8_t opcode, unsigned char *buff, int len) {

	uint16_t *ptr16 = (uint16_t *) buff;
	uint32_t *ptr32 = (uint32_t *) buff;

	switch(opcode) {
		case OPCODE_TEMPERATURE:
			printf("temperature: %f\n\n", ((float)buff[0])/10.0f);
		break;
		case OPCODE_SENSOR_VALUE:
			//ptr16 = (uint16_t *) &buff[5];
			//printf("sensor: %d, %02x\n\n", *ptr16, *ptr16);
			//printf("sensor lsb: %d\n", (buff[5] & 0xFF) | ((buff[6] << 8) & 0xFF00));
			printf("sensor: %d, %04x\n", (buff[6] & 0xFF) | ((buff[5] << 8) & 0xFF00), (buff[6] & 0xFF) | ((buff[5] << 8) & 0xFF00));
			//printf("value: %f\n", ((float)buff[0])/10.0f);
#if 0
			for(int i = 0; i < len; i++) {
				printf("u8: %d\n", buff[i]);
				if(i % 2 == 0) {
					printf("u16: %d\n", ptr16[i/2]);
				}
				if(i % 4 == 0) {
					printf("u32: %d\n", ptr32[i/4]);
				}
			}
#endif
		break;
		default:
		break;
	}
}

void decode_tcc2(unsigned char *buff, int len) {
	uint16_t source;
	uint16_t desination;

	//memcpy(&source, &buff[SOURCE+2], 2);
	memcpy(&desination, &buff[DESTINATION+1], 2);

	source = (buff[SOURCE+2] & 0xFF ) | ((buff[SOURCE] << 8) & 0xFF00);
	desination &= 0xFFFF;
	
	if(source == 0x0000) {
		printf("opcode:       %02x\n"
			" type:        %s\n"
			" source:      %04x, r/w: %02x\n"
			" destination: %04x, r/w: %02x\n"
			" opcode2:     %02x\n"
			" desc:        %s\n",
			buff[HEADER] , print_opcode(buff[HEADER]), source, buff[SOURCE+1], desination, buff[DESTINATION], buff[OPCODE2], print_opcode2(buff[OPCODE2]));
	}
	if(source == 0x0040) {
		printf("opcode:       %02x\n"
			" type:        %s\n"
			" source:      %04x, r/w: %02x\n"
			" destination: %04x, r/w: %02x\n"
			" opcode2:     %02x\n"
			" desc:        %s\n",
			buff[HEADER] , print_opcode(buff[HEADER]), source, buff[SOURCE+1], desination, buff[DESTINATION], buff[OPCODE2], print_opcode2_remote(buff[OPCODE2]));
	}
	printf(" ");
	for(int i = DATA; i < buff[SIZE] + HEADER_SIZE; i++) {
		printf("%02x ", buff[i]);
	}
	printf("\n");

	dbg_print("raw: ");
	for(int i = 0; i < buff[SIZE] + HEADER_SIZE; i++) {
		dbg_print("%02x ", buff[i]);
	}
	dbg_print("\n");

	data_tcc2(buff[HEADER], &buff[DATA], len);
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
	//printf("crc: %04x, u8h: %02x, u8l: %02x\n", crc, crc >> 8, crc & 0xff);
	if(((crc >> 8) == buff[total_len-2]) || ((crc & 0xff) == buff[total_len-1])) {
		//printf("crc correct, decoding packet\n");
		decode_tcc2(buff, len);
	} else {
		printf("crc incorect, skipping packet: crc: %02x != %02x, %02x\n", crc, buff[total_len-2], buff[total_len-1]);
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
