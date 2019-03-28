/*
 * socket-client.c
 * Simple TCP/IP communication using sockets
 *
 */
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "socket-common.h"
#include <crypto/cryptodev.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/stat.h>

#define DATA_SIZE 256
#define BLOCK_SIZE 16
#define KEY_SIZE 16


char buf[256], temp[256], c;
static  int encrypt  (int cfd) {  
	struct session_op sess;  
	struct crypt_op cryp;  
	struct {
 		unsigned  char   in[DATA_SIZE], 
		encrypted[DATA_SIZE], 
		decrypted [DATA_SIZE],
		iv [BLOCK_SIZE], 
		key [KEY_SIZE];
	} data;

	memset (& sess,  0,  sizeof(sess)); 
	memset (& cryp,  0,  sizeof(cryp)); 
	memcpy (& data.in, buf,  sizeof(buf));
	memcpy (& data.iv,  "1234567890123456", BLOCK_SIZE ); 
	memcpy (& data.key,  "abcdefghijklmnop", KEY_SIZE );

	sess.cipher  = CRYPTO_AES_CBC; 
	sess.keylen  = KEY_SIZE; 
	sess.key  = data.key;
	
	if  ( ioctl ( cfd, CIOCGSESSION,  & sess )) { 
		perror ( "ioctl(CIOCGSESSION)" );  
		exit(1);
	}

	cryp.ses  = sess.ses; 
	cryp.len  =  sizeof (data.in); 
	cryp.src  = data.in; 
	cryp.dst  = data.encrypted; 
	cryp.iv  = data.iv;
	cryp.op  = COP_ENCRYPT;

	if  (ioctl(cfd, CIOCCRYPT, &cryp)) { 
		perror ( "ioctl(CIOCCRYPT)" );  
		exit(1);
	} 
	memcpy (&buf, data.encrypted,  sizeof(buf));
 	//printf("\nEncrypted data\n");

	/* Finish crypto session */  
	if  ( ioctl (cfd, CIOCFSESSION,  &sess.ses)) {
		perror ( "ioctl(CIOCFSESSION)" );
 		exit(1); 
	}
	
	return  0;
}


static  int decrypt  (int cfd ) {  

	struct session_op sess;  
	struct crypt_op cryp;  struct {
 			unsigned  char   in[DATA_SIZE], 
			encrypted[DATA_SIZE], 
			decrypted[DATA_SIZE],
			iv[BLOCK_SIZE], 
			key[KEY_SIZE];
 	} data;

	memset (&sess,  0, sizeof(sess)); 
	memset (&cryp,  0, sizeof(cryp)); 
	memcpy (&data.in, buf ,  sizeof(buf));
	memcpy (&data.iv, "1234567890123456", BLOCK_SIZE); 
	memcpy (&data.key, "abcdefghijklmnop", KEY_SIZE);
	
	sess.cipher  = CRYPTO_AES_CBC; 
	sess.keylen  = KEY_SIZE; 
	sess.key  = data.key;
 
	if  ( ioctl (cfd, CIOCGSESSION,  &sess )) { 
		perror ( "ioctl(CIOCGSESSION)" );  
		exit(1);
	}

	cryp.ses  = sess.ses; 
	cryp.len  =  sizeof(data.in); 
	cryp.src  = data.in; 
	cryp.dst  = data.decrypted; 
	cryp.iv  = data.iv;
	cryp.op  = COP_DECRYPT;


	if  ( ioctl (cfd, CIOCCRYPT,  &cryp)) { 
		perror ( "ioctl(CIOCCRYPT)" );  
		exit(1);
	} 

	memcpy (&buf, data.decrypted,  sizeof(buf));
 
	//printf("\nDecrypted data\n");
 	
	/* Finish crypto session */  
	if  ( ioctl (cfd, CIOCFSESSION,  &sess.ses)) {
		perror ( "ioctl(CIOCFSESSION)" );
 		exit(1); 
	}
	return  0;
}








/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

int main(int argc, char *argv[])
{
	int sd, port, ret, i=0;
	ssize_t n;
	
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;

	//set of socket descriptors
	fd_set fds;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}

	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");

	int cfd = open("/dev/crypto", O_RDWR);
	if (cfd < 0) {
		perror("open(/dev/crypto)");
		exit(1);
	}

	//the communication port is asynchronous, so we use termios for it
	static struct termios oterm, nterm;

	/* 
		the parameters of the terms structure:
		tcflag_t c_iflag; input modes
		tcflag_t c_oflag; output modes
		tcflag_t c_cflag; control modes
		tcflag_t c_lflag; local modes
		cc_t cc_c[NCCS]; special characters
	*/

	//get the parameters of the current terminal and copy them to old
	tcgetattr(STDIN_FILENO, &oterm);
	//copy them
	nterm = oterm;

	//make sure to check one line at a time => return if you see \n etc
	nterm.c_lflag &= ~(ICANON | ECHO);

	//make these the settings of stdin now (TCSANOW)
	tcsetattr(STDIN_FILENO, TCSANOW, &nterm);

	memset(&temp[0], 0, sizeof(temp));

	////////////////////////////////////////////////////////
	/* Be careful with buffer overruns, ensure NUL-termination */
	strncpy(buf, HELLO_THERE, sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';

	/* Say something... */
	if (insist_write(sd, buf, strlen(buf)) != strlen(buf)) {
		perror("write");
		exit(1);
	}
	fprintf(stdout, "I said:\n%s\nRemote says:\n", buf);
	fflush(stdout);
	/////////////////////////////////////////////////////////


	/* Read answer and write it to standard output */
	for (;;) {

		//clear the socket set
		FD_ZERO(&fds);

		//now add the socket and stdin to the set
		FD_SET(sd, &fds);
		FD_SET(0, &fds);
		
		/* select allows the program to monitor more than 1 fds, 
		waiting until 1 or 1+ of them become ready for some I/O operation. */
		ret = select(sd+1, &fds, NULL, NULL, NULL);
		if ((ret<0) && (errno!=EINTR)) {
			printf("error in select");
			exit(1);
		}

		if (FD_ISSET(sd, &fds)) {
			
			n = read(sd, buf, sizeof(buf));

			if (n < 0) {
				perror("read");
				exit(1);
			}

			if (n <= 0)
				break;
			if(decrypt(cfd)<0) return 1;
			if (insist_write(1, buf, n) != n) {
				perror("write");
				exit(1);
			}
			insist_write(1,temp,sizeof(temp));
		
		}

		//if the stdin is part of the fds set then
		else if (FD_ISSET(0, &fds)) {
			//read from input, write to socket
			c = getchar();
			buf[sizeof(buf)-1]='\0';
			if (c == 127) { //delete
				--i;
				if (i>=0) temp[i] = ' ';
				const char delbuf[] = "\b \b";
				write(1, delbuf, strlen(delbuf));
			}
			else {
				write(1, &c, sizeof(c));
				temp[i++] = c;
			}

			if (c == '\n') { //if the line is over
				n = i;
				i = 0;
				for (i=0; i<n; i++) buf[i] = temp[i]; //pass everything to the buffer
				buf[i++] = '\0';
				n = i;
				if(encrypt(cfd)<0) return 1;

				if (insist_write(sd, buf, 256) != 256) { //and copy the buffer to the socket
					perror("write");
					exit(1);
				}	
				i = 0;
				n = 0;
				//clear the buffer & the temp
				memset(&buf[0], 0, sizeof(buf));
				memset(&temp[0], 0, sizeof(temp));
			}
		}
	}
	
	tcsetattr(STDIN_FILENO, TCSANOW, &oterm);

	/*
	* Let the remote know we're not going to write anything else.
	* Try removing the shutdown() call and see what happens.
	*/
	if (shutdown(sd, SHUT_WR) < 0) {
		perror("shutdown");
		exit(1);
	}
	fprintf(stderr, "\nDone.\n");
	return 0;
}
