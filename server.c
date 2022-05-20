#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include<fcntl.h>
#include<sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <sys/socket.h>
#include <netinet/in.h>

typedef unsigned char byte;
const char hn[] = "SHA256";
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
void print_it(const char* label, const byte* buff, size_t len)
{
    if(!buff || !len)
        return;
    
    if(label)
        printf("%s: ", label);
    
    for(size_t i=0; i < len; ++i)
        printf("%02X", buff[i]);
    
    printf("\n");
}



int verify_it(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey)
{
    /* Returned to caller */
    int result = -1;
    
    if(!msg || !mlen || !sig || !slen || !pkey) {
        assert(0);
        return -1;
    }

    EVP_MD_CTX* ctx = NULL;
    
    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        const EVP_MD* md = EVP_get_digestbyname(hn);
        assert(md != NULL);
        if(md == NULL) {
            printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        byte buff[EVP_MAX_MD_SIZE];
        size_t size = sizeof(buff);
        
        rc = EVP_DigestSignFinal(ctx, buff, &size);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestVerifyFinal failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        assert(size > 0);
        if(!(size > 0)) {
            printf("EVP_DigestSignFinal failed (2)\n");
            break; /* failed */
        }
        
        const size_t m = (slen < size ? slen : size);

        result = !!CRYPTO_memcmp(sig, buff, m);
        
        OPENSSL_cleanse(buff, sizeof(buff));
        
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
    
    /* Convert to 0/1 result */
    return !!result;
}

int main (void)
{
	int status, myPipe[2];
	pipe(myPipe);  // create the pipe 
	int sockfd, newsockfd, portno = 9999;
	// create a TCP/IP socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	perror("ERROR opening socket");

	struct sockaddr_in serv_addr;
	// clear address structure
	bzero((char *) &serv_addr, sizeof(serv_addr));

	/* setup the host_addr structure for use in bind call */
	// server byte order
	serv_addr.sin_family = AF_INET;

	// automatically be filled with current host's IP address
	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	// port number to bind to
	serv_addr.sin_port = htons(portno);
	pid_t pid = fork();
	
	
    if(pid == 0) {
	// listen to the port 
	printf("Child => PPID: %d PID: %d\n", getppid(), getpid());
	
	// This bind() call will bind  the socket to the current IP address on port
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
	 perror("ERROR on binding");
	}

	// This listen() call tells the socket to listen to the incoming connections.
	// The listen() function places all incoming connection into a backlog queue
	// until accept() call accepts the connection.
	// Here, we set the maximum size for the backlog queue to 5.
	listen(sockfd,5);

	newsockfd = accept(sockfd, 0, 0);
	int s = newsockfd;
	char buffer[200];
	read(s, buffer,200);
	close(s);
	
	
	close(myPipe[0]);  // close unused read end
	write(myPipe[1], buffer, 200);
	printf("Child process sent\n");
	close(myPipe[1]);  
	exit(EXIT_SUCCESS);
  }
  else if(pid > 0) {
	printf("Parent => PID: %d\n", getpid());
	// decrypt the message
	printf("Waiting for child process to finish.\n");
	wait(NULL);
	OpenSSL_add_all_algorithms();

	/* Sign and Verify HMAC keys */
	EVP_PKEY *vkey = NULL;
    

	/* A 256 bit key */
	unsigned char *key = (unsigned char *)"19A2B88289B5086145911B22510A71B420321317DF66AEE0B5430C29C529E35D";
	int size= 32,rc;
	vkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, size);
	assert(vkey != NULL);
	if(vkey == NULL) {
	    printf("EVP_PKEY_new_mac_key failed, error 0x%lx\n", ERR_get_error());
	}

	/* Buffer for the decrypted text */
	unsigned char decryptedtext[128];
	int decryptedtext_len, ciphertext_len;
	unsigned char* ciphertext;
	
	
	char buffer[200];
	
        close(myPipe[1]);  // close unused write end
        int pid_child = wait(&status);
        int length = read(myPipe[0],buffer, 200);
        printf("Parent process received \n");
        close(myPipe[0]);
	ciphertext_len=48;
	
	
	
	unsigned char *iv , *sig;
	char delim[] = "||";
	char *ptr = strtok(buffer, delim);
	int i=0;
	while(ptr != NULL)
	{
		if(i==0){ 
		//sig=ptr;
		sig=&(*++ptr);
		sig=&(*++ptr);
		}
		if(i==1) ciphertext=ptr;
		if(i==2) iv=ptr;
		//printf("Broken string: %s\n", ptr);
		ptr = strtok(NULL, delim);
		i++;
	}
	
    	size_t slen = strlen(sig);
    	print_it("Signature", sig, slen+4);
	//printf("length %ld \n",strlen(ciphertext));
	
	
	#if 0
	/* Tamper with signature */
	printf("Tampering with signature\n");
	sig[0] ^= 0x01;
	print_it("Changed signature", sig, slen);
	#endif

	#if 0
	/* Tamper with signature */
	printf("Tampering with signature\n");
	sig[slen - 1] ^= 0x01;
	print_it("Changed signature", sig, slen);
	#endif
    	
	rc = verify_it(ciphertext,  ciphertext_len, sig, slen, vkey);
	
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
	
	if(rc == 0) {
	printf("Verified signature\n");
	/* Decrypt the ciphertext */
	decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
		                decryptedtext);

	/* Add a NULL terminator. We are expecting printable text */
	decryptedtext[decryptedtext_len] = '\0';

	/* Show the decrypted text */
	printf("Decrypted text is:\n");
	printf("%s\n", decryptedtext);
	
	} else {
	printf("Failed to verify signature, return code %d\n", rc);
	}



	return EXIT_SUCCESS;
	printf("Child process finished.\n");
  }
  else {
    printf("Unable to create child process.\n");
  }
 
}
