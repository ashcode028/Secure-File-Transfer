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
int sign_it(const byte* msg, size_t mlen, byte** sig, size_t* slen, EVP_PKEY* pkey)
{
    /* Returned to caller */
    int result = -1;
    
    if(!msg || !mlen || !sig || !pkey) {
        assert(0);
        return -1;
    }
    
    if(*sig)
        OPENSSL_free(*sig);
    
    *sig = NULL;
    *slen = 0;
    
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
        
        size_t req = 0;
        rc = EVP_DigestSignFinal(ctx, NULL, &req);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        assert(req > 0);
        if(!(req > 0)) {
            printf("EVP_DigestSignFinal failed (2), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        *sig = OPENSSL_malloc(req);
        assert(*sig != NULL);
        if(*sig == NULL) {
            printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        *slen = req;
        rc = EVP_DigestSignFinal(ctx, *sig, slen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
            break; /* failed */
        }
        
        assert(req == *slen);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", req, *slen);
            break; /* failed */
        }
        
        result = 0;
        
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
    
    /* Convert to 0/1 result */
    return result;
}

char* getFileContents(char* filename){

    	FILE* ptr = fopen(filename, "a+");
 	fseek(ptr, 0, SEEK_END);
	long fsize = ftell(ptr);
	fseek(ptr, 0, SEEK_SET);  /* same as rewind(f); */ 
	char *content = malloc(fsize + 1);
	fread(content, fsize, 1, ptr);
	fclose(ptr);
	return content;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
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


int main (void)
{
    
    int status, myPipe[2];
    pipe(myPipe);  // create the pipe   
	int sockfd, portno = 9999;
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	perror("ERROR opening socket");
	bzero(&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	serv_addr.sin_port = htons(portno);

    
    pid_t pid = fork();
    
    
 if(pid == 0) {
	// encrypt the text in the file
	printf("Child => PPID: %d PID: %d\n", getppid(), getpid());
	
	OpenSSL_add_all_algorithms();
	EVP_PKEY *skey = NULL;
	unsigned char *key = (unsigned char *)"19A2B88289B5086145911B22510A71B420321317DF66AEE0B5430C29C529E35D";
	int size= 32,rc;

	skey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, size);
	assert(skey != NULL);
	if(skey == NULL) {
	    printf("EVP_PKEY_new_mac_key failed, error 0x%lx\n", ERR_get_error());
	}
	
	/* A 128 bit IV */
	char data[16];
	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	fread(&data, 1, 16, fp);
	data[16]='\0';
	print_it("IV", data, 16);
	fclose(fp);
	
	
	unsigned char *iv = (unsigned char *)data;
	//unsigned char *iv = (unsigned char *)"0123456789012345";	
	unsigned char ciphertext[128];

	/* Message to be encrypted */
	unsigned char *plaintext =
	(unsigned char *)getFileContents("send.txt");
	int ciphertext_len;

	/* Encrypt the plaintext */
	ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
		              ciphertext);
	
	/* Do something useful with the ciphertext here */
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
	//printf("\nlength %d \n",ciphertext_len);
		
	byte* sig = NULL;
	size_t slen = 0;
	
	/* Using the skey or signing key */
	rc = sign_it(ciphertext, ciphertext_len, &sig, &slen, skey);
	assert(rc == 0);
	if(rc == 0) {
	printf("Created signature\n");
	} else {
	printf("Failed to create signature, return code %d\n", rc);
	exit(1); /* Should cleanup here */
	}
	
	print_it("Signature", sig, slen);
	//printf("length %ld \n",strlen(sig));
	//printf("length %ld \n",slen);
	
	char buffer[200];
	        
        strcat(buffer,sig);
        strcat(buffer,"||");
        strcat(buffer,ciphertext);
        strcat(buffer,"||");
        strcat(buffer,iv);
        strcat(buffer,"||");
	

	
	close(myPipe[0]);  // close unused read end
	write(myPipe[1], (const char *)buffer, 200);
	printf("Child process sent \n");
	close(myPipe[1]); 

	if(sig)
	OPENSSL_free(sig);

	if(skey)
	EVP_PKEY_free(skey);
	   
	exit(EXIT_SUCCESS);
  }
  else if(pid > 0) {
// send the encrypted text
	printf("Parent => PID: %d\n", getpid());
	printf("Waiting for child process to finish.\n");
	wait(NULL);
	printf("Child process finished.\n");

	char data[200];
        close(myPipe[1]);  // close unused write end
        int pid_child = wait(&status);
        read(myPipe[0], data, sizeof(data));
        printf("Parent process received \n");
        close(myPipe[0]);

        
	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == 0) {
	printf("Client sending %s to server\n",data);
		write(sockfd, data, strlen(data));
	}
	
	else perror("ERROR connecting");

    }
    
  else {
   	printf("Unable to create child process.\n");
  }
 
	return EXIT_SUCCESS;
}
