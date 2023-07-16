#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include "libsodium-1.0.18/src/libsodium/include/sodium.h"
#include "rand_things.h"

#define PWD "suchagoodpasswowrd"
#define KEY_LEN crypto_box_SEEDBYTES
#define OPSLIMIT_JLMMECHA 10U // 10 ops
#define MEMLIMIT_JLMMECHA 32000000000U //32 GB
#define OPSLIMIT_ENIGMECHA 10U // 10 ops
#define MEMLIMIT_ENIGMECHA 1000000000U //1 GB



unsigned char salt[64];
unsigned char out[320];
uint64_t saltbytes;
struct timeval tv;
char tm_str[sizeof tv.tv_sec];


void get_timestmp() {

    gettimeofday(&tv,NULL);
    sprintf(tm_str, "%lu", tv.tv_sec);


}

void to_file(int opt) {

    FILE *sf_ptr;

    if (opt == 1) {
        char filename[+sizeof(".")+sizeof(tm_str)];

        strcpy(filename,"salt");
        strcat(filename, tm_str);

        sf_ptr = fopen(filename, "wb");

        if(sf_ptr == NULL)
        {
            printf("Error!");
            exit(1);
        }
        fwrite(salt, sizeof(salt), 1, sf_ptr);

        fclose(sf_ptr);

        sf_ptr = fopen(filename, "rb");

        unsigned char unsinereadout[sizeof(salt)];
        fread(unsinereadout, sizeof(unsinereadout), 1, sf_ptr);

        printf("SALT:\n\t");
        printf("%s", unsinereadout);



        fclose(sf_ptr);

    }else if (opt == 2)
    {
        char filename[sizeof("key")+sizeof(tm_str)];

        strcpy(filename,"key");
        strcat(filename, tm_str);

        sf_ptr = fopen(filename, "wb");

        if(sf_ptr == NULL)
        {
            printf("Error!");
            exit(1);
        }
        fwrite(out, sizeof(out), 1, sf_ptr);

        fclose(sf_ptr);

        sf_ptr = fopen(filename, "rb");

        fflush(sf_ptr);

        unsigned char unsinereadout[sizeof(out)];

        fread(unsinereadout, sizeof(unsinereadout), 1, sf_ptr);

        printf("OUT:\n\t");
        printf("%s", unsinereadout);

        *unsinereadout == *out ? printf("\nyes\n") : printf("\nNo\n");

        fclose(sf_ptr);

    }



}


unsigned char* mk_hash(const char* to_be_hashed) {

    if (sodium_init() < 0) {
        printf("Sodium init Error!");
        exit(1);
    }

    const unsigned char* salt_inst = salt;
    unsigned long long passlen = 256;
    unsigned long long outlen = 256+sizeof(salt_inst);
    if (crypto_pwhash(out,
                  outlen,
                  to_be_hashed,
                      passlen,
                  salt_inst,
                  crypto_pwhash_OPSLIMIT_SENSITIVE,
                      crypto_pwhash_MEMLIMIT_SENSITIVE,
                  crypto_pwhash_ALG_DEFAULT) < 0) {
        printf("Hashing Error!");
        exit(1);
    }


    printf("%s", out);

    return out;

}

unsigned char* mk_salt(const char* inp) {

    saltbytes = rando_64();

    sprintf((char *) salt, "%lu", saltbytes);


    return salt;


}



uint32_t rando_32(void) {

    char buff[] = {};
//uint32_t usr_in[3] = {0};
    const uint32_t clck = clock() << 16;

    printf("> %s", buff);
    scanf("%[a-d]s", buff);
    printf("%s\n\n", buff);
    uint32_t rnd_byts = randombytes_random();
    printf("%u\n", rnd_byts);
    printf("%u\n", clck);

    rnd_byts = (rnd_byts ^ clck);

    printf("%u\n", rnd_byts);

    randombytes_close();
    return rnd_byts;
}

uint64_t rando_64(void) {

    char buff[] = {};
//uint32_t usr_in[3] = {0};
    const uint64_t clck = (clock() << 16) + (clock () << 2) ;

    printf(">\n");
    fflush(stdout);
    scanf("%[a-d]s", buff);
    printf("%s\n\n", buff);
    uint64_t rnd_byts = (randombytes_random() * 2) << 16;
    printf("%lu\n", rnd_byts);
    printf("%lu\n", clck);

    rnd_byts = (rnd_byts ^ clck);

    printf("%lu\n", rnd_byts);

    randombytes_close();
    return rnd_byts;
}

int main(void) {
    get_timestmp();

    //uint32_t rnd32_u = rando_32();
    //printf("%u", rnd32_u);
    //uint64_t rnd64_u = rando_64();
    //printf("%lu", rnd64_u);

    //printf("%s", mk_salt(NULL));
    mk_salt(NULL);
    mk_hash(PWD);
    to_file(2);



}