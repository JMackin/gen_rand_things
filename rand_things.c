#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <dirent.h>
#include "libsodium-1.0.18/src/libsodium/include/sodium.h"
#include "rand_things.h"

#define PWD "suchagoodpasswowrd"
#define KEY_LEN crypto_box_SEEDBYTES
#define OPSLIMIT_JLMMECHA 10U // 10 ops
#define MEMLIMIT_JLMMECHA 32000000000U //32 GB
#define OPSLIMIT_ENIGMECHA 10U // 10 ops
#define MEMLIMIT_ENIGMECHA 1000000000U //1 GB
#define OUTPUT_DIR_KEY_FILE "./.key"
#define OUTPUT_DIR_SALT_FILE "./.salt"


unsigned char salt[64];
unsigned char out[320];
uint64_t saltbytes;
struct timeval tv;
char tm_str[sizeof tv.tv_sec];

void get_timestmp() {

    gettimeofday(&tv,NULL);
    sprintf(tm_str, "%lu", tv.tv_sec);

}

//opt 1: Print salt to file
//opt 2: print hashed string to file
void to_file(int opt) {

    FILE *sf_ptr;

    if (opt == 1) {
        char filename[sizeof(".")+sizeof(tm_str)];

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
        //printf("%s", unsinereadout);

        *unsinereadout == *out ? printf("\nyes\n") : printf("\nNo\n");

        fclose(sf_ptr);

    }

}

unsigned char* mk_hash(const char* to_be_hashed) {

    if (sodium_init() < 0) {
        fprintf(stderr, "Sodium init Error!");
        exit(1);
    }
    mk_salt(NULL);
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
        fprintf(stderr,"Hashing Error!");
        exit(1);
    }

    return out;

}

unsigned char* mk_salt(const char* inp) {


    saltbytes = rando_64();

    sprintf((char *) salt, "%lu", saltbytes);

    return salt;

}

uint64_t rando_32(void) {

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
    return (int64_t) rnd_byts;
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

int chk_hash(int64_t hash, char* passwd)
{

}


int main(int argc, char** argv) {
    get_timestmp();
    int arg_begin = 0;
    int valid = -1;
    char* result_out;
    char* func_arg;
    char* flags[OPT_ARR_LEN] = {"-h" ,"-r32","-r64","-f","-s","-chk", NULL};
    enum Opt_Cmds optCmds[OPT_ARR_LEN] = {HASH,RNDA,RNDB,TOFI,SALT,CHSH, END};
    void *opts [OPT_ARR_LEN] = { &mk_hash, &rando_32, &rando_64, &to_file, &salt, &chk_hash, NULL};


    if (argc > 1) {
        for (int i = 0; i < argc; i++) {
            if (memchr(argv[i], '\\', sizeof(argv[i]))) {
                arg_begin = i;
            }
        }

        func_arg = (char*) malloc(sizeof(argv[arg_begin]));
        strcpy(func_arg, argv[arg_begin]);

    }

    if (strcmp(func_arg, flags[RNDA]) == 0) {
        uint16_t *(*rando)() = opts[RNDA];
    }
    else if (strcmp(func_arg, flags[RNDB]) == 0) {
        uint16_t *(*rando)() = opts[RNDB];
    }
    else if (strcmp(func_arg, flags[HASH]) == 0) {
         unsigned char *(*rando)() = opts[HASH];
    }
    else if (strcmp(func_arg, flags[SALT]) == 0) {
        unsigned char *(*rando)() = opts[SALT];
    }
    else if (strcmp(func_arg, flags[CHSH]) == 0) {
        int *(*rando)() = opts[CHSH];
    }


    free(func_arg);
    //
    // free(argv);
}
