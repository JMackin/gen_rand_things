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
#define SALT_TABLE_FILE "./.salt_hash_table"




uint64_t saltbytes;
struct timeval tv;
char* tm_str[sizeof tv.tv_sec];


void get_timestmp() {

    gettimeofday(&tv,NULL);
    sprintf((char *) tm_str, "%lu", tv.tv_sec);

}

// opt 1 = salt (bytes), opt 2 = hashkey (bytes), opt 4 = hashkey (ascii)
int to_file(unsigned char *salt, unsigned char* hashed, int opt) {

    FILE *sf_ptr;
    int opt_ch = opt<<1;
    //char* filename = (char *) malloc(CHAR_MAX-16);
    //char* filename[(sizeof("salt")+sizeof(tm_str))];

decr:
    opt_ch = opt_ch>>1;

    switch (opt_ch) {
        case 8:
            opt_ch = opt_ch>>1;
            goto hshstr_out;

        case 4:
            goto hshkey_out;

        case 2:
            goto salt_out;

        case 1:
            return 0;

        default:
            return 1;
    }


    salt_out:

    //char* filen1[(sizeof("salt")+sizeof(tm_str))];
    //strcpy(*filename,"salt");

        sf_ptr = fopen("salt_out", "wb");

        if(sf_ptr == NULL)
        {
            printf("Error!");
            exit(1);
        }

        for (int i = 0; i < 64; i++){
            fputc(*(salt+i), sf_ptr);
        }

        fclose(sf_ptr);

        goto decr;


    hshkey_out:

   // char* filen2[(sizeof("key")+sizeof(tm_str))];
    //strcpy((char *) filename, "key");

        sf_ptr = fopen("key_out", "wb");

        if(sf_ptr == NULL)
        {
            fprintf(stderr, "File-open Error");
        }

        for (int i = 0; i < 320; i++){
            fputc(*(hashed+i), sf_ptr);
        }

        fclose(sf_ptr);

       // sf_ptr = fopen(*filename, "rb");
        //fflush(sf_ptr);
        goto decr;


    hshstr_out:

        printf("not implemented yet.");
        goto decr;


}

void mk_hash_key(const char* to_be_hashed, unsigned char salt_inst[64u], unsigned char hashed_out[320u],  int give_salt, int tofile) {


    if (give_salt == 0) {
        mk_salt(salt_inst, NULL, 0);
    }

//    unsigned long long passlen = strlen(to_be_hashed);
//    unsigned long long outlen = crypto_box_SEEDBYTES;

    // Salt+Password
//
//    unsigned char salt[crypto_pwhash_SALTBYTES];
    //randombytes_buf(salt, sizeof salt);



    if (crypto_pwhash(hashed_out,
                      sizeof *hashed_out*320 ,
                      to_be_hashed,
                      strlen(to_be_hashed),
                      salt_inst,
                      crypto_pwhash_OPSLIMIT_SENSITIVE,
                      crypto_pwhash_MEMLIMIT_SENSITIVE,
                      crypto_pwhash_ALG_DEFAULT) < 0) {
        fprintf(stderr,"Hashing Error!");
        exit(1);

    }
    if (tofile == 1) {
        to_file(salt_inst, hashed_out, 4);
    } else
    {

    }

}

void mk_salt(unsigned char salt[64], const unsigned char* inp, int to_bytes) {

    if (inp != NULL && to_bytes == 1) {

        saltbytes = (uint64_t) *inp;

    } else if(inp != NULL && (to_bytes == 0)){

        for (int i = 0; i < 64; i++) {

            (salt[i]) = *(inp+i);
        }

    } else if (!(inp)) {

        saltbytes = rando_64();

    } else {

        fprintf(stderr, "Error handling salt");

    }

    for (int i = 1; i < 64; i++) {

       (*(salt+i)) = (unsigned char) (saltbytes - (saltbytes % (i)));
    }

    //randombytes_buf(&salt[64], sizeof salt[64]);
    //to_file(salt, NULL, 1);

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

void read_hash_in(const char** filename, unsigned char** hash_file_content, unsigned char** out_salt) {

    char* file_path[strlen("./") + strlen(*filename)];
    strcpy(*file_path, "./");
    strcat(*file_path, *filename);

    FILE* file_in = fopen(*file_path, "r");

    while (!feof(file_in))
    {
        **hash_file_content = fgetc(file_in);
    }
    fflush(file_in);
    fclose(file_in);

    file_in = fopen(SALT_TABLE_FILE, "r");
    unsigned char** hash_buff = (unsigned char**) sodium_allocarray(320, sizeof **hash_file_content);

    int cnt = 0;
    unsigned char cbuf;

    while (!feof(file_in))
    {

        cbuf = fgetc(file_in);
        if (cnt % 2 == 0) {
            if (cbuf == '\n') {
                cnt++;
                if (*out_salt == *hash_buff) {
                    break;
                }
                else {
                    sodium_memzero(hash_buff, sizeof(*hash_buff));
                }//
            } //If cur char is \n
            else {
                **hash_buff = fgetc(file_in);;
            }
        }
        else {

        }
    }

}


int chk_hash(unsigned char salt_to_use[64], unsigned char hash_to_chk[320],  const char* passwd)
{
    mk_hash_key(passwd, salt_to_use, hash_to_chk, 1, 0);

    return 0;
}



int main(int argc, char** argv) {
    if (sodium_init() < 0)
    {
        fprintf(stderr, "Sodium Init error");
    };

    get_timestmp();
    int arg_begin = 0;
    int valid = -1;
    char* result_out;
    char* func_arg;
    char* flags[OPT_ARR_LEN] = {"-h" ,"-r32","-r64","-f","-s","-chk", NULL};
    enum Opt_Cmds optCmds[OPT_ARR_LEN] = {HASH,RNDA,RNDB,TOFI,CHSH, END};
    void *opts [OPT_ARR_LEN] = { &mk_hash_key, &rando_32, &rando_64, &to_file, &chk_hash, NULL};


    if (argc > 1) {
        for (int i = 0; i < argc+1; i++) {
            if (**argv == 47)
            {
                arg_begin = i+1;
                break;
            }

        }
        func_arg = (char*) malloc(sizeof(argv[arg_begin]));
        strcpy(func_arg, argv[arg_begin]);
    } else {
        fprintf(stderr, "No commands Provided");
        return 1;
    }


    if (strcmp(func_arg, flags[RNDA]) == 0) {
        uint32_t *(*rando)() = opts[RNDA];
        *rando(NULL);
        goto opsdone;
    }
    else if (strcmp(func_arg, flags[RNDB]) == 0) {
        uint64_t *(*rando)() = opts[RNDB];
        *rando(NULL);
        goto opsdone;
    }

//
//


//    unsigned char **out = (unsigned char**) malloc(sizeof(out));
    int hshslt_opt = 2;

    if (strcmp(func_arg, flags[HASH]) == 0) {
        void *(*rando_hsh)() = opts[HASH];

        unsigned char* hashed_out;
        hashed_out = (unsigned char *) sodium_allocarray(320, sizeof(*hashed_out));

        unsigned char* salt;
        salt = (unsigned char *) sodium_allocarray(64, sizeof(*salt));

        mk_hash_key(PWD, salt, hashed_out, 0, 1);


        FILE* hashin;
        FILE* saltin;

        hashin = fopen("key_out", "rb");
        unsigned char hashbuf[320];

        fread(hashbuf,sizeof(hashbuf),1,hashin);

        saltin =fopen("salt_out", "rb");
        unsigned char saltbuf[64];

        fread(saltbuf, sizeof(saltbuf),1,saltin);

        unsigned char genhash[320];
        mk_hash_key(PWD, saltbuf, genhash, 1, 0);

        char* newpwd = "12342";

        printf("%d", sodium_memcmp(genhash,hashbuf,sizeof(hashbuf)));


        goto opsdone;
    }

    else if (strcmp(func_arg, flags[CHSH]) == 0) {
        void *(*rando_chkhsh)() = opts[CHSH];

    }


    opsdone:

        return 0;
    //



}
