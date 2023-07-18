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
void* to_file(unsigned char* salt[64], unsigned char* hashed[320], int opt) {

    FILE *sf_ptr;
    int opt_ch = opt<<1;
    char* filename = (char *) malloc(CHAR_MAX-16);

decr:
    opt_ch = opt_ch>>1;

    switch (opt_ch) {
        case 8:
            opt_ch = opt_ch>>1;
            goto hshstr_out;
            break;
        case 4:
            goto hshkey_out;
            break;
        case 2:
            goto salt_out;
            break;
        case 1:
            printf("\n%d\n", (*filename ? *filename : -1));
            return 0;
            break;
        default:
            goto cleanup;
            break;
    }


    salt_out:


        if (!realloc(filename, (size_t) sizeof("salt")+sizeof(*tm_str))) {
            free(filename);
            fprintf(stderr, "memory failure allocating for filename");
        }


        strcpy(filename,"salt");
        strcat(filename, *tm_str);

        sf_ptr = fopen(filename, "wb");

        if(sf_ptr == NULL)
        {
            printf("Error!");
            exit(1);
        }
        fwrite(salt, sizeof(*salt), 1, sf_ptr);
        fclose(sf_ptr);

        goto decr;


    hshkey_out:

    if (!realloc(filename, (size_t) sizeof("hshkey")+sizeof(*tm_str))) {
        free(filename);
        fprintf(stderr, "memory failure allocating for filename");
    }
        filename[sizeof("key")+sizeof(tm_str)];

        strcpy(filename,"key");
        strcat(filename, *tm_str);

        sf_ptr = fopen(filename, "wb");

        if(sf_ptr == NULL)
        {
            fprintf(stderr, "File-open Error");
        }

        fwrite(hashed, sizeof(*hashed), 1, sf_ptr);

        fclose(sf_ptr);

        sf_ptr = fopen(filename, "rb");
        fflush(sf_ptr);



    hshstr_out:

        printf("not implemented yet.");
        goto decr;

    cleanup:
        if (strlen(filename) > 2) {
            free(filename);
        };

}

void* mk_hash_key(const char* to_be_hashed, unsigned char* salt_inst[64], unsigned char* hashed_out[320], int give_salt) {



    if (sodium_init() < 0) {
        fprintf(stderr, "Sodium init Error!");
        exit(1);
    }

    if (give_salt == 0) {
        *salt_inst = mk_salt(salt_inst, NULL, 0);
    }

    unsigned long long passlen = 256;
    unsigned long long outlen = 256+sizeof(*salt_inst);

    // Salt+Password


    if ((crypto_pwhash(*hashed_out,
                  outlen,
                  to_be_hashed,
                      passlen,
                  *salt_inst,
                  crypto_pwhash_OPSLIMIT_SENSITIVE,
                      crypto_pwhash_MEMLIMIT_SENSITIVE,
                  crypto_pwhash_ALG_DEFAULT)) < 0) {
        fprintf(stderr,"Hashing Error!");
        exit(1);
    }

    return hashed_out;

}

void* mk_salt(unsigned char* salt[64], const unsigned char* inp, int to_bytes) {

    if (inp != NULL && to_bytes == 1) {

        saltbytes = (uint64_t) *inp;

    } else if(inp != NULL && (to_bytes == 0)){

        for (int i = 0; i < 64; i++) {

            *salt[i] = *inp;
        }

    } else if (!*inp) {

        saltbytes = rando_64();

    } else {

        fprintf(stderr, "Error handling salt");

    }

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

void* read_hash_in(const char** filename, unsigned char** hash_file_content, unsigned char** out_salt) {

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


int chk_hash(unsigned char* salt_to_use[64], unsigned char* hash_to_chk[320], const char* passwd)
{
    mk_hash_key(passwd,salt_to_use,hash_to_chk,1);

    return 0;
}


int main(int argc, char** argv) {
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
//    unsigned char **salt  = (unsigned char**) malloc(sizeof(salt));
//    unsigned char **out = (unsigned char**) malloc(sizeof(out));
    unsigned char **salt;
    unsigned char **out;
    if (strcmp(func_arg, flags[HASH]) == 0) {
        void *(*rando)() = opts[HASH];
    }
    else if (strcmp(func_arg, flags[CHSH]) == 0) {
        void *(*rando)() = opts[CHSH];
    }



    opsdone:
        return 0;
    //
    // free(argv);


}
