#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "libsodium-1.0.18/src/libsodium/include/sodium.h"
#include "rand_things.h"

#define PWD "suchagoodpasswowrd"

#define KEY_LEN crypto_box_SEEDBYTES
#define OPSLIMIT_JLMMECHA 10U // 10 ops
#define MEMLIMIT_JLMMECHA 32000000000U //32 GB
#define OPSLIMIT_ENIGMECHA 10U // 10 ops
#define MEMLIMIT_ENIGMECHA 1000000000U //1 GB
#define OUTPUT_DIR_KEY_FILE ".hkeys"
#define OUTPUT_DIR_SALT_FILE ".salts"


struct timeval tv;

char tm_str[sizeof tv.tv_sec];


int recv_pwd(unsigned char pwd_in[100], int opt) {

    struct termios termInfo;

    unsigned char* pwd_buf = sodium_allocarray(100,sizeof(char));
    sodium_mlock(pwd_buf,100);
    char i = 0;
    int cnt = 0;
    printf("\n\nPassword: ");

    while (i != '\n')
    {
                scanf("%c",&i);
        putc('*', stdout);
        if (i != '\n') {
            pwd_buf[cnt] = i;
            cnt++;
        }

    }

    for (int j = 0; j < cnt; j++){
        pwd_in[i] = pwd_buf[i];
    }
    sodium_munlock(pwd_buf,100);
    sodium_free(pwd_buf);
    return 0;
}

void get_timestmp() {

    gettimeofday(&tv,NULL);
    sprintf((char *) tm_str, "%lu", tv.tv_sec);

}

//dir_flag: 0=home_dir, 1=cwd, 2=salt_dir, 3=key_dir
char* nav_dirs(int dir_flag){

    char* refd_dir;
    char* ret_dir_path;
    int v;
    char* var_mark[5] = {"HOME", "PWD", "/.salts", "/.hkeys", "HOSTNAME"};

    v = ((dir_flag > -1 & dir_flag < 4) ? dir_flag : -1);

    switch (v) {
        case (-1):
            fprintf(stderr, "\nInvalid directory flag\n");
            ret_dir_path = NULL;
            return NULL;
        case (0):
        case (1):
            refd_dir = getenv(var_mark[v]);
            if (refd_dir != NULL) {
                ret_dir_path = (char *) malloc(strlen(refd_dir));
                strcpy(ret_dir_path, refd_dir);
                return ret_dir_path;
            } else {
                fprintf(stderr, "\nCouldn't get environment variable %s\n", var_mark[v]);
                ret_dir_path = ".";
                return NULL;
            }
        case (2):
        case (3):
            refd_dir = nav_dirs(0);
            if (refd_dir == NULL) {
                fprintf(stderr, "\nCouldnt assign %s dir\n", var_mark[v]);
                return NULL;
            }
            ret_dir_path = (char *) malloc(strlen(refd_dir) + strlen(var_mark[v]));
            strcpy(ret_dir_path, refd_dir);
            free(refd_dir);
            strcat(ret_dir_path, var_mark[v]);
            return ret_dir_path;
        default:
            fprintf(stderr, "Invalid case %d", v);
            return NULL;
    }


}


// opt 1 = salt (bytes), opt 2 = hashkey (bytes), opt 4 = hashkey (ascii)
int to_file(const unsigned char salt[64u], const unsigned char hashed[320u], int opt) {

    FILE *sf_ptr;

    int opt_ch = opt<<1;
    int i;

    char* s_word = "salt_";
    char* k_word = "hkey_";
    char x;
    char s_filename[(size_t)  strlen(s_word) + strlen(tm_str)];
    char k_filename[(size_t)  strlen(k_word) + strlen(tm_str)];
    int j = strlen(s_word);

    for ( i = 0; i < strlen(s_word); i++)
    {
        s_filename[i] = *(s_word+i);
        k_filename[i] = *(k_word+i);
    }
    for ( i = 0; i < strlen(tm_str); i++)
    {

        x = tm_str[i];

        s_filename[i+j] = x;
        k_filename[i+j] = x;
    }


    //printf("Salt_file: %s", filename);


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

        chdir(nav_dirs(2));
        sf_ptr = fopen(s_filename, "wb");

        if(sf_ptr == NULL)
        {
            printf("Error!");
            exit(1);
        }

        for ( i = 0; i < 64+strlen(tm_str); i++){
            if (i < strlen(tm_str)*2){
                fputc((i%2==0 ? *(salt+(i/2)) : (char) tm_str[((i+1)/2)-1]), sf_ptr);
            }else
            {
                fputc(*(salt+(i-strlen(tm_str))), sf_ptr);
            }
        }

//        for (i = 0; i < 64; i++) {
//            fputc(*(salt+i), sf_ptr);
//        }


        fclose(sf_ptr);

        goto decr;


    hshkey_out:
    chdir(nav_dirs(3));
   // char* filen2[(sizeof("key")+sizeof(tm_str))];
    //strcpy((char *) filename, "key");

        sf_ptr = fopen(k_filename, "wb");

        if(sf_ptr == NULL)
        {
            fprintf(stderr, "File-open Error");
        }

        for ( i = 0; i < 320+strlen(tm_str); i++){
            if (i < strlen(tm_str)*2){
                fputc((i%2==0 ? *(hashed+(i/2)) : (char) tm_str[((i+1)/2)-1]), sf_ptr);
            }else
            {
                fputc(*(hashed+(i-strlen(tm_str))), sf_ptr);
            }
        }

//        for ( i = 0; i < 320; i++){
//            fputc(*(hashed+i), sf_ptr);
//        }

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

    uint64_t saltbytes;

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
    //printf("%s\n\n", buff);
    uint32_t rnd_byts = randombytes_random();
    //printf("%u\n", rnd_byts);
    //printf("%u\n", clck);

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
    //printf("%s\n\n", buff);
    uint64_t rnd_byts = (randombytes_random() * 2) << 16;
    //printf("%lu\n", rnd_byts);
   // printf("%lu\n", clck);

    rnd_byts = (rnd_byts ^ clck);

    printf("%lu\n", rnd_byts);

    randombytes_close();
    return rnd_byts;
}

int read_hash_in(char id[10] , unsigned char hash_file_content[320u], unsigned char salt_file_content[64u]) {

    int i;
    FILE* hash_file;
    FILE* salt_file;
    char ts_id_a[10];
    char ts_id_b[10];
    unsigned char c_buf;

    char* saltdir_path = nav_dirs(2);
    chdir(saltdir_path);
    char* salt_file_name = malloc(strlen(saltdir_path) + strlen("/salt_")+ strlen(id));

    strcpy(salt_file_name,saltdir_path);
    strcat(salt_file_name,"/salt_");
    strcat(salt_file_name,id);


    salt_file = fopen(salt_file_name, "rb");

    for (i = 0; i < 74; i++){
        c_buf = fgetc(salt_file);
        if (i < 20){
             i%2==0 ? (salt_file_content[i/2] = c_buf) : (ts_id_a[ (((i+1)/2)-1) ] = (char) c_buf);
        }
        else {
            salt_file_content[i-10] = c_buf;
        }
    }

    fclose(salt_file);
    free(salt_file_name);


    char* hkeydir_path = nav_dirs(3);
    chdir(hkeydir_path);
    char* hkey_file_name = malloc(strlen(hkeydir_path) + strlen("/hkey_") + strlen(id));

    strcpy(hkey_file_name,hkeydir_path);
    strcat(hkey_file_name,"/hkey_");
    strcat(hkey_file_name,id);

    hash_file = fopen(hkey_file_name, "rb");

    for (i = 0; i < 330; i++){
        c_buf = fgetc(hash_file);
        if (i < 20){
            i%2==0 ? (hash_file_content[i/2] = c_buf) : (ts_id_b[ (((i+1)/2)-1) ] = (char) c_buf);
        }
        else {
            hash_file_content[i-10] = c_buf;
        }
    }

    fclose(hash_file);
    free(hkey_file_name);


    int id_match = 0;
    for (i = 0; i < 10; i++)
    {
        if ((ts_id_a[i]) != (ts_id_b[i])) {
            id_match = i+1;
            break;
        }
    }


    if (id_match != 0) {
        fprintf(stderr, "Extracted salt and hash ids mismatched at index %d", (id_match-1));
        return (id_match);
    }else
    {
        printf("\nID: %s\n",ts_id_a);
        return 0;
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
    int flag = 0, cnt = 0;
    char* result_out;
    char* func_arg;
    char* flags[OPT_ARR_LEN] = {"-h" ,"-r","-R","-f","-c","-k", NULL};
    enum Opt_Cmds optCmds[OPT_ARR_LEN] = {HASH,RNDA,RNDB,TOFI,CHSH,MKKY,END};
    void *opts [OPT_ARR_LEN] = { &mk_hash_key, &rando_32, &rando_64, &to_file, &chk_hash,&mk_hash_key, NULL};


    if (argc > 1) {
        for (int i = 0; i < argc+1; i++) {
            if (**argv == 47)
            {
                arg_begin = i+1;
                break;
            }
        }

    } else {
        fprintf(stderr, "No commands Provided");
        return 1;
    }

    func_arg = (char*) malloc(sizeof(argv[arg_begin]));
    strcpy(func_arg, argv[arg_begin]);

    while (optCmds[cnt] != END){
        if (strcmp(func_arg, flags[cnt]) == 0) {
            flag = cnt;
            valid = 0;
            break;
        }
        else {
            cnt++;
        }
    }


    if (valid != 0) {
        printf("Invalid option: %s", func_arg);
        return 1;
    }


    if (flag == RNDA) {
        uint32_t *(*rando)() = opts[RNDA];
        *rando();
        goto opsdone;
    }
    else if (flag == RNDB) {
        uint64_t *(*rando)() = opts[RNDB];
        *rando();
        goto opsdone;
    }


    if (flag == HASH) {
        //void *(*rando_hsh)() = opts[HASH];

        unsigned char* hashed_out;
        hashed_out = (unsigned char *) sodium_allocarray(320, sizeof(*hashed_out));

        unsigned char* salt;
        salt = (unsigned char *) sodium_allocarray(64, sizeof(*salt));

        mk_hash_key(, salt, hashed_out, 0, 1);

        sodium_memzero(hashed_out, 320);
        sodium_memzero(hashed_out, 64);

        sodium_free(hashed_out);
        sodium_free(salt);

        goto opsdone;
    }

    else if (flag == CHSH) {
        //void *(*rando_chkhsh)() = opts[CHSH];

        if (argv[arg_begin+1] && strlen(argv[arg_begin+1]) == 10) {
            func_arg = realloc(func_arg, sizeof argv[arg_begin+1]);
        }
        else {
            fprintf(stderr, "\n Invalid ID argument \n");
            return 1;
        }

        strcpy(func_arg,argv[arg_begin+1]);
        if (!func_arg){
            fprintf(stderr, "\nReallocation for 2nd argument failed\n");
            return 1;
        }

        unsigned char* hashed_out;
        hashed_out = (unsigned char *) sodium_allocarray(320, sizeof(*hashed_out));
        unsigned char* salt;
        salt = (unsigned char *) sodium_allocarray(64, sizeof(*salt));

        read_hash_in(func_arg,hashed_out,salt);

        sodium_mlock(hashed_out, 320);




        sodium_munlock(hashed_out, 320);

        sodium_free(hashed_out);
        sodium_free(salt);





        goto opsdone;

    }


    opsdone:
        free(func_arg);
        return 0;
    //



}
