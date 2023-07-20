//
// Created by ujlm on 7/16/23.
//

#ifndef GEN_RAND_THINGS_RAND_THINGS_H
#define GEN_RAND_THINGS_RAND_THINGS_H

#define OPT_ARR_LEN 7


uint64_t rando_64(void);
uint64_t rando_32(void);

void mk_salt(unsigned char* out[64],
              const unsigned char* outp,
              int to_bytes);

void mk_hash_key(const char* to_be_hashed,
                 unsigned char salt_inst[64],
                  int give_salt,
                 int tofile);

// opt 1 = salt (bytes), opt 2 = hashkey (bytes), opt 4 = hashkey (ascii)
int to_file(unsigned char* salt,
            unsigned char* hashed,
            int opt);


void read_hash_in(const char** filename, unsigned char** hash_file_content, unsigned char** out_salt);

int chk_hash(unsigned char* salt_to_use[64],
             unsigned char* hash_to_chk[320],
             const char* passwd);





enum Opt_Cmds {

        HASH = 0, //Hash a given string
                    // IN : <char* string>
                    // OUT :
        RNDA = 1, //Return random 32 bit uint
                    // IN: NULL
                    // OUT: <uint_64>
        RNDB = 2, //Return random 64 but uint
                    // IN: NULL
                    // OUT: <uint_64>
        TOFI = 3, //Print values to file, appended to hashing or salting opts
                    // IN: <prev cmd flags> <char* "tofile" | "-f">

        CHSH = 4, //Compare given password str to a hash value
                    // IN: hashchk <char* passwd>, <uint_64 hash[320]>, <uint64 salt[64]
                    // RET: int 0 - passed comparison check, int 1 - failed cmp chk
        END = 5

};



#endif //GEN_RAND_THINGS_RAND_THINGS_H
