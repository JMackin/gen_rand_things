//
// Created by ujlm on 7/16/23.
//

#ifndef GEN_RAND_THINGS_RAND_THINGS_H
#define GEN_RAND_THINGS_RAND_THINGS_H

#define OPT_ARR_LEN 7


uint64_t rando_64(void);
uint64_t rando_32(void);

void* mk_salt(unsigned char* out[320],
              const unsigned char* inp,
              int to_bytes);

void* mk_hash_key(const char* to_be_hashed,
                  unsigned char* salt_inst[64],
                  unsigned char* hashed_out[320],
                  int give_salt);

void* to_file(unsigned char* salt[64],
              unsigned char* hashed[320],
              int opt);

void* read_hash_in(const char** filename, unsigned char** hash_file_content, unsigned char** out_salt);

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
