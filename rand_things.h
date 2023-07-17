//
// Created by ujlm on 7/16/23.
//

#ifndef GEN_RAND_THINGS_RAND_THINGS_H
#define GEN_RAND_THINGS_RAND_THINGS_H

#define OPT_ARR_LEN 7


uint64_t rando_64(void);
uint64_t rando_32(void);
unsigned char* mk_salt(const char*);


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
        SALT = 4, //Generate random 64-bit Salt
                    // IN: NULL
                    // RET: uint
        CHSH = 5, //Compare given password str to a hash value
                    // IN: hashchk <char* passwd>, <uint_64 hash[320]>, <uint64 salt[64]
                    // RET: int 0 - passed comparison check, int 1 - failed cmp chk
        END = 6

};



#endif //GEN_RAND_THINGS_RAND_THINGS_H
