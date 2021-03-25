# AES Algorithm

AES encryption is commonly used in a lot of ways, including wireless security, processor security, file encryption, and SSL/TLS.
In fact, your web browser probably used AES to encrypt your connection with this website(Github).

In this Algorithm,I am using the C language.

Basically this algorithm breaks into four part

1)SubByte

2)ShiftRows

3)MixColumn

4)Key formation and expansion

If you want to read the AES Algorithm then you may read from this link:- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

** Implementation details

uint8_t Key[16][16]; for Saving the current key corresponding to the running round which comes from the function keyFormation

 uint32_t word[44]; this array is used for saving all the 44 word which comes from the function keyExpansion(cipherkey).Also this word
 
 array is very useful when you make round keys.

 uint8_t multiplication[4][4]; This multiplication array stores the value after the MixColumn Operation
 
 uint8_t mix_Matrix[4][4] This is predifined matrix of polynomial multiplication and used in MixColumn Operation
 
 uint8_t subTable[16][16] Predefined Subbyte Table
 
////////////////////  Functions

/// SubByte Function

uint8_t operationSubbyte(uint8_t text)-> Used to find the Subbyte of the given text.

//// Key Scheduling Functions

uint32_t rotWord(uint32_t temp)->Finding the rotword of the variavle temp.

 uint32_t subWord(uint32_t temp) -> Finding the SubWord of the given Word temp.
 
uint32_t funWord(uint32_t word, int index) Function is used when Cummulative RotWord SubWord Xor with Rcon on last column of RoundKeys

void keyExpansion(uint32_t Key[4])-> This is very useful function because it finds all the 44 Word which is used in all Round Keys

void keyformataion(uint32_t word0, uint32_t word1, uint32_t word2, uint32_t word3)-> This function forms the current round keys from the given Words

////  ShiftRow 

void shiftRows(uint8_t arr[][4], uint8_t arr1[][4]) ShiftRow Operation.This takes one array aur shifts the into another array

////// Mixcolumns

uint8_t xTimesFun(uint8_t temp)-> This is the polynomial function like x*temp which we discussed in the class

uint8_t multiply_index(int i, int j, uint8_t mix_Matrix[][4], uint8_t byte_Matrix[][4], int length) In this method we are trying to do matrix multiplication of predefined

 mix_array and Byte Array(Our input)

 void operationMixColumn(uint8_t mix_Matrix[][4], uint8_t byte_Matrix[][4], int length) In this method we compute every Index of the multiplication matrix
 
 print Array() this method prints the 2D matrix
