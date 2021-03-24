// Author-Anjul Gupta
// Emailid-anjulgupta712@gmail.com
// Institute Id-201851022
// Date-22/03/2021
// Time-09:55


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// uint8_t Key[16][16]; for Saving the current key corresponding to the running round which comes from the function keyFormation
// uint32_t word[44]; this array is used for saving all the 44 word which comes from the function keyExpansion(cipherkey).Also this word
// array is very useful when you make round keys.
//
// uint8_t multiplication[4][4]; This multiplication array stores the value after the MixColumn Operation
// uint8_t mix_Matrix[4][4] This is predifined matrix of polynomial multiplication and used in MixColumn Operation
// uint8_t subTable[16][16] Predefined Subbyte Table
////////////////////  Functions
/// SubByte Function
// uint8_t operationSubbyte(uint8_t text)-> Used to find the Subbyte of the given text.
//// Key Scheduling Functions
// uint32_t rotWord(uint32_t temp)->Finding the rotword of the variavle temp.
// uint32_t subWord(uint32_t temp) -> Finding the SubWord of the given Word temp.
// uint32_t funWord(uint32_t word, int index) Function is used when Cummulative RotWord SubWord Xor with Rcon on last column of RoundKeys
// void keyExpansion(uint32_t Key[4])-> This is very useful function because it finds all the 44 Word which is used in all Round Keys
// void keyformataion(uint32_t word0, uint32_t word1, uint32_t word2, uint32_t word3)-> This function forms the current round keys from the given Words
////  ShiftRow 
// void shiftRows(uint8_t arr[][4], uint8_t arr1[][4]) ShiftRow Operation.This takes one array aur shifts the into another array
////// Mixcolumns
// uint8_t xTimesFun(uint8_t temp)-> This is the polynomial function like x*temp which we discussed in the class
// uint8_t multiply_index(int i, int j, uint8_t mix_Matrix[][4], uint8_t byte_Matrix[][4], int length) In this method we are trying to do matrix multiplication of predefined\
// mix_array and Byte Array(Our input)
//
// void operationMixColumn(uint8_t mix_Matrix[][4], uint8_t byte_Matrix[][4], int length) In this method we compute every Index of the multiplication matrix
// print Array() this method prints the 2D matrix
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
uint8_t Key[16][16];
uint32_t word[44];
uint32_t Rcon[10] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
                     0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000};
uint8_t multiplication[4][4];
uint8_t mix_Matrix[4][4] = {{2, 3, 1, 1}, {1, 2, 3, 1}, {1, 1, 2, 3}, {3, 1, 1, 2}};

uint8_t subTable[16][16] = {{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
                            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
                            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
                            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
                            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
                            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
                            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
                            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
                            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
                            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
                            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
                            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
                            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
                            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
                            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
                            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};

uint8_t operationSubbyte(uint8_t text)
{
    int r = text >> 4;
    //printf("%x\n",r);
    int c = text & 15;
    //printf("%x\n",c);
    return subTable[r][c];
}
uint32_t rotWord(uint32_t temp)
{
    uint32_t mod;
    mod = (temp >> 24) & 0xff;
    return mod | temp << 8;
}
uint32_t subWord(uint32_t temp)
{
    uint8_t arr[4];
    arr[0] = (temp >> 24) & 0xFF;

    arr[1] = (temp >> 16) & 0xFF;
    arr[2] = (temp >> 8) & 0xFF;
    arr[3] = (temp)&0xFF;
    arr[0] = operationSubbyte(arr[0]);
    //printf("%x\n",arr[0]);
    arr[1] = operationSubbyte(arr[1]);
    arr[2] = operationSubbyte(arr[2]);
    arr[3] = operationSubbyte(arr[3]);
    temp = arr[3] | (arr[2] << 8) | (arr[1] << 16) | (arr[0] << 24);
    ;
    return temp;
}

uint32_t funWord(uint32_t word, int index)
{
    //printf("%x\n", Rcon[index / 4]);
    word = subWord(rotWord(word)) ^ Rcon[index / 4];

    return word;
}

void keyExpansion(uint32_t Key[4])
{

    word[0] = Key[0];
    word[1] = Key[1];
    word[2] = Key[2];
    word[3] = Key[3];

    for (int i = 4; i < 44; i++)
    {
        uint32_t temp = word[i - 1];
        if (i % 4 == 0)
        {
            word[i] = funWord(temp, i - 1) ^ word[i - 4];
        }
        else
        {
            word[i] = temp ^ word[i - 4];
        }
    }
}

void keyformataion(uint32_t word0, uint32_t word1, uint32_t word2, uint32_t word3)
{

    Key[0][0] = (word0 >> 24) & 0xFF;
    Key[1][0] = (word0 >> 16) & 0xFF;
    Key[2][0] = (word0 >> 8) & 0xFF;
    Key[3][0] = (word0)&0xFF;
    Key[0][1] = (word1 >> 24) & 0xFF;
    Key[1][1] = (word1 >> 16) & 0xFF;
    Key[2][1] = (word1 >> 8) & 0xFF;
    Key[3][1] = (word1)&0xFF;
    Key[0][2] = (word2 >> 24) & 0xFF;
    Key[1][2] = (word2 >> 16) & 0xFF;
    Key[2][2] = (word2 >> 8) & 0xFF;
    Key[3][2] = (word2)&0xFF;
    Key[0][3] = (word3 >> 24) & 0xFF;
    Key[1][3] = (word3 >> 16) & 0xFF;
    Key[2][3] = (word3 >> 8) & 0xFF;
    Key[3][3] = (word3)&0xFF;
}
void shiftRows(uint8_t arr[][4], uint8_t arr1[][4])
{
    for (int i = 0; i < 4; i++)
    {
        int pointer = 0;
        int column_iterator = 0;
        for (int j = i; pointer < 4; j++)
        {
            if (j == 4)
            {
                j = 0;
            }
            arr1[i][column_iterator++] = arr[i][j];
            // printf("%d\n",arr[i][j]);
            pointer++;
        }
    }
}
uint8_t xTimesFun(uint8_t temp)
{
    int a7 = (temp >> 7);
    //printf("%d\n",a7);
    if (a7 == 0)
    {
        return temp << 1;
    }
    else
    {
        return (temp << 1) ^ 27;
    }
}

uint8_t multiply_index(int i, int j, uint8_t mix_Matrix[][4], uint8_t byte_Matrix[][4], int length)
{
    uint8_t temp = 0;
    // printf("length= %d \n",length);
    for (int k = 0; k < length; k++)
    {
        if (mix_Matrix[i][k] == 2)
        {   //  printf("Mix_matrix=%d\n",mix_Matrix[i][k]);
            //     printf("[%d %d %d]\n",i,j,k);
            temp = temp ^ xTimesFun(byte_Matrix[k][j]);
            // printf("Value of respected char %d\n",xTimesFun(byte_Matrix[k][j]));
        }
        else
        {
            if (mix_Matrix[i][k] == 3)
            {   //  printf("Mix_matrix=%d\n",mix_Matrix[i][k]);
                //     printf("[%d %d %d]\n",i,j,k);
                temp = temp ^ xTimesFun(byte_Matrix[k][j]) ^ byte_Matrix[k][j];
                // printf("Value of respected char %d\n",xTimesFun(byte_Matrix[k][j]^byte_Matrix[k][j]));
            }
            else
            { //  printf("Mix_matrix=%d\n",mix_Matrix[i][k]);
                //  printf("[%d %d %d]\n",i,j,k);
                temp = temp ^ byte_Matrix[k][j];
                // printf("Value of respected char %d\n",xTimesFun(byte_Matrix[k][j]));
            }
        }
    }
    return temp;
}

void operationMixColumn(uint8_t mix_Matrix[][4], uint8_t byte_Matrix[][4], int length)
{
    for (int i = 0; i < length; i++)
    {
        for (int j = 0; j < length; j++)
        {

            multiplication[i][j] = multiply_index(i, j, mix_Matrix, byte_Matrix, length);
        }
    }
}

void printArray(uint8_t arr[][4])
{
    for (int i = 0; i < 4; i++)
    {
        printf("[");
        for (int j = 0; j < 4; j++)
        {
            printf("%x ", arr[i][j]);
        }
        printf("]\n");
    }
    printf("\n");
}

int main()
{
    uint8_t plaintext[4][4] = {{0x32, 0x88, 0x31, 0xe0},
                               {0x43, 0x5a, 0x31, 0x37},
                               {0xf6, 0x30, 0x98, 0x07},
                               {0xa8, 0x8d, 0xa2, 0x34}};
    uint32_t cipherKey[4] = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
    keyExpansion(cipherKey);
    keyformataion(word[0], word[1], word[2], word[3]);
    uint8_t temp[4][4];
    uint8_t temp1[4][4];
    //For Round 0
    for (int i = 0; i < 4; i++)
    {
        printf("[");
        for (int j = 0; j < 4; j++)
        {
            temp[i][j] = plaintext[i][j] ^ Key[i][j];
            printf("%x ", temp[i][j]);
            temp[i][j] = operationSubbyte(temp[i][j]);
        }
        printf("]\n");
    }
    // From Round 1 to Round 9
    for (int i = 1; i < 10; i++)
    {

        shiftRows(temp, temp1);
       // printf("Shiftrows\n");
       // printArray(temp1);

        operationMixColumn(mix_Matrix, temp1, 4);
        keyformataion(word[4 * i], word[(4 * i) + 1], word[(4 * i) + 2], word[(4 * i) + 3]);
        printf("Cipher text of Round %d\n",i);
        for (int j = 0; j < 4; j++)
        {
            
            printf("[");
            for (int k = 0; k < 4; k++)
            {
                temp[j][k] = multiplication[j][k] ^ Key[j][k];
                printf("%x ", temp[j][k]);
                temp[j][k] = operationSubbyte(temp[j][k]);
            }
            printf("]\n");
        }
        printf("\n");
    }

    shiftRows(temp, temp1);
    keyformataion(word[40], word[41], word[42], word[43]);
    printf("Final Round and Encrypted CipherText\n");
    for (int i = 0; i < 4; i++)
    {
        printf("[");
        for (int j = 0; j < 4; j++)
        {
            temp[i][j] = temp1[i][j] ^ Key[i][j];
            printf("%x ", temp[i][j]);
        }
        printf("]\n");
    }
}