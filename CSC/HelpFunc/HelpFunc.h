#include <cstddef>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <memory>
#include <limits>
#include <algorithm>
#include <numeric>
#include <cstdlib>
#include <cstring>
#include <assert.h>
#include <stdio.h>
#include <dirent.h>
#include "seal/seal.h"

using namespace std;
using namespace seal;

/**
 * @brief  Creates file with wanted error message
 * @note   
 * @param  error_msg: error message
 * @retval None
 */
void create_msg(string error_msg);

/**
 * @brief  Takes a condition from where and adds it into the condition vectors
 * @note   
 * @param  cond: Condition
 * @param  p: Path to table
 * @param  queriespath: Path to folder where the numbers to be compared are
 * @param  cond_cols: Vector with paths to cols from previous conditions
 * @param  cond_nums: Vector with paths to nums from previous conditions
 * @param  mode: Vector with the types of previous conditions comparisons
 * @retval None
 */
bool process_cond(string cond, string p, string queriespath, vector<string>* cond_cols, vector<string>* cond_nums, vector<int>* mode);
/**
 * @brief  
 * @note   
 * @param  x: 
 * @param  dir: 
 * @param  filename: 
 * @retval None
 */
void save_hom_enc(Ciphertext x, char *dir, char *filename);

/**
 * @brief  
 * @note   
 * @param  *dir: 
 * @param  *filename: 
 * @param  context: 
 * @retval 
 */
Ciphertext load_hom_enc(char *dir, char *filename, SEALContext context);

/**
 * @brief  Creates SEALCONTEXT
 * @note   
 * @retval 
 */
SEALContext create_context(int p_m_degree, int p_mod);


string d2h(int x);

/**
 * @brief  Converts decimal number into binary
 * @note
 * @param  n: Number to be converted
 * @retval
 */
vector<int> d2b(int n, int n_bit);

/**
 * @brief  Takes a hex string and converts it into an decimal string
 * @note
 * @param  x:
 * @retval
 */
int h2d(string x);

/**
 * @brief  Encrypts binary vector
 * @note   
 * @param  n: 
 * @param  *encryptor: 
 * @retval 
 */
vector<Ciphertext> enc_binary(vector<int> n, Encryptor *encryptor);

/**
 * @brief  Decrypts and prints ciphertext vector
 * @note   
 * @param  n: 
 * @param  *decryptor: 
 * @retval None
 */
void dec_prt_vec(vector<Ciphertext> n, Decryptor *decryptor);

/**
 * @brief  Prints int vector
 * @note   
 * @param  x: 
 * @retval None
 */
void print_vec(vector<int> x);

/**
 * @brief  Takes an int and encrypts it in two ways, as a hexadecimal string and as a binary number. It also saves them into files 
 * @note   
 * @param  x: Number to be encrypted
 * @param  *encryptor: 
 * @param  *directory: Name of directory where we are going to save the numbers
 * @retval None
 */
void enc_int_total(int x, Encryptor *encryptor, char *directory, int n_bit);

/**
 * @brief Loads an homormophic encrypted number into its respective Ciphertext and vector of Ciphertexts for hexadecimal and binary version
 * 
 * @param x_hex 
 * @param bin 
 * @param directory 
 * @param context 
 */
void dec_int_total(Ciphertext* x_hex, vector<Ciphertext>* bin, char* directory, SEALContext context);

/**
 * @brief  Check if a directory exists
 * @note   
 * @param  dirname: 
 * @retval 
 */
bool chkdir(char* dirpath);

/**
 * @brief  
 * @note   
 * @param  tablename: 
 * @retval None
 */

bool createdir(char* dirpath);

/**
 * @brief Gets next line number from a collumn
 * 
 * @param columndir 
 * @return string 
 */
string getlinenumber(char *columndir);

