#include <iostream>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <seal/seal.h>
using namespace std;
using namespace seal;

/**
 * @brief  Converts decimal number into binary
 * @note
 * @param  n: Number to be converted
 * @retval
 */
vector<int> d2b(int n);


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
 * @brief  Implements NOT gate
 * @note   
 * @param  a: 
 * @param  *evaluator: 
 * @param  relinks: Keys for relinearization
 * @retval 
 */
Ciphertext NOT(Ciphertext a, Evaluator *evaluator, RelinKeys relinks);

/**
 * @brief  Implements AND gate
 * @note   
 * @param  a: 
 * @param  b: 
 * @param  *evaluator: 
 * @param  relinks: Keys for relinearization
 * @retval 
 */
Ciphertext AND(Ciphertext a, Ciphertext b, Evaluator *evaluator, RelinKeys relinks);


/**
 * @brief  Implements NAND gate
 * @note   
 * @param  a: 
 * @param  b: 
 * @param  *evaluator: 
 * @param  relinks: Keys for relinearization
 * @retval 
 */
Ciphertext NAND(Ciphertext a, Ciphertext b, Evaluator *evaluator, RelinKeys relinks);


/**
 * @brief  Checks a>b condition
 * @note   
 * @param  a: 
 * @param  b: 
 * @param  *evaluator: 
 * @param  relinks: Keys for relinearization
 * @retval 
 */
Ciphertext gt(Ciphertext a, Ciphertext b, Evaluator *evaluator, RelinKeys relinks);

/**
 * @brief  Checks a<b condition
 * @note   
 * @param  a: 
 * @param  b: 
 * @param  *evaluator: 
 * @param  relinks: Keys for relinearization
 * @retval 
 */
Ciphertext lt(Ciphertext a, Ciphertext b, Evaluator *evaluator, RelinKeys relinks);


/**
 * @brief  Implementes equality condition through a XNOR
 * @note   
 * @param  gt: 
 * @param  lt: 
 * @param  *evaluator: 
 * @param  relinks: 
 * @retval 
 */
Ciphertext XNOR(Ciphertext gt, Ciphertext lt, Evaluator *evaluator, RelinKeys relinks);

/**
 * @brief  Implements OR gate
 * @note   
 * @param  a: 
 * @param  b: 
 * @param  *evaluator: 
 * @param  relinks: Keys for relinearization
 * @retval 
 */
Ciphertext OR(Ciphertext a, Ciphertext b, Evaluator *evaluator, RelinKeys relinks);


/**
 * @brief  Makes first comparison which doesn't need previous output
 * @note   
 * @param  A: 
 * @param  B: 
 * @param  *evaluator: 
 * @param  relinks: 
 * @retval 
 */
vector<Ciphertext> init_bit_comparator(Ciphertext A, Ciphertext B, Evaluator *evaluator, RelinKeys relinks);


/**
 * @brief  Implements the comparison between 2 bits taking into account more significant bits
 * @note   
 * @param  A: 
 * @param  B: 
 * @param  *evaluator: 
 * @param  prev: 
 * @param  relinks: Keys for relinearization
 * @retval 
 */
vector<Ciphertext> bit_comparator(Ciphertext A, Ciphertext B, Evaluator *evaluator, vector<Ciphertext> prev, RelinKeys relinks);


/**
 * @brief  Implements full comparator which returns the result as a vector of 3 ciphertexts with the results of the 3 operations
 * @note   
 * @param  x: 
 * @param  y: 
 * @param  *evaluator: 
 * @param  relinks: Keys for relinearization
 * @param  *decryptor: 
 * @retval 
 */
vector<Ciphertext> full_homomorphic_comparator(vector<Ciphertext> x, vector<Ciphertext> y, Evaluator *evaluator, RelinKeys relinks);

/**
 * @brief  Comparator with prints inbetween comparisons to observe the evolution of noise budget
 * @note   
 * @param  x: 
 * @param  y: 
 * @param  *evaluator: 
 * @param  relinks: 
 * @param  *decryptor: 
 * @retval 
 */
vector<Ciphertext> full_homomorphic_comparator_debug_version(vector<Ciphertext> x, vector<Ciphertext> y, Evaluator *evaluator, RelinKeys relinks, Decryptor *decryptor);
