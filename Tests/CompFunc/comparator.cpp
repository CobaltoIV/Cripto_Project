#include <iostream>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include "seal/seal.h"
using namespace std;
using namespace seal;

/**
 * @brief  Implements NOT gate
 * @note   
 * @param  a: input of gate
 * @param  *evaluator: 
 * @param  relinks: Keys for relinearization
 * @retval 
 */
Ciphertext NOT(Ciphertext a, Evaluator *evaluator, RelinKeys relinks)
{
    Ciphertext a_neg, result;
    Plaintext plain_one("1");
    (*evaluator).negate(a, a_neg);
    //(*evaluator).relinearize_inplace(a_neg, relinks);
    (*evaluator).add_plain(a_neg, plain_one, result);
    //(*evaluator).relinearize_inplace(result, relinks);
    return result;
}
/**
 * @brief  Implements AND gate
 * @note   
 * @param  a: Input 1
 * @param  b: Input 2
 * @param  *evaluator: 
 * @param  relinks: Keys for relinearization
 * @retval 
 */
Ciphertext AND(Ciphertext a, Ciphertext b, Evaluator *evaluator, RelinKeys relinks)
{
    Ciphertext result;
    (*evaluator).multiply(a, b, result);
    (*evaluator).relinearize_inplace(result, relinks);
    return result;
}

/**
 * @brief  Implements NAND gate
 * @note   
 * @param  a: 
 * @param  b: 
 * @param  *evaluator: 
 * @param  relinks: Keys for relinearization
 * @retval 
 */
Ciphertext NAND(Ciphertext a, Ciphertext b, Evaluator *evaluator, RelinKeys relinks)
{
    Ciphertext result;
    return result = NOT(AND(a, b, evaluator, relinks), evaluator, relinks);
}

/**
 * @brief  Checks a>b condition
 * @note   
 * @param  a: 
 * @param  b: 
 * @param  *evaluator: 
 * @param  relinks: Keys for relinearization
 * @retval 
 */
Ciphertext gt(Ciphertext a, Ciphertext b, Evaluator *evaluator, RelinKeys relinks)
{
    Ciphertext result;
    result = AND(a, NOT(b, evaluator, relinks), evaluator, relinks);
    return result;
}
/**
 * @brief  Checks a<b condition
 * @note   
 * @param  a: 
 * @param  b: 
 * @param  *evaluator: 
 * @param  relinks: Keys for relinearization
 * @retval 
 */
Ciphertext lt(Ciphertext a, Ciphertext b, Evaluator *evaluator, RelinKeys relinks)
{
    Ciphertext result;
    result = AND(NOT(a, evaluator, relinks), b, evaluator, relinks);
    return result;
}

/**
 * @brief  Implementes equality condition through a XNOR
 * @note   
 * @param  gt: 
 * @param  lt: 
 * @param  *evaluator: 
 * @param  relinks: 
 * @retval 
 */
Ciphertext XNOR(Ciphertext gt, Ciphertext lt, Evaluator *evaluator, RelinKeys relinks)
{
    Ciphertext result;
    result = AND(NOT(gt, evaluator, relinks), NOT(lt, evaluator, relinks), evaluator, relinks);
    return result;
}
/**
 * @brief  Implements OR gate
 * @note   
 * @param  a: 
 * @param  b: 
 * @param  *evaluator: 
 * @param  relinks: Keys for relinearization
 * @retval 
 */
Ciphertext OR(Ciphertext a, Ciphertext b, Evaluator *evaluator, RelinKeys relinks)
{
    Ciphertext result;
    result = NAND(NOT(a, evaluator, relinks), NOT(b, evaluator, relinks), evaluator, relinks);
    return result;
}

/**
 * @brief  Makes first comparison which doesn't need previous output
 * @note   
 * @param  A: 
 * @param  B: 
 * @param  *evaluator: 
 * @param  relinks: 
 * @retval 
 */
vector<Ciphertext> init_bit_comparator(Ciphertext A, Ciphertext B, Evaluator *evaluator, RelinKeys relinks)
{
    vector<Ciphertext> result;
    Ciphertext AgtB = gt(A, B, evaluator, relinks);
    Ciphertext AltB = lt(A, B, evaluator, relinks);
    result.push_back(AgtB);
    result.push_back(XNOR(AgtB, AltB, evaluator, relinks));
    result.push_back(AltB);
    return result;
}

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
vector<Ciphertext> bit_comparator(Ciphertext A, Ciphertext B, Evaluator *evaluator, vector<Ciphertext> prev, RelinKeys relinks)
{
    vector<Ciphertext> curr, result;
    Ciphertext nAgtB, nAeqB, nAltB;
    // get comparison results between the 2 bits
    curr = init_bit_comparator(A, B, evaluator, relinks);
    // Fix them to the previuos comparison value if the A<B or A>B was already verified
    nAgtB = AND(OR(curr[0], prev[0], evaluator, relinks), NOT(prev[2], evaluator, relinks), evaluator, relinks);
    nAeqB = AND(curr[1], prev[1], evaluator, relinks);
    nAltB = AND(OR(curr[2], prev[2], evaluator, relinks), NOT(prev[0], evaluator, relinks), evaluator, relinks);
    result.push_back(nAgtB);
    result.push_back(nAeqB);
    result.push_back(nAltB);
    return result;
}

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
vector<Ciphertext> full_homomorphic_comparator(vector<Ciphertext> x, vector<Ciphertext> y, Evaluator *evaluator, RelinKeys relinks)
{
    vector<Ciphertext> curr;

    if (x.size() != y.size())
    {
        cout << "Invalid comparison not the same size (Should have beeen caugth in loading phase)";
        exit(1);
    }
    int sz = x.size();

    curr = init_bit_comparator(x[0], y[0], evaluator, relinks);

    for (int i = 1; i < sz; i++)
    {
        curr = bit_comparator(x[i], y[i], evaluator, curr, relinks);
    }
    return curr;
}
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
vector<Ciphertext> full_homomorphic_comparator_debug_version(vector<Ciphertext> x, vector<Ciphertext> y, Evaluator *evaluator, RelinKeys relinks, Decryptor *decryptor)
{
    vector<Ciphertext> curr, not_relin;
    Ciphertext rel;
    Plaintext r;

    if (x.size() != y.size())
    {
        cout << "Invalid comparison not the same size (Should have beeen caugth in loading phase)";
        exit(1);
    }
    int sz = x.size();

    curr = init_bit_comparator(x[0], y[0], evaluator, relinks);

    for (int i = 1; i < sz; i++)
    {
        curr = bit_comparator(x[i], y[i], evaluator, curr, relinks);

        cout << "Noise budget in bits : ";
        for (int k = 0; k < curr.size(); k++)
        {
            (*decryptor).decrypt(curr[k], r);
            cout << (*decryptor).invariant_noise_budget(curr[k]) << " || ";
        }
        cout << endl;
        cout << "Result ";
        for (int k = 0; k < curr.size(); k++)
        {
            (*decryptor).decrypt(curr[k], r);
            cout << r.to_string();
        }
        cout << endl;
        cout << "bit" << to_string(i) << endl;
    }
    return curr;
}
