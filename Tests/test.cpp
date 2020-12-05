
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
vector<int> d2b(int n)
{
    vector<int> result;
    int digit;
    while (n > 0)
    {
        digit = n % 2;
        n = n / 2;
        result.insert(result.begin(), digit);
    }
    return result;
}

/**
 * @brief  Encrypts binary vector
 * @note
 * @param  n:
 * @param  *encryptor:
 * @retval
 */
vector<Ciphertext> enc_binary(vector<int> n, Encryptor *encryptor)
{
    Plaintext b;
    Ciphertext enc;
    vector<Ciphertext> result;
    for (int i = 0; i < n.size(); i++)
    {
        b = to_string(n[i]);
        (*encryptor).encrypt(b, enc);
        result.push_back(enc);
    }
    return result;
}

/**
 * @brief  Decrypts and prints ciphertext vector
 * @note
 * @param  n:
 * @param  *decryptor:
 * @retval None
 */
void dec_prt_vec(vector<Ciphertext> n, Decryptor *decryptor)
{
    Plaintext result;
    cout <<"[";
    for (int i = 0; i < n.size(); i++)
    {
        (*decryptor).decrypt(n[i], result);
        cout << result.to_string();
    }
    cout << "]" << endl;
}
/**
 * @brief  Prints int vector
 * @note
 * @param  x:
 * @retval None
 */
void print_vec(vector<int> x)
{
    cout << "[";
    for (int i = 0; i < x.size(); i++)
    {
        cout << x[i];
    }
    cout << "]" << endl;
}

/**
 * @brief  Implements NOT gate
 * @note
 * @param  a:
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
 * @param  a:
 * @param  b:
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

int main(int argc, char *argv[])
{

    EncryptionParameters parms(scheme_type::bfv);
    //16384
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(512);
    SEALContext context(parms);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    SecretKey secret_key = keygen.secret_key();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    int x = 18;
    int y = 20;

    Plaintext x_plain(to_string(x)), y_plain(to_string(y)), one_plain("1"), zero_plain("0"), result;
    cout << x_plain.to_string() << " ...... Correct." << endl;
    cout << y_plain.to_string() << " ...... Correct." << endl;

    vector<int> x_v = d2b(x);
    vector<int> y_v = d2b(y);
    vector<Ciphertext> x_v_enc, not_x_v_enc;
    vector<Ciphertext> y_v_enc, not_y_v_enc;
    vector<Ciphertext> aux;
    vector<Ciphertext> output;

    cout << "x =";
    print_vec(x_v);

    cout << "y =";
    print_vec(y_v);

    x_v_enc = enc_binary(x_v, &encryptor);

    y_v_enc = enc_binary(y_v, &encryptor);

    cout << "x = ";
    dec_prt_vec(x_v_enc, &decryptor);

    cout << "y = ";
    dec_prt_vec(y_v_enc, &decryptor);

    output = full_homomorphic_comparator_debug_version(x_v_enc, y_v_enc, &evaluator, relin_keys, &decryptor);

    cout << "gt XNOR lt" << endl;
    for (int k = 0; k < output.size(); k++)
    {
        decryptor.decrypt(output[k], result);
        cout << result.to_string();
    }
    cout << endl;

    /*
    for (int i = 0; i < x_v_enc.size(); i++)
    {
        not_x_v_enc.push_back(NOT(x_v_enc[i], context));
    }
    vector<int> x_v = d2b(x);
    Ciphertext x_v_enc[x_v.size()];
    Plaintext b;
    for (int i = 0; i < x_v.size(); i++)
    {
        b = to_string(x_v[i]);
        encryptor.encrypt(b, x_v_enc[i]);
    }

    Ciphertext y_v_enc[10];
    /*
    decryptor.decrypt(not_encrypted, result);
    cout << "NOT(x,y) = " << result.to_string() << endl;
    decryptor.decrypt(and_encrypted, result);
    cout << "AND(x,y) = " << result.to_string() << endl;
    decryptor.decrypt(xnor_encrypted, result);
    cout << "XNOR(x,y) = " << result.to_string() << endl;
    decryptor.decrypt(lt_encrypted, result);
    cout << "lt(x,y) = " << result.to_string() << endl;
    decryptor.decrypt(gt_encrypted, result);
    cout << "gt(x,y) = " << result.to_string() << endl;
    decryptor.decrypt(nand_encrypted, result);
    cout << "NAND(x,y) = " << result.to_string() << endl;
    */
    /*
    BatchEncoder batch_encoder(context);

    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    int n = x;
    int k = y;
    int digit1 = 0, digit2 = 0;
    vector<uint64_t> pod_matrix1;
    vector<uint64_t> pod_matrix2;
    vector<uint64_t> pod_result;

    cout << "[";


    Plaintext plain_matrix1, plain_matrix2, plain_result;
    Ciphertext encrypted_matrix1, encrypted_matrix2, encrypted_matrix3;
    print_matrix(pod_matrix1, row_size);
    print_matrix(pod_matrix2, row_size);
    batch_encoder.encode(pod_matrix1, plain_matrix1);
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    encryptor.encrypt(plain_matrix1, encrypted_matrix1);
    encryptor.encrypt(plain_matrix2, encrypted_matrix2);
    //encrypted_matrix3 = AND(encrypted_matrix1, encrypted_matrix2);
    //evaluator.sub(encrypted_matrix1, encrypted_matrix2, encrypted_matrix3);
    Ciphertext v = encrypted_matrix3[0];
    decryptor.decrypt(v, plain_result);
    //batch_encoder.decode(plain_result, pod_result);
    //cout << "Result = " << plain_result.to_string() << endl;
    //print_matrix(pod_result, row_size);
    Plaintext x_plain(to_string(x)), y_plain(to_string(y));
    Ciphertext x_encrypted, y_encrypted, result_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);
    encryptor.encrypt(y_plain, y_encrypted);
    evaluator.add(x_encrypted, y_encrypted, result_encrypted);
    Plaintext result;
    decryptor.decrypt(result_encrypted, result);
    cout << "0x" << result.to_string() << " ...... Correct." << endl;
    fstream fb;
    char stringex[50];
    sprintf(stringex, "result.txt");
    fb.open(stringex, fstream::binary | fstream::out);
    result_encrypted.save(fb);
    fb.close();

    sprintf(stringex, "x.txt");
    fb.open(stringex, fstream::binary | fstream::out);
    x_encrypted.save(fb);
    fb.close();

    sprintf(stringex, "y.txt");
    fb.open(stringex, fstream::binary | fstream::out);
    y_encrypted.save(fb);
    fb.close();

    sprintf(stringex, "y.txt");
    fb.open(stringex, fstream::binary | fstream::out);
    y_encrypted.save(fb);
    fb.close();

    sprintf(stringex, "pod.txt");
    fb.open(stringex, fstream::binary | fstream::out);
    encrypted_matrix3.save(fb);
    fb.close();

    Ciphertext x_encrypted, y_encrypted, xnor_encrypted, result_encrypted, y_neg, and_encrypted, not_encrypted, gt_encrypted, lt_encrypted, nand_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);
    encryptor.encrypt(y_plain, y_encrypted);
    not_encrypted = NOT(x_encrypted, context);
    and_encrypted = AND(x_encrypted, y_encrypted, context);
    gt_encrypted = gt(x_encrypted, y_encrypted, context);
    lt_encrypted = lt(x_encrypted, y_encrypted, context);
    xnor_encrypted = XNOR(gt_encrypted, lt_encrypted, context);
    nand_encrypted = NAND(x_encrypted, y_encrypted, context);


    int size = x_v_enc.size();
    cout << "gt XNOR lt" << endl;
    for (int i = 0; i < size; i++)
    {
        output = bit_comparator(x_v_enc[i], y_v_enc[i], context, aux);
        for (int k = 0; k < output.size(); k++)
        {
            decryptor.decrypt(output[k], result);
            cout << result.to_string();
        }
        cout << endl;
    }
    */
}