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
#include <string.h>
#include "seal/seal.h"

using namespace std;
using namespace seal;
/**
 * @brief  Saves homormophic encrypted
 * @note
 * @param  x:
 * @param  dir:
 * @param  filename:
 * @retval None
 */
void save_hom_enc(Ciphertext x, char *dir, char *filename)
{
    fstream fb;
    char stringex[50] = "";
    sprintf(stringex, "%s/%s", dir, filename);
    fb.open(stringex, fstream::binary | fstream::out);
    x.save(fb);
    fb.close();
}

Ciphertext load_hom_enc(char *dir, char *filename, SEALContext context)
{

    fstream fb;
    Ciphertext x;
    char stringex[50] = "";
    sprintf(stringex, "%s/%s", dir, filename);
    fb.open(stringex, fstream::binary | fstream::in);
    x.load(context, fb);
    fb.close();
    //cout << "Bit sucessfully decrypted";
    return x;
}
/**
 * @brief  Create SEALContext
 * @note
 * @retval
 */
SEALContext create_context(int p_m_degree, int p_mod)
{
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = p_m_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(p_mod);
    SEALContext context(parms);
    return context;
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
    cout << "[";
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
 * @brief  Takes a n into and converts it into an hexadecimal string
 * @note
 * @param  x:
 * @retval
 */
string d2h(int x)
{
    stringstream stream;
    stream << hex << x;
    string result(stream.str());
    cout << to_string(x) << " ---->" << result << endl;
    return result;
}

/**
 * @brief  Takes a hex string and converts it into an decimal string
 * @note
 * @param  x:
 * @retval
 */
int h2d(string x)
{
    stringstream stream;
    string aux;
    stream << "0x"<< x;
    stream >> hex >> aux;
    long int result = strtol (aux.c_str(),NULL,0);
    cout << x << " ----> " << to_string(result) << endl;
    return result;
}

/**
 * @brief  Converts decimal number into binary
 * @note
 * @param  n: Number to be converted
 * @retval
 */
vector<int> d2b(int n, int n_bit)
{
    vector<int> result;
    if (n >= (int)pow(2,n_bit))
    {
        cout << "Number must be smaller than number of bits";
        exit(1);
    }
    int digit;
    int i = n_bit;
    while (i > 0)
    {
        digit = n % 2;
        n = n / 2;
        result.insert(result.begin(), digit);
        i--;
    }
    cout << "Sucessefully converted to bynary" << endl;
    return result;
}
/**
 * @brief  Takes an int and encrypts it in two ways, as a hexadecimal string and as a binary number. It also saves them into files
 * @note
 * @param  x: Number to be encrypted
 * @param  *encryptor:
 * @param  *directory: Name of directory where we are going to save the numbers
 * @retval None
 */
void enc_int_total(int x, Encryptor *encryptor, char *directory, int n_bit)
{
    // Ciphertexts which will store both ypes of encryption
    Ciphertext x_hex_enc;
    vector<Ciphertext> x_bin_enc;

    // Preprocessing x to be encrypted through SEAL
    Plaintext x_hex(d2h(x));
    vector<int> x_bin = d2b(x,n_bit);

    // Encrypting Data
    (*encryptor).encrypt(x_hex, x_hex_enc);
    x_bin_enc = enc_binary(x_bin, encryptor);

    char systemcall[500];
    char filename[50];
    char bin_dir[50];

    sprintf(systemcall, "mkdir %s", directory);
    system(systemcall);
    sprintf(systemcall, "cd %s && mkdir bin", directory);
    system(systemcall);

    sprintf(bin_dir, "%s/bin", directory);
    sprintf(filename, "%s.hex", directory);

    save_hom_enc(x_hex_enc, directory, filename);

    // bits in folder will be ordered by most to least significative
    for (int i = 0; i < x_bin_enc.size(); i++)
    {

        sprintf(filename, "%s.bin", to_string(i).c_str());
        save_hom_enc(x_bin_enc[i], bin_dir, filename);
    }
}

/**
 * @brief  Decrypts number into a Ciphertext (in hexadecimal) and a vector of Ciphertexts(binary)
 * @note   
 * @param  *hex: 
 * @param  *bin: 
 * @param  *decryptor: 
 * @param  *directory: 
 * @param  context: 
 * @retval None
 */
void dec_int_total(Ciphertext* x_hex, vector<Ciphertext>* bin, Decryptor* decryptor, char* directory, SEALContext context)
{
    char systemcall[500];
    char filename[50];
    char bin_dir[50];
    Ciphertext aux;

    sprintf(filename, "%s.hex", directory);
    (*x_hex) = load_hom_enc(directory, filename, context);

    cout << "hex sucessfully decrypted" << endl;

    DIR *folder;

    struct dirent *entry;

    sprintf(bin_dir, "./%s/bin", directory);
    folder = opendir(bin_dir);

    if (folder == NULL)
    {
        perror("Unable to read directory");
        exit(1);
    }

    while ((entry = readdir(folder)))
    {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
        {
            // do nothing (straight logic)
        }
        else
        {
            cout << "File" << entry->d_name << endl;
            aux = load_hom_enc(bin_dir, entry->d_name, context);
            (*bin).push_back(aux);
        }
    }

    closedir(folder);
}