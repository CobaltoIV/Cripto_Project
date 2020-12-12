#include <cstddef>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include "seal/seal.h"

using namespace std;
using namespace seal;

void process_cond(string cond, string p, string queriespath, vector<string>* cond_cols, vector<string>* cond_nums, vector<int>* mode)
{
    size_t pos;
    stringstream ss;
    string delimiter = " ";
    string c1, col, comp, num, num_dir;

    pos = cond.find(delimiter);
    c1 = cond.substr(0, pos);
    cond.erase(0, pos + delimiter.length());

    cout << c1 << endl;
    ss << p << "/" << c1;
    col = ss.str();

    (*cond_cols).push_back(col);
    ss.str(string());

    // get type of comparison
    pos = cond.find(delimiter);
    comp = cond.substr(0, pos);
    cond.erase(0, pos + delimiter.length());

    if (comp.compare(">") == 0)
    {
        (*mode).push_back(0);
    }
    else if (comp.compare("=") == 0)
    {
        (*mode).push_back(1);
    }
    else if (comp.compare("<") == 0)
    {
        (*mode).push_back(2);
    }

    // cout << mode << endl;
    // get number to be compared
    pos = cond.find(delimiter);
    num = cond.substr(0, pos);
    cond.erase(0, pos + delimiter.length());
    cout << num << endl;

    ss << queriespath << "/" << num;
    num_dir = ss.str();
    (*cond_nums).push_back(num_dir);
}
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
    //cout << stringex << endl;
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
    stream << "0x" << x;
    stream >> hex >> aux;
    long int result = strtol(aux.c_str(), NULL, 0);
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
    if (n >= (int)pow(2, n_bit))
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
    vector<int> x_bin = d2b(x, n_bit);

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
 * @brief  Check if a directory exists
 * @note
 * @param  tablename:
 * @retval
 */
bool chkdir(char *dirpath)
{
    DIR *pzDir;
    bool ret = false;

    pzDir = opendir(dirpath);

    if (pzDir != NULL)
    {
        ret = true;
        (void)closedir(pzDir);
    }

    return ret;
}
/**
 * @brief
 * @note
 * @param  *dirpath:
 * @retval None
 */
bool createdir(char *dirpath)
{
    char systemcall[500];
    if (chkdir(dirpath)) // if directory already exists no need to create
    {
        return false;
    }
    else // create directory
    {
        sprintf(systemcall, "mkdir %s", dirpath);
        system(systemcall);
        return true;
    }
}
string getlinenumber(char *columndir)
{
    DIR *folder;
    string last_line;
    char *dirpath, *resultfile, *resultdir, *enc_dir, *hexdir;
    char systemcall[500];
    struct dirent *entry;
    int i = 0;

    folder = opendir(columndir);

    if (folder == NULL)
    {
        perror("Unable to read directory");
        exit(1);
    }
    while ((entry = readdir(folder)))
    {

        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) // ignore non important entries
        {
            // do nothing (straight logic)
        }
        else if (entry->d_type == DT_DIR) // if the entry is a folder(only folder inside directory would be the bin folder)
        {
            // open directory
            cout << entry->d_name << endl;
            i++;
            last_line = entry->d_name;
        }
    }
    if (i == 0) // table is empty
    {
        string ret = "1";
        return ret;
    }
    else
    {
        stringstream ss(last_line);
        int temp;
        ss >> temp;
        temp++;
        return to_string(temp);
    }
    closedir(folder);
}

void dec_int_total(Ciphertext *x_hex, vector<Ciphertext> *bin, char *directory, SEALContext context)
{
    char systemcall[500];
    char filename[50];
    char bin_dir[50];
    Ciphertext aux;

    DIR *folder;

    struct dirent *entry;

    folder = opendir(directory);

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
        else if (entry->d_type != DT_DIR)
        {
            (*x_hex) = load_hom_enc(directory, entry->d_name, context);
        }
    }
    closedir(folder);

    sprintf(bin_dir, "%s/bin", directory);
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
            //cout << "File " << entry->d_name << endl;
            aux = load_hom_enc(bin_dir, entry->d_name, context);
            (*bin).push_back(aux);
        }
    }
    closedir(folder);
}
