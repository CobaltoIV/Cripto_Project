
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
#include <dirent.h>
#include <CompFunc/CompFunc.h>
#include <HelpFunc/HelpFunc.h>
#include <seal/seal.h>

using namespace std;
using namespace seal;

/**
 * @brief  It takes a column and a encrypted number and compares every entry of the column against it. The comparison saved is defined by the mode
 * @note   Function is supposed to be called in SELECT ... Where queries
 * @param  *columndir: Path to column folder
 * @param  *intdir: Path to number to be compared to
 * @param  context: 
 * @param  evaluator: 
 * @param  relinks: 
 * @param  mode: Type of comparison: 0 -> a>b || 1-> a=b || 2 -> a<b
 * @retval None
 */
void comparecolumn(char *columndir, char *intdir, SEALContext context, Evaluator* evaluator, RelinKeys relinks, int mode)
{
    DIR *folder;
    stringstream ss;
    string fullpath, aux, auxdir,auxfile, auxdir_hex;
    char *dirpath, *resultfile, *resultdir, *enc_dir, *hexdir;
    char systemcall[500];
    struct dirent *entry;

    Ciphertext x_hex, i_hex;
    vector<Ciphertext> x_bin, i_bin, comp_res;

    // Load number that was inserted by user in WHERE
    dec_int_total(&i_hex, &i_bin, intdir, context);

    // open column directory to iterate through entries
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
            // Get fullpath for number in entry
            ss << columndir << "/" << entry->d_name;
            fullpath = ss.str();
            dirpath = &fullpath[0];
            // load entry encryptons into x_hex and x_bin variables
            dec_int_total(&x_hex, &x_bin, dirpath, context);
            // Compare entry to number inserted by user in where
            comp_res = full_homomorphic_comparator(x_bin, i_bin, evaluator, relinks);
            ss.str(string());

            // Save result in folder to be sent to user

            // Get path to .hex of corresponding number
            ss << columndir << "/" << entry->d_name << "/" << entry->d_name << ".hex";
            aux = ss.str();
            enc_dir = &aux[0];

            ss.str(string()); // clean stream for next operation
            
            // Get directory in Result folder of corresponding number
            ss << "Server/Result/" << entry->d_name;
            auxdir_hex = ss.str();
            hexdir = &auxdir_hex[0];
            // Create directory to save number
            sprintf(systemcall, "mkdir %s", hexdir);
            system(systemcall);
             // Copy encrypted number to Result folder in corresponding directory
            sprintf(systemcall, "cp %s %s", enc_dir, hexdir);
            system(systemcall); 

            auxdir = "Server/Result";
            resultdir = &auxdir[0];
            auxfile = "comp.res";
            resultfile = &auxfile[0];
            // Copy result of the comparison to the folder with the respective number
            save_hom_enc(comp_res[mode], hexdir, resultfile);
            // clear previous comparison data
            x_bin.clear();
            fullpath.clear();
            ss.str(string());
        }
    }
    closedir(folder);
}

// TODO  Similar function to compare column but returns only the sum of the entries
int main(int argc, char *argv[])
{

    char directoryx[50] = "x";
    char directoryy[50] = "y";
    char directoryz[50] = "z";
    char systemcall[500];
    system("rm -r Server");
    system("mkdir Server");
    system("cd Server && mkdir Database");
    system("cd Server && mkdir Result");
    string t;
    t.append("Server/Database/");
    t.append("table");
    char *t_c = &t[0];
    string c;
    c.append("Server/Database/table/");
    c.append("col");
    char *col = &c[0];
    if (!createdir(t_c))
    {
        cout << "Table " << t_c << " already exists" << endl;
    }
    if (!createdir(col))
    {
        cout << "Table " << col << " already exists" << endl;
    }

    SEALContext context = create_context(8192, 128);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    SecretKey secret_key = keygen.secret_key();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    int x = 13;
    int y = 12;
    int z = 13;
    int mode = 0;

    int n_bit = 4;
    int y_res;
    Plaintext result;

    vector<Ciphertext> x_v_enc, y_v_enc, z_v_enc, output;
    Ciphertext x_hex, y_hex, z_hex, res;

    enc_int_total(x, &encryptor, directoryx, n_bit);

    enc_int_total(y, &encryptor, directoryy, n_bit);

    enc_int_total(z, &encryptor, directoryz, n_bit);

    system("mv x Server/Database/table/col");
    system("mv y Server/Database/table/col");

    comparecolumn(col, directoryz, context, &evaluator, relin_keys, mode);

    /*
    SEALContext context = create_context(8192, 128);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    SecretKey secret_key = keygen.secret_key();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    sprintf(systemcall,"rm -r %s", directoryx);
    system(systemcall);
    sprintf(systemcall,"rm -r %s", directoryy);
    system(systemcall);
    int x = 13;
    int y = 12;
    int n_bit = 4;
    int y_res;
    Plaintext result;

    vector<Ciphertext> x_v_enc, y_v_enc, output;
    Ciphertext x_hex, y_hex, res;

    enc_int_total(x, &encryptor, directoryx, n_bit);

    enc_int_total(y, &encryptor, directoryy, n_bit);

    dec_int_total(&x_hex, &x_v_enc,&decryptor, directoryx, context);

    dec_int_total(&y_hex, &y_v_enc,&decryptor, directoryy, context);

    decryptor.decrypt(x_hex, result);
    cout << "x = "<< result.to_string() << endl;
    cout << "x = ";
    dec_prt_vec(x_v_enc, &decryptor);

    decryptor.decrypt(y_hex, result);
    cout << "x = "<< result.to_string() << endl;
    cout << "x = ";
    dec_prt_vec(y_v_enc, &decryptor);
    y_res = h2d(result.to_string());

    //output = full_homomorphic_comparator_debug_version(x_v_enc, y_v_enc, &evaluator, relin_keys, &decryptor);

    //evaluator.multiply(x_hex, output[0], res);
    //decryptor.decrypt(res, result);
    //cout << "Result = "<< result.to_string() << endl;
    cout << "x = ";
    dec_prt_vec(y_v_enc, &decryptor);
    y_res = h2d(result.to_string());
    */
    /*
    d2h(x);
    d2h(y);
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
    */
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