
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

vector<int> d2b(int n)
{
    vector<int> result;
    int digit;
    while (n > 0)
    {
        digit = n % 2;
        n = n / 2;
        result.push_back(digit);
    }
    return result;
}
Ciphertext NOT(Ciphertext a, SEALContext context)
{
    Ciphertext a_neg, result;
    Plaintext plain_one("1");
    Evaluator evaluator(context);
    evaluator.negate(a, a_neg);
    evaluator.add_plain(a_neg, plain_one, result);
    return result;
}
Ciphertext AND(Ciphertext a, Ciphertext b, SEALContext context)
{
    Ciphertext result;
    Evaluator evaluator(context);
    evaluator.multiply(a, b, result);
    return result;
}
Ciphertext NAND(Ciphertext a, Ciphertext b, SEALContext context)
{
    Ciphertext result;
    return result = NOT(AND(a, b, context), context);
}
Ciphertext gt(Ciphertext a, Ciphertext b, SEALContext context)
{
    Ciphertext result;
    result = AND(a, NOT(b, context), context);
    return result;
}
Ciphertext lt(Ciphertext a, Ciphertext b, SEALContext context)
{
    Ciphertext result;
    result = AND(NOT(a, context), b, context);
    return result;
}
Ciphertext XNOR(Ciphertext gt, Ciphertext lt, SEALContext context)
{
    Ciphertext result;
    result = AND(NOT(gt, context), NOT(lt, context), context);
    return result;
}
int main(int argc, char *argv[])
{
    /*
    string command;
    cout<<"Type something:";

    getline(cin, command);

    cout<<"Your command:"<<command<<"\n";
    */
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    SEALContext context(parms);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    int x = 18;
    int y = 9;

    Plaintext x_plain(to_string(x)), y_plain(to_string(y)), one_plain("1"), result;
    cout << x_plain.to_string() << " ...... Correct." << endl;
    cout << y_plain.to_string() << " ...... Correct." << endl;

    /*
    Ciphertext x_encrypted, y_encrypted, xnor_encrypted, result_encrypted, y_neg, and_encrypted, not_encrypted, gt_encrypted, lt_encrypted, nand_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);
    encryptor.encrypt(y_plain, y_encrypted);
    not_encrypted = NOT(x_encrypted, context);
    and_encrypted = AND(x_encrypted, y_encrypted, context);
    gt_encrypted = gt(x_encrypted, y_encrypted, context);
    lt_encrypted = lt(x_encrypted, y_encrypted, context);
    xnor_encrypted = XNOR(gt_encrypted, lt_encrypted, context);
    nand_encrypted = NAND(x_encrypted, y_encrypted, context);
    */

    vector<int> x_v = d2b(x);
    vector<Ciphertext> x_v_enc, not_x_v_enc;
    Ciphertext enc;
    Plaintext b;
    cout <<"[";
    for(int i =0; i < x_v.size(); i++)
    {
        cout << x_v[i] ;
    }
    cout<<"]"<< endl;

    for (int i = 0; i < x_v.size(); i++)
    {
        b = to_string(x_v[i]);
        encryptor.encrypt(b, enc);
        x_v_enc.push_back(enc);
    }

    for (int i = 0; i < x_v_enc.size(); i++)
    {
        not_x_v_enc.push_back(NOT(x_v_enc[i], context));
    }

    cout << "[";
    for (int i = 0; i < x_v_enc.size(); i++)
    {
        decryptor.decrypt(not_x_v_enc[i], result);
        cout << result.to_string();
    }
    cout << "]" << endl;
    /*
    

    vector<int> x_v = d2b(x);
    Ciphertext x_v_enc[x_v.size()];
    Plaintext b;
    for (int i = 0; i < x_v.size(); i++)
    {   
        b = to_string(x_v[i]);
        encryptor.encrypt(b, x_v_enc[i]);
    }
    */

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
    */
}