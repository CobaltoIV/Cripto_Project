
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


void create_exec(string query, size_t pos)
{
    string col, c, token;
    string delimiter = " ";
    // get tablename
    pos = query.find(delimiter);
    token = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());
    string p = "Server/Database/";
    p.append(token);
    char *dir = &p[0];
    if (!createdir(dir))
    {
        exit(1);
    }
    //find rest of the collumns
    while ((pos = query.find(delimiter)) != query.npos)
    {
        stringstream ss;
        char *coldir;
        //Get a column name from the input string
        col = query.substr(0, pos);
        //cout << col << endl;
        //Remove the current column name from the input string
        query.erase(0, pos + delimiter.length());
        ss << p << "/" << col;
        c = ss.str();
        coldir = &c[0];
        createdir(coldir);
        ss.str(string());
    }

    ofstream fb;
    fb.open("Server/Result/res.txt");
    fb << "CREATE Sucessfull";
    fb.close();
}

void insert_exec(string query, size_t pos, string queriespath)
{
    string allcolls, c, col, table, value, v, valuename;
    vector<string> cols;
    vector<string> values;
    string delimiter = " ";
    string coldelimiter = "VALUES ";
    stringstream ss;
    char systemcall[500];
    char *coldir, *valuedir, *linedir, *valuehex;

    // get tablename
    pos = query.find(delimiter);
    table = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());
    string p = "Server/Database/";
    p.append(table);
    char *tabledir = &p[0];
    if (!chkdir(tabledir))
    {
        cout << "Table doesn't exist";
        exit(1);
    }

    pos = query.find(coldelimiter);
    allcolls = query.substr(0, pos);
    query.erase(0, pos + coldelimiter.length());

    //cout << allcolls << endl;
    //cout << query << endl;
    //get the values into a vector
    while ((pos = query.find(delimiter)) != query.npos)
    {
        //Get a value name from the input string
        value = query.substr(0, pos);
        //Remove the current value name from the input string
        query.erase(0, pos + delimiter.length());
        ss << queriespath << "/" << value;
        v = ss.str();
        values.push_back(v);
        ss.str(string());
    }
    // get the collumns into a vector
    while ((pos = allcolls.find(delimiter)) != allcolls.npos)
    {
        //Get a column name from the input string
        col = allcolls.substr(0, pos);
        //cout << value << endl;
        //Remove the current column name from the input string
        allcolls.erase(0, pos + delimiter.length());
        ss << "Server/Database/" << table << "/" << col;
        c = ss.str();
        //cout << c << endl;
        cols.push_back(c);
        ss.str(string());
    }
    // Doesn't matter which collumn they all have the same number of lines
    col = cols[0];
    coldir = &col[0];
    string line_number = getlinenumber(coldir);
    linedir = &line_number[0];
    for (int i = 0; i < cols.size(); i++) // move numbers to respective collumns with the rigth line number
    {
        // Get directories for collumns and values
        col = cols[i];
        coldir = &col[0];
        value = values[i];
        valuedir = &value[0];
        // create directory to copy value to collumn using the number of line
        sprintf(systemcall, "mkdir %s/%s", coldir, linedir);
        system(systemcall);

        //std::cout << "Splitting: " << value << endl;
        unsigned found = value.find_last_of("/\\");
        //std::cout << " path: " << value.substr(0, found) << endl;
        //std::cout << " file: " << value.substr(found + 1) << endl;
        // get name of the .hex encryption so we can alter it to the number of the line
        valuename = value.substr(found + 1);
        valuehex = &valuename[0];

        // change name of .hex
        sprintf(systemcall, "mv %s/%s.hex %s/%s.hex", valuedir, valuehex, valuedir, linedir);
        system(systemcall);

        // copy number
        sprintf(systemcall, "cp -r %s/* %s/%s", valuedir, coldir, linedir);
        system(systemcall);
    }
    // Send Sucess message
    ofstream fb;
    fb.open("Server/Result/res.txt");
    fb << "INSERT Sucessfull";
    fb.close();
}

void select_exec(string query, size_t pos)
{
    string allcolls, c, col, table, value, v, valuename;
    vector<string> cols;
    string delimiter = " ";
    string coldelimiter = "FROM ";
    stringstream ss;
    char systemcall[500];
    char *coldir, *tablename, *linedir, *valuehex;

    // get all collumns
    pos = query.find(coldelimiter);
    allcolls = query.substr(0, pos);
    query.erase(0, pos + coldelimiter.length());

    // get table name
    pos = query.find(delimiter);
    table = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());
    tablename = &table[0];

    sprintf(systemcall, "mkdir Server/Result/%s", tablename);
    system(systemcall);
    // check table exists
    string p = "Server/Database/";
    p.append(table);
    char *tabledir = &p[0];
    if (!chkdir(tabledir))
    {
        cout << "Table doesn't exist";
        exit(1);
    }

    while ((pos = allcolls.find(delimiter)) != allcolls.npos)
    {
        //Get a column name from the input string
        col = allcolls.substr(0, pos);
        //Remove the current column name from the input string
        allcolls.erase(0, pos + delimiter.length());
        // Get directory of collum
        ss << p << "/" << col;
        c = ss.str();
        char *coldir = &c[0];
        if (!chkdir(coldir))
        {
            cout << "Collumn doesn't exist";
            exit(1);
        }

        sprintf(systemcall, "cp -r %s Server/Result/%s ",coldir, tablename);
        system(systemcall);

        ss.str(string());

    }
}
void query_exec(string query, string queriespath)
{
    string delimiter = " ";
    string token;
    size_t pos = query.find(delimiter);
    token = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());

    //cout << query << endl;

    if (token.compare("CREATE") == 0)
    {
        create_exec(query, pos);
    }
    else if (token.compare("INSERT") == 0)
    {
        insert_exec(query, pos, queriespath);
    }
    else if (token.compare("SELECT") == 0)
    {
        select_exec(query, pos);
    }
}

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
void comparecolumn(char *columndir, char *intdir, SEALContext context, Evaluator *evaluator, RelinKeys relinks, int mode)
{
    DIR *folder;
    stringstream ss;
    string fullpath, aux, auxdir, auxfile, auxdir_hex;
    char *dirpath, *resultfile, *resultdir, *enc_dir, *hexdir;
    char systemcall[500];
    struct dirent *entry;
    Ciphertext x_hex, i_hex;
    vector<Ciphertext> x_bin, i_bin, comp_res;
    string coldir = columndir;

    // Create directory in Result with name of collumn
    // Get name of column
    std::cout << "Splitting: " << coldir << endl;
    unsigned found = coldir.find_last_of("/\\");
    std::cout << " path: " << coldir.substr(0, found) << endl;
    std::cout << " file: " << coldir.substr(found + 1) << endl;
    string colname = coldir.substr(found + 1);

    // Get directory path
    ss << "Server/Result/" << colname;
    string rescol = ss.str();
    cout << rescol << endl;
    char *rescoldir = &rescol[0];
    // Create directory
    cout << rescoldir << endl;
    createdir(rescoldir);
    ss.str(string());
    // Load number that was inserted by user in WHERE
    dec_int_total(&i_hex, &i_bin, intdir, context);

    //createdir()
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
            ss << rescol << "/" << entry->d_name;
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
            ss.str(string());
            ss << entry->d_name << ".res";
            auxfile = ss.str();
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

/**
 * @brief  It takes a column and sums every entry.
 * @note   Function is supposed to be called in SELECT SUM queries without where
 * @param  *columndir: Path to column folder
 * @param  *intdir: Path to number to be compared to
 * @param  context: 
 * @param  evaluator: 
 * @param  relinks: 
 * @retval None
 */
void sumcolumn(char *columndir, SEALContext context, Evaluator *evaluator, RelinKeys relinks)
{
    DIR *folder;
    stringstream ss;
    string fullpath, aux, auxdir, auxfile, auxdir_hex;
    char *dirpath, *resultfile, *resultdir, *enc_dir, *hexdir, *dir;
    char systemcall[500];
    struct dirent *entry;

    Ciphertext x_hex, sum_total;
    vector<Ciphertext> x_bin;
    bool first = true;
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
            cout << dirpath << endl;
            // load entry encryptons into x_hex and x_bin variables
            dec_int_total(&x_hex, &x_bin, dirpath, context);
            if (first)
            {
                // for first entry just insert this
                sum_total = x_hex;
                first = false;
            }
            else
            {
                //add the entry to the result
                (*evaluator).add_inplace(sum_total, x_hex);
            }
            //Clear contents of previous
            x_bin.clear();
            fullpath.clear();
            ss.str(string());
        }
    }
    closedir(folder);
    auxdir = "Server/Result";
    resultdir = &auxdir[0];
    auxfile = "sum.res";
    resultfile = &auxfile[0];
    // Copy result of the comparison to the folder with the respective number
    save_hom_enc(sum_total, resultdir, resultfile);
}

//TODO Function similar to sumcolumn but that it also checks a condition
int main(int argc, char *argv[])
{
    char directoryx[50] = "x";
    char directoryy[50] = "y";
    char directoryz[50] = "z";
    char directoryk[50] = "k";
    const char *filepath = "Server/Queries/Client1Query/msg.txt";
    string qpath = "Server/Queries/Client1Query";
    int i = 1;
    int x = 10;
    int y = 5;
    int z = 14;
    int k = 8;
    int n_bit = 4;
    char systemcall[500];
    size_t pos;
    Ciphertext x_hex, y_hex, z_hex, res, x_r,y_r;
    Plaintext result;
    system("rm -r Server");
    system("mkdir Server");
    system("cd Server && mkdir Database");
    system("cd Server && mkdir Result");
    system("cd Server && mkdir Queries");
    system("cd Server/Queries && mkdir Client1Query");

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

    enc_int_total(x, &encryptor, directoryx, n_bit);

    enc_int_total(y, &encryptor, directoryy, n_bit);

    enc_int_total(z, &encryptor, directoryz, n_bit);

    enc_int_total(k, &encryptor, directoryk, n_bit);

    system("mv x Server/Queries/Client1Query");
    system("mv y Server/Queries/Client1Query");
    system("mv z Server/Queries/Client1Query");
    system("mv k Server/Queries/Client1Query");

    string sql = "CREATE table col1 col2 ";
    fstream fb;
    fb.open(filepath, fstream::out);
    fb << sql;
    fb.close();

    string query;
    fb.open(filepath, fstream::in);
    while (fb)
    {
        getline(fb, query);
        cout << query << endl;
    }
    fb.close();

    query_exec(query, qpath);

    sql = "INSERT table col1 col2 VALUES x y ";
    fb.open(filepath, fstream::out);
    fb << sql;
    fb.close();

    fb.open(filepath, fstream::in);
    while (fb)
    {
        getline(fb, query);
        cout << query << endl;
    }
    fb.close();

    query_exec(query, qpath);

    sql = "INSERT table col1 col2 VALUES z k ";
    fb.open(filepath, fstream::out);
    fb << sql;
    fb.close();

    fb.open(filepath, fstream::in);
    while (fb)
    {
        getline(fb, query);
        cout << query << endl;
    }
    fb.close();

    query_exec(query, qpath);

    sql = "SELECT col1 col2 FROM table ";
    fb.open(filepath, fstream::out);
    fb << sql;
    fb.close();

    fb.open(filepath, fstream::in);
    while (fb)
    {
        getline(fb, query);
        cout << query << endl;
    }
    fb.close();

    query_exec(query, qpath);

    /*
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
    int i = 7;
    int k = 3
    int mode = 0;

    int n_bit = 4;
    int y_res;
    Plaintext result;

    vector<Ciphertext> x_v_enc, y_v_enc, z_v_enc, output;
    Ciphertext x_hex, y_hex, z_hex, res, x_r,y_r;

    enc_int_total(x, &encryptor, directoryx, n_bit);

    enc_int_total(y, &encryptor, directoryy, n_bit);

    enc_int_total(z, &encryptor, directoryz, n_bit);

    system("mv x Server/Database/table/col");
    system("mv y Server/Database/table/col");
    //system("mv z Server/Database/table/col");

    comparecolumn(col, directoryz, context, &evaluator ,relin_keys, mode);
    */

    /*
    sumcolumn(col, context, &evaluator, relin_keys);
    string d = "Server/Result";
    char* dir = &d[0];
    string file = "sum.res";
    char* filename = &file[0];
    res = load_hom_enc(dir, filename, context);
    decryptor.decrypt(res, result);
    cout << "x+y+z = "<< h2d(result.to_string()) << endl;
    */

    /*    
    Ciphertext x_encrypted, y_encrypted;
    Plaintext x_plain(to_string(x)), y_plain(to_string(y));

    encryptor.encrypt(x_plain, x_encrypted);
    encryptor.encrypt(y_plain, y_encrypted);
    cout << "encrypted" << endl;
    string x_dir = ".";
    char* dir  = &x_dir[0];
    string filename = "lol.enc";
    char* file = &filename[0];
    save_hom_enc(x_encrypted, dir , file);
    save_hom_enc(y_encrypted, dir , file);
    cout << "saved" << endl;
    cout << "saved" << endl;
    char stringex[50] = "";
    sprintf(stringex, "%s/%s", dir, file);
    cout << stringex << endl;
    fstream fb;
    cout << stringex << endl;
    fb.open(file, fstream::binary | fstream::in);
    cout << stringex << endl;
    x_r.load(context, fb);
    decryptor.decrypt(x_r, result);
    cout << "x = "<< result.to_string() << endl;
    y_r.load(context, fb);
    decryptor.decrypt(y_r, result);
    cout << "y = "<< result.to_string() << endl;
    fb.close();


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