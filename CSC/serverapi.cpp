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
#include <string.h>
#include "seal/seal.h"

using namespace std;
using namespace seal;
/**
 * @brief  Creates file with wanted error message
 * @note   
 * @param  error_msg: error message
 * @retval None
 */
void handle_error(string error_msg)
{
    ofstream fb;
    fb.open("Server/Result/msg.txt");
    fb << error_msg;
    fb.close();
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

/**
 * @brief  Takes a collumn and a group of condictions. Sums the collumn according to the conditions
 * @note   Function is supposed to be called in SELECT SUM queries with where
 * @param  *columndir: Path to collumn
 * @param  cond_cols: vector with collumns in conditions
 * @param  modes: vector with types of comparisons
 * @param  cond_nums: vectot with numbers to be compared
 * @param  context: 
 * @param  *evaluator: 
 * @param  relinks: 
 * @retval None
 */
void sumcolumn_where(char *columndir, vector<string> cond_cols, vector<int> modes, vector<string> cond_nums, SEALContext context, Evaluator *evaluator, RelinKeys relinks)
{
    DIR *folder;
    stringstream ss;
    string fullpath, aux, auxdir, auxfile, auxdir_hex, col, col_line, num;
    char *dirpath, *resultfile, *resultdir, *enc_dir, *hexdir, *dir, *col_line_dir, *numdir;
    char systemcall[500];
    struct dirent *entry;

    Ciphertext x_hex, num_hex, col_hex, comp, sum_total, add;
    vector<Ciphertext> x_bin, num_bin, col_bin, output;
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
        else if (entry->d_type == DT_DIR) // if the entry is a folder(corresponds to a line)
        {
            // Run through conditions for this line
            for (int i = 0; i < cond_cols.size(); i++)
            {
                // Get line from the col
                col = cond_cols[i];
                ss << col << "/" << entry->d_name;
                col_line = ss.str();
                col_line_dir = &col_line[0];

                //cout << col_line << endl;
                //cout << col << endl;
                // Get number to be compared
                num = cond_nums[i];
                numdir = &num[0];
                // Load numbers
                dec_int_total(&num_hex, &num_bin, numdir, context);
                dec_int_total(&col_hex, &col_bin, col_line_dir, context);
                //Compare
                cout << "OUTPUT CALC" << endl;
                output = full_homomorphic_comparator(col_bin, num_bin, evaluator, relinks);

                if (i == 0)
                    comp = output[modes[i]]; // If it's the first condition just don't need to multiply
                else
                {
                    // Multiply with the result from the previous condition
                    (*evaluator).multiply_inplace(comp, output[modes[i]]);
                    (*evaluator).relinearize_inplace(comp, relinks);
                }
                // Clear for next condition
                num_bin.clear();
                col_bin.clear();
                ss.str(string());
            }

            //c out << entry->d_name << endl;

            // Get fullpath for number in entry
            ss << columndir << "/" << entry->d_name;
            fullpath = ss.str();
            dirpath = &fullpath[0];
            cout << dirpath << endl;

            // Load entry into x_hex and x_bin variables
            dec_int_total(&x_hex, &x_bin, dirpath, context);
            if (first)
            {

                // For first entry just insert it into sum
                (*evaluator).multiply(comp, x_hex, add);
                (*evaluator).relinearize_inplace(add, relinks);
                sum_total = add;
                first = false;
            }
            else
            {
                //add the entry to the previous total
                (*evaluator).multiply(comp, x_hex, add);
                (*evaluator).relinearize_inplace(add, relinks);
                (*evaluator).add_inplace(sum_total, add);
            }
            //Clear contents of previous entry
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
    // Copy result of the sum to the Result folder
    save_hom_enc(sum_total, resultdir, resultfile);
}

/**
 * @brief  Takes a group of conditrions and saves their results into the Server/Result/Comp folder per line
 * @note   Function is supposed to be called in SELECT queries with where
 * @param  cond_cols: 
 * @param  modes: 
 * @param  cond_nums: 
 * @param  context: 
 * @param  *evaluator: 
 * @param  relinks: 
 * @retval None
 */
void selectcollumn_where(vector<string> cond_cols, vector<int> modes, vector<string> cond_nums, SEALContext context, Evaluator *evaluator, RelinKeys relinks)
{
    DIR *folder;
    stringstream ss;
    string fullpath, resdir, col, col_line, num;
    char *resultfile, *resultdir, *col_line_dir, *numdir;
    char systemcall[500];
    struct dirent *entry;

    // Create filename
    string file = "comp.res";
    char *filename = &file[0];

    // Get directory to any collumn (just to iterate through lines)
    fullpath = cond_cols[0];
    char *columndir = &fullpath[0];

    Ciphertext x_hex, num_hex, col_hex, comp;
    vector<Ciphertext> x_bin, num_bin, col_bin, output;

    bool first = true;
    // Create Comp folder to save results
    system("mkdir Server/Result/Comp");
    // open any collumn to iterate through entries
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
        else if (entry->d_type == DT_DIR) // if the entry is a folder(corresponds to a line)
        {
            // Run through conditions for this line using entry
            for (int i = 0; i < cond_cols.size(); i++)
            {
                col = cond_cols[i];
                ss << col << "/" << entry->d_name;
                col_line = ss.str();
                col_line_dir = &col_line[0];
                //cout << col_line << endl;
                //cout << col << endl;

                // Get number to be compared
                num = cond_nums[i];
                numdir = &num[0];

                // Load numbers
                dec_int_total(&num_hex, &num_bin, numdir, context);
                dec_int_total(&col_hex, &col_bin, col_line_dir, context);
                // Compare
                cout << "OUTPUT CALC" << endl;
                output = full_homomorphic_comparator(col_bin, num_bin, evaluator, relinks);

                if (i == 0)
                    comp = output[modes[i]];
                else
                {
                    (*evaluator).multiply_inplace(comp, output[modes[i]]);
                    (*evaluator).relinearize_inplace(comp, relinks);
                }
                num_bin.clear();
                col_bin.clear();
                ss.str(string());
            }

            //cout << entry->d_name << endl;

            // Create folder to save line comparison
            sprintf(systemcall, "mkdir Server/Result/Comp/%s", entry->d_name);
            system(systemcall);
            ss << "Server/Result/Comp/" << entry->d_name;
            resdir = ss.str();
            resultdir = &resdir[0];
            save_hom_enc(comp, resultdir, filename);
            //Clear contents of previous line
            ss.str(string());
        }
    }
    closedir(folder);
}

/**
 * @brief  Process SELECT query string with 1 condition and execute query
 * @note   Function is supposed to be called in SELECT queries with 1 condition
 * @param  query: Query string
 * @param  queriespath: Path to folder with query's components
 * @param  context: 
 * @param  *evaluator: 
 * @param  relinks: 
 * @retval None
 */
void select_exec_where1(string query, string queriespath, SEALContext context, Evaluator *evaluator, RelinKeys relinks)
{
    string allcolls, c1, c, col, table, temp, cond, num, comp, num_dir;
    string delimiter = " ";
    string coldelimiter = "FROM ";
    string tabdelimiter = " WHERE ";
    vector<string> cols, cond_nums, cond_cols;
    vector<int> mode;
    size_t pos;
    stringstream ss;
    char systemcall[500];
    char *coldir, *tablename;

    //Get collumns
    pos = query.find(coldelimiter);
    allcolls = query.substr(0, pos);
    query.erase(0, pos + coldelimiter.length());

    //Get table name
    pos = query.find(tabdelimiter);
    table = query.substr(0, pos);
    query.erase(0, pos + tabdelimiter.length());
    tablename = &table[0];

    // Check if table exists
    string p = "Server/Database/";
    p.append(table);
    char *tabledir = &p[0];
    if (!chkdir(tabledir))
    {
        string err = "Table doesn't exist";
        handle_error(err);
        return;
    }

    // Create folder for table in Results
    sprintf(systemcall, "mkdir Server/Result/%s", tablename);
    system(systemcall);

    // Separate collumns
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
            string err = "Collumn doesn't exist";
            handle_error(err);
            return;
        }

        // Copy collumn to Result/table/col since you can't know which lines should be printed
        sprintf(systemcall, "cp -r %s Server/Result/%s ", coldir, tablename);
        system(systemcall);

        ss.str(string());
    }
    // Process conditions in where
    process_cond(query, p, queriespath, &cond_cols, &cond_nums, &mode);
    // Execute comparisons in conditions and save them to be read in the Client side
    selectcollumn_where(cond_cols, mode, cond_nums, context, evaluator, relinks);
}

/**
 * @brief  Process SELECT query string with 2 condition and execute query
 * @note   Function is supposed to be called in SELECT queries with 2 condition
 * @param  query: Query string
 * @param  queriespath: Path to folder with query's components
 * @param  context: 
 * @param  *evaluator: 
 * @param  relinks: 
 * @retval None
 */
void select_exec_where2(string query, string queriespath, SEALContext context, Evaluator *evaluator, RelinKeys relinks)
{
    string allcolls, c1, c, col, col2, c2, cond1, table, temp, cond, num, comp, num_dir, comp2, num2, num_dir2;
    string delimiter = " ";
    string coldelimiter = "FROM ";
    string tabdelimiter = " WHERE ";
    string conddelimiter = "AND ";
    vector<string> cols, cond_nums, cond_cols;
    vector<int> mode;
    size_t pos;
    stringstream ss;
    char systemcall[500];
    char *coldir, *tablename;

    // Get collumns
    pos = query.find(coldelimiter);
    allcolls = query.substr(0, pos);
    query.erase(0, pos + coldelimiter.length());

    //Get table name
    pos = query.find(tabdelimiter);
    table = query.substr(0, pos);
    query.erase(0, pos + tabdelimiter.length());
    tablename = &table[0];

    // Check if table exists
    string p = "Server/Database/";
    p.append(table);
    char *tabledir = &p[0];
    if (!chkdir(tabledir))
    {
        string err = "Table doesn't exist";
        handle_error(err);
        return;
    }

    // Create folder for table in Results
    sprintf(systemcall, "mkdir Server/Result/%s", tablename);
    system(systemcall);

    // Separate collumns
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

        sprintf(systemcall, "cp -r %s Server/Result/%s ", coldir, tablename);
        system(systemcall);

        ss.str(string());
    }
    // Separate first condition from second condition
    pos = query.find(conddelimiter);
    cond1 = query.substr(0, pos);
    query.erase(0, pos + conddelimiter.length());

    // process first condition
    process_cond(cond1, p, queriespath, &cond_cols, &cond_nums, &mode);
    // process second condition
    process_cond(query, p, queriespath, &cond_cols, &cond_nums, &mode);
    // execute and save comparisons
    selectcollumn_where(cond_cols, mode, cond_nums, context, evaluator, relinks);
}

void sumcolumn_where_debug(char *columndir, vector<string> cond_cols, vector<int> modes, vector<string> cond_nums, SEALContext context, Evaluator *evaluator, RelinKeys relinks, Decryptor *decryptor)
{
    DIR *folder;
    stringstream ss;
    string fullpath, aux, auxdir, auxfile, auxdir_hex, col, col_line, num;
    char *dirpath, *resultfile, *resultdir, *enc_dir, *hexdir, *dir, *col_line_dir, *numdir;
    char systemcall[500];
    struct dirent *entry;

    Ciphertext x_hex, num_hex, col_hex, comp, sum_total, add;
    vector<Ciphertext> x_bin, num_bin, col_bin, output;
    Plaintext res1, res2, res3;
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
        else if (entry->d_type == DT_DIR) // if the entry is a folder(corresponds to a line)
        {
            // check conditions for this line using entry
            for (int i = 0; i < cond_cols.size(); i++)
            {
                col = cond_cols[i];
                ss << col << "/" << entry->d_name;
                col_line = ss.str();

                cout << col_line << endl;

                col_line_dir = &col_line[0];
                num = cond_nums[i];
                numdir = &num[0];
                // load numbers
                dec_int_total(&num_hex, &num_bin, numdir, context);
                dec_int_total(&col_hex, &col_bin, col_line_dir, context);
                (*decryptor).decrypt(col_hex, res2);
                (*decryptor).decrypt(num_hex, res3);
                cout << "    + noise budget in encrypted_result: " << (*decryptor).invariant_noise_budget(col_hex) << " bits" << endl;
                cout << "    + noise budget in encrypted_result: " << (*decryptor).invariant_noise_budget(num_hex) << " bits" << endl;
                //compare
                output = full_homomorphic_comparator(col_bin, num_bin, evaluator, relinks);

                if (i == 0)
                {
                    comp = output[modes[i]];
                    (*decryptor).decrypt(comp, res1);
                    cout << "    + noise budget in encrypted_result: " << (*decryptor).invariant_noise_budget(comp) << " bits" << endl;
                    cout << res2.to_string() << ">" << res3.to_string() << "=" << res1.to_string() << endl;
                }
                else
                {
                    (*evaluator).multiply_inplace(comp, output[modes[i]]);
                    (*evaluator).relinearize_inplace(comp, relinks);
                }
                num_bin.clear();
                col_bin.clear();
                ss.str(string());
            }

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
                (*evaluator).multiply(comp, x_hex, add);
                (*evaluator).relinearize_inplace(add, relinks);
                sum_total = add;
                first = false;
            }
            else
            {
                //add the entry to the result
                (*evaluator).multiply(comp, x_hex, add);
                (*evaluator).relinearize_inplace(add, relinks);
                (*evaluator).add_inplace(sum_total, add);
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

/**
 * @brief  Process and execute CREATE query
 * @note   
 * @param  query: 
 * @retval None
 */
void create_exec(string query)
{
    string col, c, token;
    string delimiter = " ";
    size_t pos;
    // Get tablename
    pos = query.find(delimiter);
    token = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());
    // Get table path
    string p = "Server/Database/";
    p.append(token);
    char *dir = &p[0];
    // Create table
    if (!createdir(dir))
    {
        string err = "Cannot create table";
        handle_error(err);
        return;
    }
    //Find the collumns
    while ((pos = query.find(delimiter)) != query.npos)
    {
        stringstream ss;
        char *coldir;
        //Get a column name from the input string
        col = query.substr(0, pos);
        //Remove the current column name from the input string
        query.erase(0, pos + delimiter.length());
        // Get collumn path
        ss << p << "/" << col;
        c = ss.str();
        coldir = &c[0];
        // Create collumn directory
        createdir(coldir);
        ss.str(string());
    }
    // Save sucess message
    ofstream fb;
    fb.open("Server/Result/msg.txt");
    fb << "CREATE Sucessfull";
    fb.close();
}

/**
 * @brief  Process and execute INSERT query
 * @note   
 * @param  query: 
 * @param  queriespath: 
 * @retval None
 */
void insert_exec(string query, string queriespath)
{
    string allcolls, c, col, table, value, v, valuename;
    vector<string> cols;
    vector<string> values;
    string delimiter = " ";
    string coldelimiter = "VALUES ";
    stringstream ss;
    size_t pos;
    char systemcall[500];
    char *coldir, *valuedir, *linedir, *valuehex;

    // Get tablename
    pos = query.find(delimiter);
    table = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());
    // Get table path
    string p = "Server/Database/";
    p.append(table);
    char *tabledir = &p[0];
    if (!chkdir(tabledir))
    {
        string err = "Table doesn't exist";
        handle_error(err);
        return;
    }
    // Get all collumns
    pos = query.find(coldelimiter);
    allcolls = query.substr(0, pos);
    query.erase(0, pos + coldelimiter.length());

    //Get the values of the line into a vector
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
    // Get the collumns into a vector
    while ((pos = allcolls.find(delimiter)) != allcolls.npos)
    {
        //Get a column name from the input string
        col = allcolls.substr(0, pos);
        //Remove the current column name from the input string
        allcolls.erase(0, pos + delimiter.length());
        ss << "Server/Database/" << table << "/" << col;
        c = ss.str();
        cols.push_back(c);
        ss.str(string());
    }
    // Doesn't matter which collumn they all have the same number of lines
    col = cols[0];
    coldir = &col[0];
    // Get the name of the folder for the new line
    string line_number = getlinenumber(coldir);
    linedir = &line_number[0];
    for (int i = 0; i < cols.size(); i++) // move numbers to respective collumns with the rigth line number
    {
        // Get directories for collumns and values
        col = cols[i];
        coldir = &col[0];
        value = values[i];
        valuedir = &value[0];
        // Create directory to copy value to collumn using the number of line
        sprintf(systemcall, "mkdir %s/%s", coldir, linedir);
        system(systemcall);

        // Get name of the .hex encryption so we can alter it to the number of the line

        //std::cout << "Splitting: " << value << endl;
        unsigned found = value.find_last_of("/\\");
        //std::cout << " path: " << value.substr(0, found) << endl;
        //std::cout << " file: " << value.substr(found + 1) << endl;
        valuename = value.substr(found + 1);
        valuehex = &valuename[0];

        // change name of .hex
        sprintf(systemcall, "mv %s/%s.hex %s/%s.hex", valuedir, valuehex, valuedir, linedir);
        system(systemcall);

        // Copy number with correct value
        sprintf(systemcall, "cp -r %s/* %s/%s", valuedir, coldir, linedir);
        system(systemcall);
    }
    // Send Sucess message
    ofstream fb;
    fb.open("Server/Result/msg.txt");
    fb << "INSERT Sucessfull";
    fb.close();
}

/**
 * @brief  Process and execute SELECT query without conditions
 * @note   
 * @param  query: 
 * @retval None
 */
void select_exec(string query)
{
    string allcolls, c, col, table, value, v, valuename;
    vector<string> cols;
    string delimiter = " ";
    string coldelimiter = "FROM ";
    stringstream ss;
    size_t pos;
    char systemcall[500];
    char *coldir, *tablename, *linedir, *valuehex;

    // Get all collumns
    pos = query.find(coldelimiter);
    allcolls = query.substr(0, pos);
    query.erase(0, pos + coldelimiter.length());

    // Get table name
    pos = query.find(delimiter);
    table = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());
    tablename = &table[0];

    // Check if table exists
    string p = "Server/Database/";
    p.append(table);
    char *tabledir = &p[0];
    if (!chkdir(tabledir))
    {
        string err = "Table doesn't exist";
        handle_error(err);
        return;
    }

    sprintf(systemcall, "mkdir Server/Result/%s", tablename);
    system(systemcall);

    while ((pos = allcolls.find(delimiter)) != allcolls.npos)
    {
        //Get a column name from the input string
        col = allcolls.substr(0, pos);
        //Remove the current column name from the input string
        allcolls.erase(0, pos + delimiter.length());
        // Get directory of collumn
        ss << p << "/" << col;
        c = ss.str();
        char *coldir = &c[0];
        if (!chkdir(coldir))
        {
            cout << "Collumn doesn't exist";
            exit(1);
        }

        sprintf(systemcall, "cp -r %s Server/Result/%s ", coldir, tablename);
        system(systemcall);

        ss.str(string());
    }
}
/**
 * @brief  Process and execute SUM query without conditions
 * @note   
 * @param  query: 
 * @param  context: 
 * @param  *evaluator: 
 * @param  relinks: 
 * @retval None
 */
void sum_exec(string query, SEALContext context, Evaluator *evaluator, RelinKeys relinks)
{
    string c, col, table, temp;
    string delimiter = " ";
    string coldelimiter = " FROM ";
    stringstream ss;
    size_t pos;
    char systemcall[500];
    char *coldir, *tablename;

    // Get the SUM token out
    pos = query.find(delimiter);
    temp = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());
    // Get the collumn to be summed
    pos = query.find(coldelimiter);
    col = query.substr(0, pos);
    query.erase(0, pos + coldelimiter.length());

    // Get table name
    pos = query.find(delimiter);
    table = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());
    tablename = &table[0];

    // Check if table exists
    string p = "Server/Database/";
    p.append(table);
    char *tabledir = &p[0];
    if (!chkdir(tabledir))
    {
        string err = "Table doesn't exist";
        handle_error(err);
        return;
    }

    // Get directory of collumn
    ss << p << "/" << col;
    c = ss.str();
    coldir = &c[0];
    if (!chkdir(coldir))
    {
        string err = "Collumn doesn't exist";
        handle_error(err);
        return;
    }
    // Sum the collumn and save result into Server/Result/sum.res
    sumcolumn(coldir, context, evaluator, relinks);

    ss.str(string());
}

/**
 * @brief  Process and executes SUM query with 1 condition
 * @note   
 * @param  query: 
 * @param  queriespath: 
 * @param  context: 
 * @param  *evaluator: 
 * @param  relinks: 
 * @retval None
 */
void sum_exec_where1(string query, string queriespath, SEALContext context, Evaluator *evaluator, RelinKeys relinks)
{
    string c1, c, col, table, temp, cond, num, comp, num_dir;
    string delimiter = " ";
    string coldelimiter = " FROM ";
    string tabdelimiter = " WHERE ";
    size_t pos;
    vector<string> cond_nums, cond_cols;
    vector<int> mode;

    stringstream ss;
    char systemcall[500];
    char *coldir, *tablename;

    //cout << query << "94u40707" << endl;
    // get the SUM token out
    pos = query.find(delimiter);
    temp = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());
    // get the collumn to be summed
    pos = query.find(coldelimiter);
    col = query.substr(0, pos);
    query.erase(0, pos + coldelimiter.length());

    // get table name
    pos = query.find(tabdelimiter);
    table = query.substr(0, pos);
    query.erase(0, pos + tabdelimiter.length());
    tablename = &table[0];

    // Check if table exists
    string p = "Server/Database/";
    p.append(table);
    char *tabledir = &p[0];
    if (!chkdir(tabledir))
    {
        string err = "Table doesn't exist";
        handle_error(err);
        return;
    }
    // Get directory of collumn
    ss << p << "/" << col;
    c = ss.str();
    coldir = &c[0];
    ss.str(string());
    if (!chkdir(coldir))
    {
        string err = "Collumn doesn't exist";
        handle_error(err);
        return;
    }
    process_cond(query, p, queriespath, &cond_cols, &cond_nums, &mode);
    sumcolumn_where(coldir, cond_cols, mode, cond_nums, context, evaluator, relinks);
}

/**
 * @brief  Processes and executes SUM query with 2 conditions
 * @note   
 * @param  query: 
 * @param  queriespath: 
 * @param  context: 
 * @param  *evaluator: 
 * @param  relinks: 
 * @retval None
 */
void sum_exec_where2(string query, string queriespath, SEALContext context, Evaluator *evaluator, RelinKeys relinks)
{
    string c1, c2, c, col, col1, col2, table, temp, cond, num1, num2, comp1, comp2, num_dir1, num_dir2, cond1;
    string delimiter = " ";
    string coldelimiter = " FROM ";
    string tabdelimiter = " WHERE ";
    string conddelimiter = "AND ";
    vector<string> cond_nums, cond_cols;
    vector<int> mode;
    size_t pos;

    stringstream ss;
    char systemcall[500];
    char *coldir, *tablename;

    //cout << query << "94u40707" << endl;
    // get the SUM token out
    pos = query.find(delimiter);
    temp = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());
    // get the collumn to be summed
    pos = query.find(coldelimiter);
    col = query.substr(0, pos);
    query.erase(0, pos + coldelimiter.length());

    // get table name
    pos = query.find(tabdelimiter);
    table = query.substr(0, pos);
    query.erase(0, pos + tabdelimiter.length());
    tablename = &table[0];

    string p = "Server/Database/";
    p.append(table);
    char *tabledir = &p[0];
    if (!chkdir(tabledir))
    {
        string err = "Table doesn't exist";
        handle_error(err);
        return;
    }

    // Get directory of collumn
    ss << p << "/" << col;
    c = ss.str();
    cout << c << endl;
    coldir = &c[0];
    cout << coldir << endl;
    ss.str(string());
    if (!chkdir(coldir))
    {
        string err = "Collumn doesn't exist";
        handle_error(err);
        return;
    }
    // get first condition into cond1
    pos = query.find(conddelimiter);
    cond1 = query.substr(0, pos);
    query.erase(0, pos + conddelimiter.length());

    //cout << cond1 << " First cond" << endl;

    process_cond(cond1, p, queriespath, &cond_cols, &cond_nums, &mode);
    process_cond(query, p, queriespath, &cond_cols, &cond_nums, &mode);
    sumcolumn_where(coldir, cond_cols, mode, cond_nums, context, evaluator, relinks);
}

void sum_exec_where1_debug(string query, string queriespath, size_t pos, SEALContext context, Evaluator *evaluator, RelinKeys relinks, Decryptor *decryptor)
{
    string c1, c, col, table, temp, cond, num, comp, num_dir;
    string delimiter = " ";
    string coldelimiter = " FROM ";
    string tabdelimiter = " WHERE ";
    vector<string> cond_nums, cond_cols;
    vector<int> mode;

    stringstream ss;
    char systemcall[500];
    char *coldir, *tablename;

    //cout << query << "94u40707" << endl;
    // get the SUM token out
    pos = query.find(delimiter);
    temp = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());
    // get the collumn to be summed
    pos = query.find(coldelimiter);
    col = query.substr(0, pos);
    query.erase(0, pos + coldelimiter.length());

    // get table name
    pos = query.find(tabdelimiter);
    table = query.substr(0, pos);
    query.erase(0, pos + tabdelimiter.length());
    tablename = &table[0];

    // check table exists
    string p = "Server/Database/";
    p.append(table);
    char *tabledir = &p[0];
    if (!chkdir(tabledir))
    {
        cout << "Table doesn't exist";
        exit(1);
    }

    // Get directory of collumn
    ss << p << "/" << col;
    c = ss.str();
    cout << c << endl;
    coldir = &c[0];
    cout << coldir << endl;
    ss.str(string());
    if (!chkdir(coldir))
    {
        cout << "Collumn doesn't exist";
        exit(1);
    }
    // get collumn to compare
    pos = query.find(delimiter);
    c1 = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());
    //cout << c1 << endl;
    ss << p << "/" << c1;
    col = ss.str();
    //cout << col << endl;
    cond_cols.push_back(col);
    ss.str(string());

    // get type of comparison
    pos = query.find(delimiter);
    comp = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());
    cout << query << endl;

    if (comp.compare(">") == 0)
    {
        mode.push_back(0);
    }
    else if (comp.compare("=") == 0)
    {
        mode.push_back(1);
    }
    else if (comp.compare("<") == 0)
    {
        mode.push_back(2);
    }

    // cout << mode << endl;
    // get number to be compared
    pos = query.find(delimiter);
    num = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());
    cout << num << "numunu" << endl;

    ss << queriespath << "/" << num;
    num_dir = ss.str();
    cond_nums.push_back(num_dir);
    ss.str(string());

    sumcolumn_where_debug(coldir, cond_cols, mode, cond_nums, context, evaluator, relinks, decryptor);
}

/**
 * @brief  Process query and call respective routine for the type of query
 * @note   
 * @param  query: 
 * @param  queriespath: 
 * @param  context: 
 * @param  *evaluator: 
 * @param  relinks: 
 * @retval None
 */
void query_exec(string query, string queriespath, SEALContext context, Evaluator *evaluator, RelinKeys relinks)
{
    string delimiter = " ";
    string token;
    string s1 = "WHERE";
    string s2 = "AND";
    string s3 = "SUM";
    size_t pos = query.find(delimiter);
    token = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());

    //cout << query << endl;

    if (token.compare("CREATE") == 0)
    {
        create_exec(query);
    }
    else if (token.compare("INSERT") == 0)
    {
        insert_exec(query, queriespath);
    }
    else if (token.compare("SELECT") == 0)
    {
        // if it's a SUM
        if (query.find(s3) != std::string::npos)
        {
            if (query.find(s1) != std::string::npos)
            {
                // if there is a second condition
                if (query.find(s2) != std::string::npos)
                {
                    sum_exec_where2(query, queriespath, context, evaluator, relinks);
                }
                else
                {
                    sum_exec_where1(query, queriespath, context, evaluator, relinks);
                }
            }
            else
            {
                sum_exec(query, context, evaluator, relinks);
            }
        }
        else if (query.find(s1) != std::string::npos) // If there's a condition
        {
            // if there is a second condition
            if (query.find(s2) != std::string::npos)
            {
                select_exec_where2(query, queriespath, context, evaluator, relinks);
            }
            else
            {
                select_exec_where1(query, queriespath, context, evaluator, relinks);
            }
        }
        else // if there is no condition
        {
            select_exec(query);
        }
    }
}

void query_exec_debug(string query, string queriespath, SEALContext context, Evaluator *evaluator, RelinKeys relinks, Decryptor *decryptor)
{
    string delimiter = " ";
    string token;
    string s1 = "WHERE";
    string s2 = "AND";
    string s3 = "SUM";
    size_t pos = query.find(delimiter);
    token = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());

    //cout << query << endl;

    if (token.compare("CREATE") == 0)
    {
        create_exec(query);
    }
    else if (token.compare("INSERT") == 0)
    {
        insert_exec(query, queriespath);
    }
    else if (token.compare("SELECT") == 0)
    {
        // if it's a SUM
        if (query.find(s3) != std::string::npos)
        {
            if (query.find(s1) != std::string::npos)
            {
                // if there is a second condition
                if (query.find(s2) != std::string::npos)
                {
                    cout << "2 cond" << endl;
                    //select_exec_where2()
                }
                else
                {
                    //cout << "1 cond" << endl;
                    sum_exec_where1_debug(query, queriespath, pos, context, evaluator, relinks, decryptor);
                }
            }
            else
            {
                sum_exec(query, context, evaluator, relinks);
            }
        }
        else if (query.find(s1) != std::string::npos) // If there's a condition
        {
            // if there is a second condition
            if (query.find(s2) != std::string::npos)
            {
                cout << "2 cond" << endl;
                //select_exec_where2()
            }
            else
            {
                //cout << "1 cond" << endl;
                //select_exec_where1();
            }
        }
        else // if there is no condition
        {
            select_exec(query);
        }
    }
}

/**
 * @brief  retrives console output
 * @note   
 * @param  cmd: Commend to be executed
 * @retval String with console output
 */
string exec(const char *cmd)
{
    char buffer[128];
    string result = "";
    FILE *pipe = popen(cmd, "r");
    if (!pipe)
        throw runtime_error("popen() failed!");
    try
    {
        while (fgets(buffer, sizeof buffer, pipe) != NULL)
        {
            result += buffer;
        }
    }
    catch (...)
    {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}

/**
 * @brief  Verifies signature of a file according to an authority
 * @note   
 * @param  directory: Directory where the file is found
 * @param  filename: Filename
 * @param  signedfile: Filename signed by the authority through SHA256 digest function
 * @param  authority: Authority which signed the file
 * @retval boolean 
 */

string verifysgn(char *directory, char *filename, char *signedfile, char *authority)
{
    char systemcall[512] = "";
    sprintf(systemcall, "cd %s && openssl base64 -d -in %s -out /tmp/sign.sha256", directory, signedfile);
    system(systemcall);
    sprintf(systemcall, "cd %s && openssl x509 -pubkey -in %s -out CApubkey.pem ", directory, authority);
    system(systemcall);
    sprintf(systemcall, "cd %s && openssl dgst -sha256 -verify CApubkey.pem -signature /tmp/sign.sha256 %s", directory, filename);

    return exec(systemcall);
}
int main(int argc, char *argv[])
{
    int clientcount = 0, i = 0;
    string sql, line;
    char cmdout[256] = "";
    char systemcall[512] = "";
    char directory[50] = "";
    char filename[50] = "";
    char signedfile[50] = "";
    char authority[50] = "";

    //Handling input parameters
    for (int k = 0; k < argc; ++k)
    {
        if (strcmp(argv[k], "-cid") == 0)
            i = atoi(argv[++k]);
        //if (strcmp(argv[i], "-o") == 0) //verbose mode, using /dev/null to suppress console output
        //	strcpy(cmdout, " > /dev/null 2>&1");
    }

    //Verify client certificate
    sprintf(directory, "Server");
    sprintf(filename, "c%d-cert.crt", i);
    sprintf(signedfile, "c%d-cert_signed.txt", i);
    sprintf(authority, "CAcert.crt");
    cout << verifysgn(directory, filename, signedfile, authority) << " - Client Public Key" << endl;

    //Verify signature of message
    sprintf(directory, "Server");
    sprintf(filename, "msg_enc.txt");
    sprintf(signedfile, "signed_digest.txt");
    sprintf(authority, "c%d-cert.crt", i);
    cout << verifysgn(directory, filename, signedfile, authority) << " - Message Signature Key" << endl;

    // Obtain server Public key and encrypt message
    sprintf(systemcall, "cd Server && openssl rsautl -decrypt -inkey server_pk.key -in msg_enc.txt -out msg.txt");
    system(systemcall);
    cout << "Message Decrypted" << endl;

    //Delete encrypted version of the message and signature file
    sprintf(systemcall, "cd Server && rm msg_enc.txt signed_digest.txt");
    system(systemcall);

    ifstream msg;

    msg.open("../Server/msg.txt");

    while (msg)
    {
        getline(msg, line);
        cout << line << endl;
    }
    msg.close();

    return 0;
}
