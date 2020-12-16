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
#include <dirent.h>
#include <CompFunc/CompFunc.h>
#include <HelpFunc/HelpFunc.h>
#include "seal/seal.h"

using namespace std;
using namespace seal;
/**
 * @brief  Creates file with wanted error message
 * @note   
 * @param  error_msg: error message
 * @retval None
 */
void create_msg(string error_msg)
{
    ofstream fb;
    fb.open("Server/Result/msg.txt");
    fb << error_msg;
    fb.close();
}

void selectline(char *tabledir, string line, char *tablename)
{
    DIR *folder;
    stringstream ss;
    string fullpath, c, linenum, new_l, new_fullpath;
    vector<string> cols;
    char *linepath, *coldir, *lnum, *colname;
    char systemcall[500];
    struct dirent *entry;
    int l = 1;

    // open table directory to iterate through entries
    folder = opendir(tabledir);

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
        else if (entry->d_type == DT_DIR) // if the entry is a folder(only folder inside table directory would be the collumn folder)
        {
            // open directory
            cout << entry->d_name << endl;

            colname = &entry->d_name[0];
            cout << tablename << endl;
            sprintf(systemcall, "mkdir Server/Result/%s/%s", tablename, colname);
            system(systemcall);
            // if it's the wanted line
            // Get fullpath for number in entry
            ss << tabledir << "/" << entry->d_name;
            ss << "/" << line;
            fullpath = ss.str();
            linepath = &fullpath[0];
            cout << fullpath << endl;
            // Delete entry from collumn
            sprintf(systemcall, "cp -r %s Server/Result/%s/%s", linepath, tablename, colname);
            system(systemcall);
            //Clear contents of previous
            fullpath.clear();
            ss.str(string());
        }
    }
    closedir(folder);
}

void deleteline(char *tabledir, string line)
{
    DIR *folder;
    stringstream ss;
    string fullpath, c, linenum, new_l, new_fullpath;
    vector<string> cols;
    char *linepath, *coldir, *lnum, *newnum, *new_linepath;
    char systemcall[500];
    struct dirent *entry;
    int l = 1;

    // open table directory to iterate through entries
    folder = opendir(tabledir);

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
        else if (entry->d_type == DT_DIR) // if the entry is a folder(only folder inside table directory would be the collumn folder)
        {
            // open directory
            cout << entry->d_name << endl; // collumn name
            // Get fullpath for number in entry
            ss << tabledir << "/" << entry->d_name;
            cols.push_back(ss.str());
            ss << "/" << line;
            fullpath = ss.str();
            linepath = &fullpath[0];
            cout << fullpath << endl;
            // Delete entry from collumn
            sprintf(systemcall, "rm -r %s", linepath);
            system(systemcall);
            //Clear contents of previous
            fullpath.clear();
            ss.str(string());
        }
    }
    closedir(folder);

    // Rename lines
    for (int i = 0; i < cols.size(); i++)
    {
        l = 1;
        c = cols[i];
        coldir = &c[0];
        folder = opendir(coldir);

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
            else if (entry->d_type == DT_DIR) // if the entry is a folder(only folder inside table directory would be the collumn folder)
            {
                // open directory
                cout << entry->d_name << endl; // collumn name
                linenum = entry->d_name;
                lnum = &linenum[0];

                new_l = to_string(l);
                newnum = &new_l[0];
                ss << c << "/" << new_l;
                new_fullpath = ss.str();
                new_linepath = &new_fullpath[0];

                ss.str(string());
                // Get fullpath for number in entry
                ss << c << "/" << linenum;
                fullpath = ss.str();
                linepath = &fullpath[0];
                cout << fullpath << endl;
                // Delete entry from collumn
                sprintf(systemcall, "mv %s/%s.hex %s/%s.hex", linepath, lnum, linepath, newnum);
                system(systemcall);

                sprintf(systemcall, "mv %s %s", linepath, new_linepath);
                system(systemcall);
                //Clear contents of previous
                fullpath.clear();
                ss.str(string());
                l++;
            }
        }
        closedir(folder);
    }
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
 * @brief  Takes a collumn and a group of conditions. Sums the collumn according to the conditions
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
void sumcolumn_where(char *columndir, vector<string> cond_cols, vector<int> modes, vector<string> cond_nums, SEALContext context, Evaluator *evaluator, RelinKeys relinks, int comptype)
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
                    if (comptype == 0) // AND
                    {
                        comp = AND(comp, output[modes[i]], evaluator, relinks);
                        /*
                    // Multiply with the result from the previous condition
                    (*evaluator).multiply_inplace(comp, output[modes[i]]);
                    (*evaluator).relinearize_inplace(comp, relinks);
                    */
                    }
                    else // OR
                    {
                        comp = OR(comp, output[modes[i]], evaluator, relinks);
                    }
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
void selectcollumn_where(vector<string> cond_cols, vector<int> modes, vector<string> cond_nums, SEALContext context, Evaluator *evaluator, RelinKeys relinks, int comptype)
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
                    comp = output[modes[i]]; // If it's the first condition just don't need to multiply
                else
                {
                    if (comptype == 0) // AND
                    {
                        comp = AND(comp, output[modes[i]], evaluator, relinks);
                        /*
                    // Multiply with the result from the previous condition
                    (*evaluator).multiply_inplace(comp, output[modes[i]]);
                    (*evaluator).relinearize_inplace(comp, relinks);
                    */
                    }
                    else // OR
                    {
                        comp = OR(comp, output[modes[i]], evaluator, relinks);
                    }
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

void selectline_exec(string query)
{
    string c, line, table, temp;
    string delimiter = " ";
    string linedelimiter = " FROM ";
    stringstream ss;
    size_t pos;
    char systemcall[500];
    char *coldir, *tablename;

    // Get the LINE token out
    pos = query.find(delimiter);
    temp = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());
    // Get the line to be summed
    pos = query.find(linedelimiter);
    line = query.substr(0, pos);
    query.erase(0, pos + linedelimiter.length());

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
        create_msg(err);
        return;
    }

    sprintf(systemcall, "mkdir Server/Result/%s", tablename);
    system(systemcall);
    // Sum the collumn and save result into Server/Result/sum.res
    selectline(tabledir, line, tablename);

    ss.str(string());

    ss << "SELECT " << table;
    string m = ss.str();
    create_msg(m);
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
        create_msg(err);
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
            create_msg(err);
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
    selectcollumn_where(cond_cols, mode, cond_nums, context, evaluator, relinks, 0);

    ss << "SELECT WHERE " << table;
    string m = ss.str();
    create_msg(m);
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
void select_exec_where2(string query, string queriespath, SEALContext context, Evaluator *evaluator, RelinKeys relinks, int comptype)
{
    string allcolls, c1, c, col, col2, c2, cond1, table, temp, cond, num, comp, num_dir, comp2, num2, num_dir2;
    string delimiter = " ";
    string coldelimiter = "FROM ";
    string tabdelimiter = " WHERE ";
    string conddelimiter;
    if (comptype == 0)
    {
        conddelimiter = "AND ";
    }
    else
    {
        conddelimiter = "OR ";
    }
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
        create_msg(err);
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
    //cout << cond1 << endl;
    //cout << query << endl;
    // process first condition
    process_cond(cond1, p, queriespath, &cond_cols, &cond_nums, &mode);
    // process second condition
    process_cond(query, p, queriespath, &cond_cols, &cond_nums, &mode);
    // execute and save comparisons
    selectcollumn_where(cond_cols, mode, cond_nums, context, evaluator, relinks, comptype);

    ss << "SELECT WHERE " << table;
    string m = ss.str();
    create_msg(m);
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
void create_exec(string query, int owner)
{
    string col, c, token, owner_file;
    stringstream ss;
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
        create_msg(err);
        return;
    }
    ss << p << "/"
       << "owner.txt";
    owner_file = ss.str();
    ofstream fs;
    fs.open(owner_file);
    fs << owner;
    fs.close();
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
    string m = "CREATE Sucessfull";
    create_msg(m);
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
        create_msg(err);
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
    string m = "INSERT Sucessfull ";
    create_msg(m);
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
        create_msg(err);
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
            string err = "Collumn doesn't exist";
            create_msg(err);
            return;
        }

        sprintf(systemcall, "cp -r %s Server/Result/%s ", coldir, tablename);
        system(systemcall);

        ss.str(string());
    }

    ss << "SELECT " << table;
    string m = ss.str();
    create_msg(m);
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
        create_msg(err);
        return;
    }

    // Get directory of collumn
    ss << p << "/" << col;
    c = ss.str();
    coldir = &c[0];
    if (!chkdir(coldir))
    {
        string err = "Collumn doesn't exist";
        create_msg(err);
        return;
    }
    // Sum the collumn and save result into Server/Result/sum.res
    sumcolumn(coldir, context, evaluator, relinks);

    ss.str(string());

    string m = "SUM ";
    create_msg(m);
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
        create_msg(err);
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
        create_msg(err);
        return;
    }
    process_cond(query, p, queriespath, &cond_cols, &cond_nums, &mode);
    sumcolumn_where(coldir, cond_cols, mode, cond_nums, context, evaluator, relinks, 0);

    string m = "SUM WHERE";
    create_msg(m);
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
void sum_exec_where2(string query, string queriespath, SEALContext context, Evaluator *evaluator, RelinKeys relinks, int comptype)
{
    string c1, c2, c, col, col1, col2, table, temp, cond, num1, num2, comp1, comp2, num_dir1, num_dir2, cond1;
    string delimiter = " ";
    string coldelimiter = " FROM ";
    string tabdelimiter = " WHERE ";
    string conddelimiter;
    if (comptype == 0)
    {
        conddelimiter = "AND ";
    }
    else
    {
        conddelimiter = "OR ";
    }
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
        create_msg(err);
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
        create_msg(err);
        return;
    }
    // get first condition into cond1
    pos = query.find(conddelimiter);
    cond1 = query.substr(0, pos);
    query.erase(0, pos + conddelimiter.length());

    //cout << cond1 << " First cond" << endl;

    process_cond(cond1, p, queriespath, &cond_cols, &cond_nums, &mode);
    process_cond(query, p, queriespath, &cond_cols, &cond_nums, &mode);
    sumcolumn_where(coldir, cond_cols, mode, cond_nums, context, evaluator, relinks, comptype);

    string m = "SUM WHERE";
    create_msg(m);
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

void delete_exec(string query)
{
    string coldelimiter = "FROM ";
    string delimiter = " ";
    string alllines, line, table;
    stringstream ss;
    size_t pos;
    char systemcall[500];
    char *tablename;
    // Get all lines
    pos = query.find(coldelimiter);
    alllines = query.substr(0, pos);
    query.erase(0, pos + coldelimiter.length());

    // Get table name
    pos = query.find(delimiter);
    table = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());
    tablename = &table[0];

    string p = "Server/Database/";
    p.append(table);
    char *tabledir = &p[0];
    if (!chkdir(tabledir))
    {
        string err = "Table doesn't exist";
        create_msg(err);
        return;
    }

    while ((pos = alllines.find(delimiter)) != alllines.npos)
    {
        //Get a column name from the input string
        line = alllines.substr(0, pos);
        //Remove the current column name from the input string
        alllines.erase(0, pos + delimiter.length());
        // Get directory of collumn

        deleteline(tabledir, line);

        ss.str(string());
    }
    string m = "DELETE Sucessfull";
    create_msg(m);
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
void query_exec(string query, string queriespath, SEALContext context, Evaluator *evaluator, RelinKeys relinks, int cid)
{
    string delimiter = " ";
    string token;
    string s1 = "WHERE";
    string s2 = "AND";
    string s3 = "SUM";
    string s4 = "LINE";
    string s5 = "OR";


    size_t pos = query.find(delimiter);
    token = query.substr(0, pos);
    query.erase(0, pos + delimiter.length());

    //cout << query << endl;

    if (token.compare("CREATE") == 0)
    {
        create_exec(query, cid);
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
                    sum_exec_where2(query, queriespath, context, evaluator, relinks, 0);
                }
                else if (query.find(s5) != std::string::npos)
                {
                    sum_exec_where2(query, queriespath, context, evaluator, relinks, 1);
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
                select_exec_where2(query, queriespath, context, evaluator, relinks, 0);
            }
            else if (query.find(s5) != std::string::npos)
            {
                select_exec_where2(query, queriespath, context, evaluator, relinks, 1);
            }
            else
            {
                select_exec_where1(query, queriespath, context, evaluator, relinks);
            }
        }
        else if (query.find(s4) != std::string::npos)
        {
            selectline_exec(query);
        }
        else // if there is no condition
        {
            select_exec(query);
        }
    }
    else if (token.compare("DELETE") == 0)
    {
        delete_exec(query);
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
    string sql, query;
    char cmdout[256] = "";
    char systemcall[512] = "";
    char directory[50] = "";
    char filename[50] = "";
    char signedfile[50] = "";
    char authority[50] = "";
    string verified = "Verified OK";
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
    if(verifysgn(directory, filename, signedfile, authority).find(verified) != string::npos){
        cout << verified << ": Client Certificate" << endl;
    }
    else
    {
        cout << "Invalid Client Certificate signature" << endl;
        exit(1);
    }

    sprintf(directory, "Server");
    sprintf(filename, "Relin_key.txt");
    sprintf(signedfile, "Relin_key_signed.txt");
    sprintf(authority, "CAcert.crt");
    if(verifysgn(directory, filename, signedfile, authority).find(verified) != string::npos){
        cout << verified << ": DB Relin Key" << endl;
    }
    else
    {
        cout << "Invalid Relin Keys signature" << endl;
        exit(1);
    }
    //Verify signature of message
    sprintf(directory, "Server");
    sprintf(filename, "Queries/Client%dQuery.zip", i);
    sprintf(signedfile, "Queries/signed_digest%d.txt", i);
    sprintf(authority, "c%d-cert.crt", i);
    if(verifysgn(directory, filename, signedfile, authority).find(verified) != string::npos){
        cout << verified << ": Client Query" << endl;
    }
    else
    {
        cout << "Invalid Query signature" << endl;
        exit(1);
    }
    SEALContext context = create_context(8192, 128);

    RelinKeys relin_keys;

    fstream fs;
    fs.open("Server/Relin_key.txt", fstream::binary | fstream::in);
    relin_keys.load(context, fs);
    fs.close();

    Evaluator evaluator(context);

    sprintf(systemcall, "cd Server/Queries && unzip -qq Client%dQuery.zip", i);
    system(systemcall);

    // Obtain server Public key and encrypt message
    sprintf(systemcall, "cd Server && openssl rsautl -decrypt -inkey server_pk.key -in Queries/Client%dQuery/msg_enc.txt -out Queries/Client%dQuery/msg.txt", i, i);
    system(systemcall);
    cout << "Message Decrypted" << endl;

    sprintf(systemcall, "cd Server/Queries && rm Client%dQuery.zip && rm signed_digest%d.txt && cd Client%dQuery && rm msg_enc.txt", i, i, i);
    system(systemcall);

    stringstream ss;
    ss << "Server/Queries/Client" << i << "Query";
    string qpath = ss.str();
    //cout << qpath << endl;
    ss << "/"
       << "msg.txt";
    string msgpath = ss.str();
    //cout << msgpath << endl;
    ifstream msg;

    msg.open(msgpath);

    while (msg)
    {
        getline(msg, query);
    }
    msg.close();

    query_exec(query, qpath, context, &evaluator, relin_keys, i);

    //Obtain server Public key and encrypt message
    sprintf(systemcall, "cd Server && openssl x509 -pubkey -in c%d-cert.crt -out /tmp/c%dpub.key ", i, i);
    system(systemcall);
    sprintf(systemcall, "cd Server/Result && openssl rsautl -encrypt -pubin -inkey /tmp/c%dpub.key -in msg.txt -out msg_enc.txt", i);
    system(systemcall);

    // Delete original message
    system("rm Server/Result/msg.txt");

    //zip the Result folder and move it to the client folder
    sprintf(systemcall, "cd Server && zip -r -qq Result.zip Result");
    system(systemcall);

    // Sign the Result folder
    sprintf(systemcall, "cd Server && openssl dgst -sha256 -sign server_pk.key -out /tmp/sign.sha256 Result.zip");
    system(systemcall);
    sprintf(systemcall, "cd Server && openssl base64 -in /tmp/sign.sha256 -out result_digest.txt %s", cmdout);
    system(systemcall);

    sprintf(systemcall, "cd Server && mv Result.zip result_digest.txt ../Clients/Client%d", i);
    system(systemcall);
    // Delete contents of Result waiting for next query
    system("rm -r  Server/Result/* Server/Queries/*");

    return 0;
}
