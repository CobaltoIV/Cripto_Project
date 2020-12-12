
#include <iostream>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <dirent.h>
#include <CompFunc/CompFunc.h>
#include <HelpFunc/HelpFunc.h>
#include <seal/seal.h>

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

int main(int argc, char *argv[])
{
    char directoryx[50] = "x";
    char directoryy[50] = "y";
    char directoryz[50] = "z";
    char directoryk[50] = "k";
    char directoryl[50] = "l";
    char directoryp[50] = "p";
    char directoryj[50] = "j";
    const char *filepath = "Server/Queries/Client1Query/msg.txt";
    string qpath = "Server/Queries/Client1Query";
    int i = 1;
    int x = 13;
    int y = 10;
    int z = 9;
    int k = 14;
    int l = 5;
    int p = 10;
    int n_bit = 4;
    char systemcall[500];
    size_t pos;
    Ciphertext x_hex, y_hex, z_hex, res, x_r, y_r;
    Plaintext result;
    system("rm -r Server");
    system("mkdir Server");
    system("cd Server && mkdir Database");
    system("cd Server && mkdir Result");
    system("cd Server && mkdir Queries");
    system("cd Server/Queries && mkdir Client1Query");

    SEALContext context = create_context(8192, 32);
    KeyGenerator keygen(context);
    PublicKey public_key;
    RelinKeys relin_keys;
    SecretKey secret_key;
    /*
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    SecretKey secret_key = keygen.secret_key();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    */
    fstream fs;
    fs.open("DBpublic_key.txt", fstream::binary | fstream::in);
    public_key.load(context, fs);
    fs.close();
    fs.open("DBprivate_key.txt", fstream::binary | fstream::in);
    secret_key.load(context, fs);
    fs.close();
    fs.open("Relin_key.txt", fstream::binary | fstream::in);
    relin_keys.load(context, fs);
    fs.close();

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    enc_int_total(x, &encryptor, directoryx, n_bit);

    enc_int_total(y, &encryptor, directoryy, n_bit);

    enc_int_total(z, &encryptor, directoryz, n_bit);

    enc_int_total(k, &encryptor, directoryk, n_bit);

    enc_int_total(l, &encryptor, directoryl, n_bit);

    enc_int_total(p, &encryptor, directoryp, n_bit);

    enc_int_total(y, &encryptor, directoryj, n_bit);

    system("mv x Server/Queries/Client1Query");
    system("mv y Server/Queries/Client1Query");
    system("mv z Server/Queries/Client1Query");
    system("mv k Server/Queries/Client1Query");
    system("mv l Server/Queries/Client1Query");
    system("mv p Server/Queries/Client1Query");
    system("mv j Server/Queries/Client1Query");

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

    query_exec(query, qpath, context, &evaluator, relin_keys);

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

    query_exec(query, qpath, context, &evaluator, relin_keys);

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

    query_exec(query, qpath, context, &evaluator, relin_keys);

    sql = "INSERT table col1 col2 VALUES l j ";
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

    query_exec(query, qpath, context, &evaluator, relin_keys);

    //sql = "SELECT col1 col2 FROM table WHERE col1 > l AND col2 = y ";
    //sql = "SELECT col1 col2 FROM table WHERE col1 > l ";
    sql = "SELECT SUM col1 FROM table WHERE col1 > l ";

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

    //query_exec_debug(query, qpath, context, &evaluator, relin_keys, &decryptor);

    query_exec(query, qpath, context, &evaluator, relin_keys);

    system("cd Server && tar -cf Result.tar Result/*");
    system("cd Server && rm -r Result");
    system("cd Server && tar -xf Result.tar Result/");
    system("cd Server && rm -r Result.tar");

    string d = "Server/Result";
    char *dir = &d[0];
    string file = "sum.res";
    char *filename = &file[0];
    res = load_hom_enc(dir, filename, context);
    decryptor.decrypt(res, result);
    cout << "SUM = " << h2d(result.to_string()) << endl;
    /*
    string d = "Server/Result/Comp/1";
    char *dir = &d[0];
    string file = "comp.res";
    char *filename = &file[0];
    res = load_hom_enc(dir, filename, context);
    decryptor.decrypt(res, result);
    cout << "Comp1 = " << h2d(result.to_string()) << endl;

    d = "Server/Result/Comp/2";
    dir = &d[0];
    file = "comp.res";
    filename = &file[0];
    res = load_hom_enc(dir, filename, context);
    decryptor.decrypt(res, result);
    cout << "Comp1 = " << h2d(result.to_string()) << endl;
    */

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