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
#include "seal/seal.h"
#include <HelpFunc/HelpFunc.h>

using namespace std;
using namespace seal;
int n_client;

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

/**
 * @brief  Checks if a file exists
 * @note
 * @param
 * @retval 1 if the file exists, 0 if it doesn't
 */
int fileExists(string filename, string directory)
{

    ifstream file;

    string file_path;
    file_path.append(directory);
    file_path.append(filename);

    file.open(file_path);
    if (file)
    {
        return 1;
    }
    else
        return 0;
}

/**
 * @brief Prints select according to the result of the comparisons executed in the Server
 *
 * @param tabledir : Table directory
 * @param compdir : Directory with the result of the conditions per line
 * @param context
 * @param decryptor
 */
void print_select_where(char *tabledir, char *compdir, SEALContext context, Decryptor *decryptor)
{
    DIR *folder;
    stringstream ss;
    string fullpath, c, linenum, cp, col, numpath, num;
    vector<string> cols;
    char *auxpath, *coldir, *n, *npath;
    string help = "comp.res";
    char *compfile = &help[0];
    char systemcall[500];
    Ciphertext comp, pos;
    Plaintext result;
    struct dirent *entry;
    int l = 1;
    int e;

    // open table directory to iterate through entries
    folder = opendir(tabledir);
    cout << "line   ||  ";
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
            // Get collumn directory in vector
            ss << tabledir << "/" << entry->d_name;
            cols.push_back(ss.str());
            ss.str(string());

            cout << entry->d_name << "  ||  ";
        }
    }
    closedir(folder);
    cout << endl;
    folder = opendir(compdir);

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
        else if (entry->d_type == DT_DIR) // For each line
        {
            // Get path for the result of the comparison for that line
            ss << compdir << "/" << entry->d_name;
            fullpath = ss.str();
            auxpath = &fullpath[0];
            ss.str(string());
            // Load result of the comparison and decrypt it
            comp = load_hom_enc(auxpath, compfile, context);
            (*decryptor).decrypt(comp, result);
            cp = result.to_string();

            // if condition was respected print line
            if (cp.compare("1") == 0)
            {
                cout << entry->d_name << "  ||  ";
                for (int i = 0; i < cols.size(); i++)
                {
                    col = cols[i];
                    // Get path to line dir
                    ss << col << "/" << entry->d_name;
                    numpath = ss.str();
                    npath = &numpath[0];
                    ss.str(string());

                    // Get path to hexadecimal encryption
                    ss << entry->d_name << ".hex";
                    num = ss.str();
                    n = &num[0];
                    // Load hexadecimal encryption
                    pos = load_hom_enc(npath, n, context);
                    (*decryptor).decrypt(pos, result);
                    // Print result
                    cout << h2d(result.to_string()) << "  ||  ";

                    ss.str(string());
                }
                cout << endl;
            }

            ss.str(string());
        }
    }
    closedir(folder);
}

/**
 * @brief Prints the selected content by user
 *
 * @param tabledir
 * @param context
 * @param decryptor
 */
void print_select(char *tabledir, SEALContext context, Decryptor *decryptor)
{
    DIR *folder;
    stringstream ss;
    string fullpath, c, linenum, cp, col, numpath, num;
    vector<string> cols;
    char *auxpath, *coldir, *n, *npath;
    char systemcall[500];
    Ciphertext pos;
    Plaintext result;
    struct dirent *entry;
    int l = 1;
    int e;

    // open table directory to iterate through entries
    folder = opendir(tabledir);
    cout << "line   ||  ";
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
            // Get collumn in vector
            ss << tabledir << "/" << entry->d_name;
            cols.push_back(ss.str());
            ss.str(string());

            cout << entry->d_name << "  ||  ";
        }
    }
    closedir(folder);
    cout << endl;

    col = cols[0];
    coldir = &col[0];

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
        else if (entry->d_type == DT_DIR) // For each line
        {

            cout << entry->d_name << "  ||  ";
            for (int i = 0; i < cols.size(); i++)
            {
                col = cols[i];

                // Get path to line dir
                ss << col << "/" << entry->d_name;
                numpath = ss.str();
                npath = &numpath[0];
                ss.str(string());

                ss << entry->d_name << ".hex";
                num = ss.str();
                n = &num[0];
                pos = load_hom_enc(npath, n, context);
                (*decryptor).decrypt(pos, result);

                // Print entry
                cout << h2d(result.to_string()) << "  ||  ";

                ss.str(string());
            }
            cout << endl;

            ss.str(string());
        }
    }
    closedir(folder);
}

/**
 * @brief Parses the response sent by the server if the query was of type SELECT WHERE
 *
 * @param msg : Response sent by the server
 * @param result_path :Path to the directory with the response of the Server
 * @param context
 * @param decryptor
 */
void read_select_where(string msg, string result_path, SEALContext context, Decryptor *decryptor)
{
    string table, token, filepath, tablepath, comppath;
    string delimiter = " ";
    char *tabledir, *compdir;
    size_t pos;
    stringstream ss;

    // Take SELECT off
    pos = msg.find(delimiter);
    token = msg.substr(0, pos);
    msg.erase(0, pos + delimiter.length());

    // Take WHERE off
    pos = msg.find(delimiter);
    token = msg.substr(0, pos);
    msg.erase(0, pos + delimiter.length());

    // Get table name
    pos = msg.find(delimiter);
    table = msg.substr(0, pos);
    msg.erase(0, pos + delimiter.length());

    // Generate path to table folder containing wanted collumns
    ss << result_path << "/" << table;
    tablepath = ss.str();
    tabledir = &tablepath[0];
    ss.str(string());

    // Get path to the folder with the results of the comparisons
    ss << result_path << "/Comp";
    comppath = ss.str();
    compdir = &comppath[0];

    // Call printing routine
    print_select_where(tabledir, compdir, context, decryptor);
}

/**
 * @brief Parses the response sent by the server if the query was of type SELECT
 *
 * @param msg
 * @param result_path
 * @param context
 * @param decryptor
 */
void read_select(string msg, string result_path, SEALContext context, Decryptor *decryptor)
{
    string table, token, filepath, tablepath;
    string delimiter = " ";
    char *tabledir;
    size_t pos;
    stringstream ss;

    // Take SELECT off
    pos = msg.find(delimiter);
    token = msg.substr(0, pos);
    msg.erase(0, pos + delimiter.length());

    // Get table name
    pos = msg.find(delimiter);
    table = msg.substr(0, pos);
    msg.erase(0, pos + delimiter.length());

    // Generate path to table folder containing wanted collumns
    ss << result_path << "/" << table;
    tablepath = ss.str();
    tabledir = &tablepath[0];
    ss.str(string());

    print_select(tabledir, context, decryptor);
}

/**
 * @brief Reads response of the server and executes a subroutine for each of the response types
 *
 * @param msg
 * @param result_path
 * @param context
 * @param decryptor
 */
void readResult(string msg, string result_path, SEALContext context, Decryptor *decryptor)
{
    string s1 = "WHERE";
    string crt = "CREATE", ins = "INSERT", sel = "SELECT", del = "DELETE", sum = "SUM";
    stringstream ss;


    if (msg.find(crt) != string::npos) //If CREATE command
    {
        cout << msg << endl;
    }
    else if (msg.find(ins) != string::npos) //If INSERT command
    {
        cout << msg << endl;
    }
    else if (msg.find(del) != string::npos) //If DELETE command
    {
        cout << msg << endl;
    }
    else if (msg.find(sum) != string::npos) //If SUM command
    {
        Ciphertext res;
        Plaintext result;
        char *dir = &result_path[0];
        string file = "sum.res";
        char *filename = &file[0];
        res = load_hom_enc(dir, filename, context);
        (*decryptor).decrypt(res, result);
        //cout << "SUM = " << result.to_string() << endl; 
        cout << "SUM = " << h2d(result.to_string()) << endl;
    }
    else if (msg.find(sel) != string::npos)
    {
        // if it's SELECT with conditions
        if (msg.find(s1) != string::npos)
        {
            read_select_where(msg, result_path, context, decryptor);
        }
        else //if no conditions
        {
            read_select(msg, result_path, context, decryptor);
        }
    }
    else // If none of the above print the msg because it's an error message
    {
        cout << msg << endl;
    }
}

/**
 * @brief Decrypt and load the message sent by the server
 * 
 * @param context 
 * @param decryptor 
 */
void handleResult(SEALContext context, Decryptor *decryptor)
{
    char systemcall[512] = "";
    stringstream ss;
    string filepath, msg, result_path;

    //Decrypt message using client's private key
    sprintf(systemcall, "cd Clients/Client%d && openssl rsautl -decrypt -inkey c%dpk.key -in Result/msg_enc.txt -out Result/msg.txt", n_client, n_client);
    system(systemcall);

    // Get path to Result folder
    ss << "Clients/Client" << n_client << "/Result";
    result_path = ss.str();
    // Get path to message
    ss << "/msg.txt";
    filepath = ss.str();
    ss.str(string());

    // Load msg into an string
    fstream fb;
    fb.open(filepath, fstream::in);
    while (fb)
    {
        getline(fb, msg);
    }
    fb.close();
    readResult(msg, result_path, context, decryptor);
}

/**
 * @brief Checks if there's any response from the server to be read. Verifies the signature of the response and executes function to handle the response
 * 
 * @param context 
 * @param decryptor 
 */
void checkResult(SEALContext context, Decryptor *decryptor)
{
    char filename[50] = "";
    char directory[50] = "";
    char authority[50] = "";
    char signedfile[50] = "";
    char systemcall[512] = "";
    stringstream ss;
    string verified = "Verified OK";
    string resultpath;

    sprintf(directory, "Clients/Client%d/", n_client);
    //Return if there is no response from the server
    if (!fileExists("result_digest.txt", directory))
    {
        return;
    }

    //Verify the Result's signature
    sprintf(directory, "Clients/Client%d", n_client);
    sprintf(filename, "Result.zip");
    sprintf(signedfile, "result_digest.txt");
    sprintf(authority, "server-cert.crt");
    if (verifysgn(directory, filename, signedfile, authority).find(verified) != string::npos)
    {
        cout << verified << "- Result" << endl;
        cout << endl;
    }
    else
    {
        cout << "Invalid Result signature" << endl;
        //Delete In valid result folder
        sprintf(systemcall, "cd Clients/Client%d && rm Result.zip && rm result_digest.txt", n_client);
        system(systemcall);
        return;
    }

    //Unzip the Result folder
    sprintf(systemcall, "cd Clients/Client%d && unzip -qq Result.zip", n_client);
    system(systemcall);

    //Delete the zip and its signature
    sprintf(systemcall, "cd Clients/Client%d && rm Result.zip && rm result_digest.txt", n_client);
    system(systemcall);

    handleResult(context, decryptor);

    //Delete the Result folder after checking it
    sprintf(systemcall, "rm -r Clients/Client%d/Result", n_client);
    system(systemcall);
}

/**
 * @brief Receives values to be encrypted. Calls function that encrypts the values and puts them in a folder. Writes the name of the folders instead of the original values 
 *        in the message to be sent to the server
 * 
 * @param values list of the values to be encrypted
 * @param context 
 * @param encryptor 
 * @param option specifies if there's only one value to be encrypted or a list of values (option=0 means there's a list of values)
 */
void encryptValues(string values, SEALContext context, Encryptor *encryptor, int option)
{

    char filename[100];
    char systemcall[500];
    char directory[50];
    string output = " ";
    int n_bit = 8;

    //Variables for value processing
    string delimiter = " ";
    size_t pos = 0;
    string token;
    int int_token;
    int i = 1;

    if (option != 0)
    {
        int_token = stoi(values);
        sprintf(directory, "Value%d", option);
        enc_int_total(int_token, encryptor, directory, n_bit);
        sprintf(systemcall, "mv Value%d Client%dQuery", option, n_client);
        system(systemcall);
        output.append(directory);
        output.append(" ");
    }
    else
    {
        //Get every value and encrypt it
        while ((pos = values.find(delimiter)) != values.npos)
        {

            pos = values.find(delimiter);
            token = values.substr(0, pos);
            values.erase(0, pos + delimiter.length());
            int_token = stoi(token);
            sprintf(directory, "Value%d", i);
            enc_int_total(int_token, encryptor, directory, n_bit);
            sprintf(systemcall, "mv Value%d Client%dQuery", i, n_client);
            system(systemcall);

            output.append(directory);
            output.append(" ");
            i++;
        }
    }

    ofstream out;
    out.open("msg.txt", ios::app);
    out << output;
    out.close();
}

/**
 * @brief Parsing function. Handles the "SELECT SUM" command
 * 
 * @param sql command inserted by the user without the initial "SELECT SUM (colname)"
 * @param context 
 * @param encryptor 
 * @param colname 
 * @return 1 if an error occured, 0 if no error is found
 */
int select_sum(string sql, SEALContext context, Encryptor *encryptor, string colname)
{
    string delimiter = " ";
    size_t pos = 0;
    string output = "SELECT SUM";
    sql.append(" ");

    //Append the colname and the word FROM to the output string
    output.append(" ");
    output.append(colname);
    output.append(" FROM");

    //Skip the word FROM in the input command
    pos = sql.find(delimiter);
    string token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Exit if the program is unable to get the word FROM from the command
    if (sql.npos == pos || pos == 0)
    {
        return -1;
    }

    //Get the tablename from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Exit if the program is unable to get the tablename from the command
    if (sql.npos == pos || pos == 0)
    {
        return -1;
    }
    output.append(" ");
    output.append(token);

    output.append(" ");
    //Write output to file msg.txt
    ofstream out("msg.txt");
    out << output;
    out.close();
    output = "";

    //Get the word WHERE from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //If there is no WHERE write message as it is
    if (pos == sql.npos)
    {
        return 0;
    }
    //If the second word isn't WHERE, the program must return
    if (token.compare("WHERE") != 0)
    {
        return -1;
    }
    output.append("WHERE ");

    //Get the first colname from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    output.append(token);
    output.append(" ");

    //Get the first operator from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Write the message from WHERE until the first operator
    output.append(token);
    out.open("msg.txt", ios::app);
    out << output;
    out.close();

    //Get the first value from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    encryptValues(token, context, encryptor, 1);

    //Get the logical operator (AND or OR)
    pos = sql.find(delimiter);
    //Return if there is no logical operator
    if (pos == sql.npos)
    {
        return 0;
    }
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Return if the logical operator is neither AND or OR
    if (token.compare("AND") != 0 && token.compare("OR") != 0)
    {
        return -1;
    }
    output = "";
    output.append(token);
    output.append(" ");

    //Get the second colname from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    output.append(token);
    output.append(" ");

    //Get the second operator from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    output.append(token);
    out.open("msg.txt", ios::app);
    out << output;
    out.close();

    //Get the second value from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    encryptValues(token, context, encryptor, 2);

    return 0;
}

/**
 * @brief Parsing function. Handles the "SELECT" (query table) command
 * 
 * @param sql command inserted by the user without the initial "SELECT col1name"
 * @param context 
 * @param encryptor 
 * @param col1name 1st collumn to be selected
 * @return 1 if an error occured, 0 if no error is found
 */
int select_query(string sql, SEALContext context, Encryptor *encryptor, string col1name)
{
    
    size_t pos = 0;
    string delimiter = ",";
    string output = "SELECT ";
    string token = "";

    //Check if the col name has a coma
    pos = col1name.find(delimiter);
    if (pos != col1name.npos)
    {
        col1name = col1name.substr(0, pos);
    }
    //Append the 1st column's name
    output.append(col1name);

    //Get the colnames
    delimiter = "FROM ";
    pos = sql.find(delimiter);
    string colnames = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Exit if the program is unable to get the word FROM from the command
    if (sql.npos == pos)
    {
        return -1;
    }

    

    delimiter = ", ";
    while ((pos = colnames.find(delimiter)) != colnames.npos)
    {

        //Get a column name from the colnames' string
        token = colnames.substr(0, pos);

        //Append the column name to the output string
        output.append(" ");
        output.append(token);

        //Remove the current column name from the input string
        colnames.erase(0, pos + delimiter.length());
    }

    //Get the last colname
    delimiter = " ";
    pos = colnames.find(delimiter);
    token = colnames.substr(0, pos);
    if (!token.empty())
    {
        output.append(" ");
        output.append(token);
    }

    //Append the word FROM to the output string
    output.append(" FROM ");

    //Get the tablename from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());

    output.append(token);
    output.append(" ");

    //Write output to file msg.txt
    ofstream out("msg.txt");
    out << output;
    out.close();

    //Exit if the program is unable to get the tablename from the command
    if (sql.npos == pos)
    {
        return 0;
    }

    output = "";
    //Get the word WHERE from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //If there is no WHERE write message as it is
    if (pos == sql.npos)
    {
        return 0;
    }
    //If the second word isn't WHERE, the program must return
    if (token.compare("WHERE") != 0)
    {
        return -1;
    }
    output.append("WHERE ");

    //Get the first colname from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    output.append(token);
    output.append(" ");

    //Get the first operator from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Write the message from WHERE until the first operator
    output.append(token);
    out.open("msg.txt", ios::app);
    out << output;
    out.close();

    //Get the first value from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    encryptValues(token, context, encryptor, 1);

    //Get the logical operator (AND or OR)
    pos = sql.find(delimiter);
    //Return if there is no logical operator
    if (pos == sql.npos)
    {
        return 0;
    }
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Return if the logical operator is neither AND or OR
    if (token.compare("AND") != 0 && token.compare("OR") != 0)
    {
        return -1;
    }
    output = "";
    output.append(token);
    output.append(" ");

    //Get the second colname from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    output.append(token);
    output.append(" ");

    //Get the second operator from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    output.append(token);
    out.open("msg.txt", ios::app);
    out << output;
    out.close();

    //Get the second value from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    encryptValues(token, context, encryptor, 2);

    return 0;
}

/**
 * @brief Parsing function. Handles the "SELECT LINE" command
 * 
 * @param sql 
 * @return 1 if an error occured, 0 if no error is found
 */
int select_line(string sql)
{
    string delimiter = " ";
    size_t pos = 0;
    string output = "SELECT LINE";

    //Get the line number
    pos = sql.find(delimiter);
    string token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Exit if the program is unable to get the line number from the command
    if (sql.npos == pos || pos == 0)
    {
        return -1;
    }
    //Append the line number to the output string
    output.append(" ");
    output.append(token);

    //Get the word FROM from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //If the word isn't FROM, the program must return
    if (token.compare("FROM") != 0)
    {
        return -1;
    }
    //Append FROM to the output string
    output.append(" ");
    output.append(token);

    //Check if there's something written in the command other than the tablename
    pos = sql.find(delimiter);
    if (pos != sql.npos)
    {
        return -1;
    }

    output.append(" ");
    output.append(sql);
    output.append(" ");

    //Write output to file msg.txt
    ofstream out("msg.txt");
    out << output;
    out.close();

    return 0;
}

/**
 * @brief Parsing function. Checks what type of "SELECT" command was inserted ("SELECT", "SELECT_LINE" or "SELECT_SUM") and the calls the specific handler.
 * 
 * @param sql command inserted by the client without the word "SELECT"
 * @param context 
 * @param encryptor 
 * @return 1 if an error occured, 0 if no error is found
 */
int select(string sql, SEALContext context, Encryptor *encryptor)
{
    string delimiter = " ";
    size_t pos = 0;
    string colname;

    //Get the second word of the SELECT command
    pos = sql.find(delimiter);
    string token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());

    //Exit if the program is unable to get the second word from the command
    if (sql.npos == pos || pos == 0)
    {
        return -1;
    }

    if (token.compare("LINE") == 0)
    {
        return select_line(sql);
    }

    delimiter = ")";
    if (pos = token.find(delimiter) != token.npos)
    {
        colname = token.substr(4, (token.length() - 5));
        return select_sum(sql, context, encryptor, colname);
    }

    delimiter = ",";
    if (token.find((delimiter)))
    {
        colname = token.substr(0, token.length());
        return select_query(sql, context, encryptor, colname);
    }
    return -1;
}

/**
 * @brief Parsing function. Handles the "DELETE" command
 * 
 * @param sql command inserted by the client without the word "DELETE"
 * @return 1 if an error occured, 0 if no error is found
 */
int delete_row(string sql)
{
    string delimiter = " ";
    size_t pos = 0;
    string output = "DELETE";

    //Get the line number
    pos = sql.find(delimiter);
    string token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Exit if the program is unable to get the line number from the command
    if (sql.npos == pos || pos == 0)
    {
        return -1;
    }
    //Append the line number to the output string
    output.append(" ");
    output.append(token);

    //Get the word FROM from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //If the word isn't FROM, the program must return
    if (token.compare("FROM") != 0)
    {
        return -1;
    }
    //Append FROM to the output string
    output.append(" ");
    output.append(token);

    //Check if there's something written in the command other than the tablename
    pos = sql.find(delimiter);
    if (pos != sql.npos)
    {
        return -1;
    }

    output.append(" ");
    output.append(sql);
    output.append(" ");

    //Write output to file msg.txt
    ofstream out("msg.txt");
    out << output;
    out.close();

    return 0;
}

/**
 * @brief Parsing function. Handles the "INSERT INTO" command
 * 
 * @param sql command inserted by the client without the word "INSERT"
 * @param context 
 * @param encryptor 
 * @return 1 if an error occured, 0 if no error is found
 */
int insert(string sql, SEALContext context, Encryptor *encryptor)
{
    string delimiter = " ";
    size_t pos = 0;
    int n_cols = 0, n_vals = 0;
    vector<string> colnames;
    string args;
    string values;

    //Get the second from the command
    pos = sql.find(delimiter);
    string token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());

    //If the second word isn't INTO, the program must return
    if (token.compare("INTO") != 0)
    {
        return -1;
    }

    string output = "INSERT";

    //Get the tablename
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Exit if the program is unable to get the tablename from the command
    if (sql.npos == pos || pos == 0)
    {
        return -1;
    }

    //Append the tablename to the output string
    output.append(" ");
    output.append(token);

    //Get the first parenthesis
    delimiter = "(";
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Exit if the program is unable to get the first parenthesis from the command
    if (pos != 0)
    {
        return -1;
    }

    //Get the second parenthesis
    delimiter = ") ";
    pos = sql.find(delimiter);
    args = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Exit if the program is unable to get the second parenthesis from the command or if there is no info between parenthesis
    if (pos == 0 || pos == sql.npos)
    {
        return -1;
    }

    delimiter = ", ";
    string space = " ";
    string coma = ",";

    //Get the column names
    while ((pos = args.find(delimiter)) != args.npos)
    {

        //Get a column name from the input string
        token = args.substr(0, pos);

        //Check if the column name has a space
        if (token.find(space) != token.npos)
        {
            return -1;
        }

        //Check if the column name was not used yet
        for (int i = 0; i < colnames.size(); i++)
        {
            if (token.compare(colnames[i]) == 0)
            {
                cout << "Nome repetido" << endl;
                return -1;
            }
        }
        //Append the column name to the output string
        output.append(" ");
        output.append(token);
        n_cols++;

        //Add colname to the list of colnames
        colnames.push_back(token);

        //Remove the current column name from the input string
        args.erase(0, pos + delimiter.length());
    }

    //Check if the column name has a space or a coma
    if (args.find(space) != args.npos || args.find(coma) != args.npos)
    {
        return -1;
    }

    output.append(" ");
    output.append(args);
    n_cols++;

    //Get the word VALUES from the command
    delimiter = " ";
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //If the second word isn't VALUES, the program must return
    if (token.compare("VALUES") != 0)
    {
        return -1;
    }

    //Append VALUES to the output string
    output.append(" ");
    output.append(token);

    //Get the first parenthesis
    delimiter = "(";
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Exit if the program is unable to get the first parenthesis from the command
    if (pos != 0)
    {
        return -1;
    }

    //Get the second parenthesis
    delimiter = ")";
    pos = sql.find(delimiter);
    args = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Exit if the program is unable to get the second parenthesis from the command or if there is no info between parenthesis
    if (pos == 0 || pos == sql.npos)
    {
        return -1;
    }

    delimiter = ", ";

    //Get the values
    while ((pos = args.find(delimiter)) != args.npos)
    {

        //Get a value from the input string
        token = args.substr(0, pos);

        //Check if the value has a space
        if (token.find(space) != token.npos)
        {
            return -1;
        }

        //Append the value to the output string
        values.append(token);
        values.append(" ");
        n_vals++;

        //Remove the current value from the input string
        args.erase(0, pos + delimiter.length());
    }

    //Check if the value has a space or a coma
    if (args.find(space) != args.npos || args.find(coma) != args.npos)
    {
        return -1;
    }

    values.append(args);
    values.append(" ");
    n_vals++;

    if (n_vals != n_cols)
    {
        return -1;
    }

    //Write output to file msg.txt
    ofstream out("msg.txt");
    out << output;
    out.close();
    encryptValues(values, context, encryptor, 0);

    return 0;
}

/**
 * @brief Parsing function. Handles the "CREATE TABLE" command
 * 
 * @param sql command inserted by the user without the word "CREATE"
 * @return 1 if an error occured, 0 if no error is found
 */
int create(string sql)
{
    string delimiter = " ";
    size_t pos = 0;
    vector<string> colnames;

    //Get the word TABLE from the command
    pos = sql.find(delimiter);
    string token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());

    //If the second word isn't TABLE, the program must return
    if (token.compare("TABLE") != 0)
    {
        return -1;
    }
    string output = "CREATE";

    //Get the tablename
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());

    //Exit if the program is unable to get the tablename from the command
    if (sql.npos == pos || pos == 0)
    {
        return -1;
    }

    //Append the tablename to the output string
    output.append(" ");
    output.append(token);

    //Get the first parenthesis
    delimiter = "(";
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());

    //Exit if the program is unable to get the first parenthesis from the command
    if (pos != 0)
    {
        return -1;
    }

    delimiter = ", ";
    string space = " ";
    string coma = ",";

    //Get the column names
    while ((pos = sql.find(delimiter)) != sql.npos)
    {

        //Get a column name from the input string
        token = sql.substr(0, pos);

        //Check if the column name has a space
        if (token.find(space) != token.npos)
        {
            return -1;
        }

        //Check if the column name was not used yet
        for (int i = 0; i < colnames.size(); i++)
        {
            if (token.compare(colnames[i]) == 0)
            {
                cout << "Nome repetido" << endl;
                return -1;
            }
        }

        //Append the column name to the output string
        output.append(" ");
        output.append(token);

        //Add colname to the list of colnames
        colnames.push_back(token);

        //Remove the current column name from the input string
        sql.erase(0, pos + delimiter.length());
    }

    //Get the last parenthesis
    delimiter = ")";
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    //Check if the column name has a space or a coma
    if (token.find(space) != token.npos || token.find(coma) != token.npos)
    {
        return -1;
    }

    //Check if the column name was not used yet
    for (int i = 0; i < colnames.size(); i++)
    {
        if (token.compare(colnames[i]) == 0)
        {
            cout << "Nome repetido" << endl;
            return -1;
        }
    }
    output.append(" ");
    output.append(token);

    sql.erase(0, pos + delimiter.length());

    //Checks if colnames is empty: "()"
    if (sql.npos == pos || pos == 0)
    {
        return -1;
    }

    output.append(" ");

    //Write output to file msg.txt
    ofstream out("msg.txt");
    out << output;
    out.close();

    return 0;
}

/**
 * @brief Parsing function. Checks the type of command that was inserted and calls it's specific handler
 * 
 * @param sql command inserted by the client
 * @param context 
 * @param encryptor 
 * @return 1 if an error occured, 0 if no error is found
 */
int handleQuery(string sql, SEALContext context, Encryptor *encryptor)
{
    string delimiter = " ";
    size_t pos = 0;
    char systemcall[512] = "";

    //Get the first word of the command
    pos = sql.find(delimiter);
    string token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());

    //Exit if the program is unable to get a word from the command
    if (sql.npos == pos || pos == 0)
    {
        return -1;
    }

    if (token.compare("CREATE") == 0)
    {
        return create(sql);
    }

    else if (token.compare("INSERT") == 0)
    {
        return insert(sql, context, encryptor);
    }

    else if (token.compare("DELETE") == 0)
    {
        return delete_row(sql);
    }

    else if (token.compare("SELECT") == 0)
    {
        return select(sql, context, encryptor);
    }

    else
    {
        return -1;
    }
}

/**
 * @brief Deletes residual files that were not previously deleted. These files only exist if the program was interrupted in a previous execution (CTRL + C) 
 * 
 */
void deleteResidues()
{
    char systemcall[512] = "";

    sprintf(systemcall, "rm -r Client%dQuery 2>/dev/null", n_client);
    system(systemcall);

    sprintf(systemcall, "cd Clients/Client%d && rm msg.txt 2>/dev/null && rm signed_digest%d.txt 2>/dev/null && rm Client%dQuery.zip 2>/dev/null", n_client, n_client, n_client);
    system(systemcall);

    sprintf(systemcall, "cd Clients/Client%d && rm -r Result 2>/dev/null", n_client);
    system(systemcall);
}

int main(int argc, char *argv[])
{
    int clientcount = 0;
    string sql;
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
            n_client = atoi(argv[++k]);
    }

    // Verify the autenticity of Client Private Key and Certificate - They should be signed by the CA 
    sprintf(directory, "Clients/Client%d", n_client);
    sprintf(filename, "c%dpk.key", n_client);
    sprintf(signedfile, "c%dpk_signed.txt", n_client);
    sprintf(authority, "CAcert.crt");
    if (verifysgn(directory, filename, signedfile, authority).find(verified) != string::npos)
    {
        cout << verified << ": Client Private Key" << endl;
    }
    else
    {
        cout << "Invalid Client Private Key signature" << endl;
        exit(1);
    }
    sprintf(directory, "Clients/Client%d", n_client);
    sprintf(filename, "c%d-cert.crt", n_client);
    sprintf(signedfile, "c%d-cert_signed.txt", n_client);
    sprintf(authority, "CAcert.crt");
    if (verifysgn(directory, filename, signedfile, authority).find(verified) != string::npos)
    {
        cout << verified << ": Client Certificate" << endl;
    }
    else
    {
        cout << "Invalid Client Certificate signature" << endl;
        exit(1);
    }

    // Verify the autenticity of the Database Keys
    sprintf(directory, "Clients/Client%d", n_client);
    sprintf(filename, "DBprivate_key.txt");
    sprintf(signedfile, "DBprivate_key_signed.txt");
    sprintf(authority, "CAcert.crt");
    if (verifysgn(directory, filename, signedfile, authority).find(verified) != string::npos)
    {
        cout << verified << ": DB Private Key" << endl;
    }
    else
    {
        cout << "Invalid DB Private Key signature" << endl;
        exit(1);
    }

    sprintf(directory, "Clients/Client%d", n_client);
    sprintf(filename, "DBpublic_key.txt");
    sprintf(signedfile, "DBpublic_key_signed.txt");
    sprintf(authority, "CAcert.crt");
    if (verifysgn(directory, filename, signedfile, authority).find(verified) != string::npos)
    {
        cout << verified << ": DB Public Key" << endl;
    }
    else
    {
        cout << "Invalid DB Public Key signature" << endl;
        exit(1);
    }

    // Create SEALContext and load DB keys
    SEALContext context = create_context(16384, 256);
    PublicKey public_key;
    SecretKey secret_key;
    fstream keyfile;
    sprintf(filename, "Clients/Client%d/DBpublic_key.txt", n_client);
    keyfile.open(filename, fstream::binary | fstream::in);
    public_key.load(context, keyfile);
    keyfile.close();
    sprintf(filename, "Clients/Client%d/DBprivate_key.txt", n_client);
    keyfile.open(filename, fstream::binary | fstream::in);
    secret_key.load(context, keyfile);
    keyfile.close();
    // Create instances of the Encryptor and Decryptor from SEAL 
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);

    //deletes files on the client side that weren't deleted when the program was interrupted ("^C" aka "Ctrl + C")
    deleteResidues();

    //Loop to receive input commands
    while (1)
    {

        cout << endl;
        cout << endl;
        cout << "Input Command:";
        sql = "";
        getline(cin, sql);

        //break loop if exit is inserted
        if (sql.compare("exit") == 0)
        {
            break;
        }

        //Create folder for the query
        sprintf(systemcall, "mkdir Client%dQuery", n_client);
        system(systemcall);

        //Repeat loop if the command is invalid
        if (handleQuery(sql, context, &encryptor) == -1)
        {
            cerr << "Invalid command" << endl;
            sprintf(systemcall, "rm -r Client%dQuery", n_client);
            system(systemcall);
            continue;
        }

        //Move message to the client folder
        sprintf(systemcall, "mv msg.txt Clients/Client%d", n_client);
        system(systemcall);


        //Obtain server Public key and encrypt message
        sprintf(systemcall, "cd Clients/Client%d && openssl x509 -pubkey -in server-cert.crt -out /tmp/serverpub.key ", n_client);
        system(systemcall);
        sprintf(systemcall, "cd Clients/Client%d && openssl rsautl -encrypt -pubin -inkey /tmp/serverpub.key -in msg.txt -out msg_enc.txt", n_client);
        system(systemcall);

        sprintf(systemcall, "mv Clients/Client%d/msg_enc.txt Client%dQuery", n_client, n_client);
        system(systemcall);

        //zip the query folder and move it to the client folder
        sprintf(systemcall, "zip -r -qq Client%dQuery.zip Client%dQuery && mv Client%dQuery.zip Clients/Client%d", n_client, n_client, n_client, n_client);
        system(systemcall);

        //Delete the original query folder
        sprintf(systemcall, "rm -r Client%dQuery", n_client);
        system(systemcall);

        //Sign zip with private key from client
        sprintf(systemcall, "cd Clients/Client%d && openssl dgst -sha256 -sign c%dpk.key -out /tmp/sign.sha256 Client%dQuery.zip", n_client, n_client, n_client);
        system(systemcall);
        sprintf(systemcall, "cd Clients/Client%d && openssl base64 -in /tmp/sign.sha256 -out signed_digest%d.txt", n_client, n_client);
        system(systemcall);

        //Send Query to server
        sprintf(systemcall, " mv Clients/Client%d/Client%dQuery.zip Clients/Client%d/signed_digest%d.txt -t Server/Queries", n_client, n_client, n_client, n_client);
        system(systemcall);

        //Delete non encrypted version of the message in the client folder
        sprintf(systemcall, "cd Clients/Client%d && rm msg.txt", n_client);
        system(systemcall);

        cout << "Query sent to the Server" << endl;
        sprintf(systemcall, "./serverapi -cid %d", n_client);
        system(systemcall);
        cout << endl;
        cout << endl;
        cout << "Response received from the Server" << endl;
        checkResult(context, &decryptor);
    }

    return 0;
}
