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

/**
 * @brief  checks if a file exists
 * @note   
 * @param   
 * @retval 1 if the file exists, 0 if it doesn't
 */
int fileExists(string filename, string directory){

    ifstream file;
    
    string file_path;
    file_path.append(directory);
    file_path.append(filename);

    file.open(file_path);
    if(file){
        return 1;
    }
    else return 0;
}

void handleResult(){
    char systemcall[512] = "";

    //Decrypt message using client's private key
    sprintf(systemcall, "cd Clients/Client%d && openssl rsautl -decrypt -inkey c%dpk.key -in Result/msg_enc.txt -out Result/msg.txt", n_client, n_client);
    system(systemcall);

    
}

void checkResult(){
    char filename[50] = "";
    char directory[50] = "";
    char authority[50] = "";
    char signedfile[50] = "";
    char systemcall[512] = "";


    sprintf(directory, "Clients/Client%d/", n_client);
    //Return if there is no response from the server 
    if(!fileExists("result_digest.txt", directory)){
        return;
    }

    //Verify the Result's signature
    sprintf(directory, "Clients/Client%d", n_client);
    sprintf(filename, "Result.zip");
    sprintf(signedfile, "result_digest.txt");
    sprintf(authority, "server-cert.crt");
    cout << verifysgn(directory, filename, signedfile, authority) << " - Result signature" << endl;

    //Unzip the Result folder
    sprintf(systemcall, "cd Clients/Client%d && unzip -qq Result.zip", n_client);
    system(systemcall);

    //Delete the zip and its signature
    sprintf(systemcall, "cd Clients/Client%d && rm Result.zip && rm result_digest.txt", n_client);
    system(systemcall);

    handleResult();

    //Delete the Result folder after checking it
    //sprintf(systemcall, "rm -r Clients/Client%d/Result", n_client);
    //system(systemcall);



}

void encryptValues(string values, int option)
{

    char filename[100];
    char systemcall[500];
    char directory[50];
    string output = " ";
    int n_bit = 4;

    //Get DB public key and create encryptor
    SEALContext context = create_context(8192, 128);
    PublicKey public_key;
    fstream keyfile;
    sprintf(filename, "Clients/Client%d/DBpublic_key.txt", n_client);
    keyfile.open(filename, fstream::binary | fstream::in);
    public_key.load(context, keyfile);
    keyfile.close();
    Encryptor encryptor(context, public_key);

    //Variables for value processing
    string delimiter = " ";
    size_t pos = 0;
    string token;
    int int_token;
    int i = 1;

    if(option != 0){
        int_token = stoi(values);
        sprintf(directory, "Value%d", option);
        enc_int_total(int_token, &encryptor, directory, n_bit);
        sprintf(systemcall, "mv Value%d Client%dQuery", option, n_client);
        system(systemcall);
        output.append(directory);
        output.append(" ");
    }
    else{
        //Get every value and encrypt it
        while ((pos = values.find(delimiter)) != values.npos)
        {

            pos = values.find(delimiter);
            token = values.substr(0, pos);
            values.erase(0, pos + delimiter.length());
            int_token = stoi(token);
            sprintf(directory, "Value%d", i);
            enc_int_total(int_token, &encryptor, directory, n_bit);
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

int select_sum(string sql, string colname)
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
    if(pos == sql.npos){
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
    encryptValues(token, 1);

    //Get the logical operator (AND or OR)
    pos = sql.find(delimiter);
    //Return if there is no logical operator
    if(pos == sql.npos){
        return 0;
    }
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Return if the logical operator is neither AND or OR
    if(token.compare("AND") != 0 && token.compare("OR") != 0){
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
    encryptValues(token, 2);

    return 0;
}

int select_query(string sql, string col1name)
{
    cout << "query" << endl;
    size_t pos = 0;
    string delimiter = "FROM ";
    string output = "SELECT";
    string token = "";

    //Get the colnames 
    pos = sql.find(delimiter);
    string colnames = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Exit if the program is unable to get the word FROM from the command
    if (sql.npos == pos || pos == 0)
    {
        return -1;
    }

    delimiter = ", ";
    while((pos = colnames.find(delimiter)) != colnames.npos){
        
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
    output.append(" ");
    output.append(token);

    //Append the word FROM to the output string 
    output.append(" FROM ");

    //Get the tablename from the command
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Exit if the program is unable to get the tablename from the command
    if (sql.npos == pos || pos == 0)
    {
        return -1;
    }
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
    if(pos == sql.npos){
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
    encryptValues(token, 1);

    //Get the logical operator (AND or OR)
    pos = sql.find(delimiter);
    //Return if there is no logical operator
    if(pos == sql.npos){
        return 0;
    }
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Return if the logical operator is neither AND or OR
    if(token.compare("AND") != 0 && token.compare("OR") != 0){
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
    encryptValues(token, 2);

    return 0;
}

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

int select(string sql)
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
        return select_sum(sql, colname);
    }

    delimiter = ",";
    if (token.find((delimiter)))
    {
        colname = token.substr(0, token.length() - 1);
        return select_query(sql, colname);
    }
    return -1;
}

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

int insert(string sql)
{
    string delimiter = " ";
    size_t pos = 0;
    int n_cols = 0, n_vals = 0;
    vector<string> colnames;
    string args;
    string values;

    //Get the word INSERT from the command
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
    encryptValues(values, 0);

    return 0;
}

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

int handleQuery(string sql)
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
        return insert(sql);
    }

    else if (token.compare("DELETE") == 0)
    {
        return delete_row(sql);
    }

    else if (token.compare("SELECT") == 0)
    {
        return select(sql);
    }

    else
    {
        return -1;
    }
}

int main(int argc, char *argv[])
{
    int clientcount = 0;
    string sql;
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
            n_client = atoi(argv[++k]);
        //if (strcmp(argv[i], "-o") == 0) //verbose mode, using /dev/null to suppress console output
        //	strcpy(cmdout, " > /dev/null 2>&1");
    }

    sprintf(directory, "Clients/Client%d", n_client);
    sprintf(filename, "c%dpk.key", n_client);
    sprintf(signedfile, "c%dpk_signed.txt", n_client);
    sprintf(authority, "CAcert.crt");
    cout << verifysgn(directory, filename, signedfile, authority) << endl;

    sprintf(directory, "Clients/Client%d", n_client);
    sprintf(filename, "c%d-cert.crt", n_client);
    sprintf(signedfile, "c%d-cert_signed.txt", n_client);
    sprintf(authority, "CAcert.crt");
    cout << verifysgn(directory, filename, signedfile, authority) << endl;

    sprintf(directory, "Clients/Client%d", n_client);
    sprintf(filename, "DBprivate_key.txt");
    sprintf(signedfile, "DBprivate_key_signed.txt");
    sprintf(authority, "CAcert.crt");
    cout << verifysgn(directory, filename, signedfile, authority) << endl;

    sprintf(directory, "Clients/Client%d", n_client);
    sprintf(filename, "DBpublic_key.txt");
    sprintf(signedfile, "DBpublic_key_signed.txt");
    sprintf(authority, "CAcert.crt");
    cout << verifysgn(directory, filename, signedfile, authority) << endl;

    //Loop to receive input commands
    while(1){

        checkResult();

        cout << "Input Command:";
        sql = "";
        getline(cin,sql);

        //break loop if exit is inserted 
        if (sql.compare("exit") == 0){
            break;
        }

        //sql = "SELECT SUM(col) FROM table2";
        //sql = "SELECT SUM(col) FROM table2 WHERE col1 < 1 AND col2 < 2";

        //Create folder for the query
        sprintf(systemcall, "mkdir Client%dQuery", n_client);
        system(systemcall);

        //Repeat loop if the command is invalid
        if(handleQuery(sql) == -1){
            cerr << "Invalid command" << endl;
            sprintf(systemcall, "rm -r Client%dQuery", n_client);
            system(systemcall);
            continue;
        }

        //Move message to the client folder
        sprintf(systemcall, "mv msg.txt Clients/Client%d", n_client);
        system(systemcall);

        cout << "end of handle query" << endl;
        getline(cin, sql);

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
        sprintf(systemcall, "cd Clients/Client%d && openssl base64 -in /tmp/sign.sha256 -out signed_digest%d.txt %s", n_client, n_client, cmdout);
        system(systemcall);

        cout << "zip criado e assinado" << endl;
        getline(cin, sql);

        /*
        cout << "pasta apagada" << endl;
        getline(cin, sql);

        //Unzip the query folder
        sprintf(systemcall, "unzip Client%dQuery.zip", n_client);
        system(systemcall);

        cout << "pasta descomprimida" << endl;
        getline(cin, sql);
        */

        /*
        // Obtain server Public key and encrypt message
        sprintf(systemcall, "cd Clients/Client%d && openssl x509 -pubkey -in server-cert.crt -out /tmp/serverpub.key ", n_client);
        system(systemcall);
        sprintf(systemcall, "cd Clients/Client%d && openssl rsautl -encrypt -pubin -inkey /tmp/serverpub.key -in msg.txt -out msg_enc.txt",n_client);
        system(systemcall);

        //Sign message with private key from client
        sprintf(systemcall, "cd Clients/Client%d && openssl dgst -sha256 -sign c%dpk.key -out /tmp/sign.sha256 msg_enc.txt", n_client,n_client);
        system(systemcall);
        sprintf(systemcall, "cd Clients/Client%d && openssl base64 -in /tmp/sign.sha256 -out signed_digest.txt %s", n_client,cmdout);
        system(systemcall);

        //Bundle query 
        sprintf(systemcall, "cd Clients/Client%d && mv msg_enc.txt signed_digest.txt ../../Client%dQuery", n_client, n_client);
        system(systemcall);
        */

        //Send Query to server
        sprintf(systemcall, " mv Clients/Client%d/Client%dQuery.zip Clients/Client%d/signed_digest%d.txt -t Server/Queries", n_client, n_client, n_client, n_client);
        system(systemcall);

        //Delete non encrypted version of the message in the client folder
        sprintf(systemcall, "cd Clients/Client%d && rm msg.txt", n_client);
        system(systemcall);

        cout << "end of client api" << endl;
        getline(cin, sql);
        sprintf(systemcall, "./serverapi -cid %d", n_client);
        system(systemcall);
    }

    return 0;
}
