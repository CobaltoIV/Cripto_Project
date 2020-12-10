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



int insert(string sql){
    string delimiter = " ";
    size_t pos = 0;
    int n_cols = 0, n_vals = 0;
    vector<string> colnames;
    string args;

    //Get the word INSERT from the command 
    pos = sql.find(delimiter);
    string token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());

    //If the second word isn't INTO, the program must return
    if(token.compare("INTO") != 0){
        return -1;
    }

    string output = "INSERT INTO";

    //Get the tablename 
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Exit if the program is unable to get the tablename from the command 
    if(sql.npos == pos || pos == 0){
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
    if(pos != 0){
        return -1;
    }


    //Get the second parenthesis
    delimiter = ") ";
    pos = sql.find(delimiter);
    args = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Exit if the program is unable to get the second parenthesis from the command or if there is no info between parenthesis 
    if(pos == 0 || pos == sql.npos){
        return -1;
    }

    delimiter = ", ";
    string space = " ";
    string coma = ",";

    //Get the column names 
    while ((pos = args.find(delimiter)) != args.npos){

        //Get a column name from the input string
        token = args.substr(0, pos);

        //Check if the column name has a space 
        if(token.find(space) != token.npos){
            return -1;
        }  

        //Check if the column name was not used yet
        for(int i = 0; i<colnames.size(); i++){
            if(token.compare(colnames[i]) == 0){
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
    if(args.find(space) != args.npos || args.find(coma) != args.npos){
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
    if(token.compare("VALUES") != 0){
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
    if(pos != 0){
        return -1;
    }

    //Get the second parenthesis
    delimiter = ")";
    pos = sql.find(delimiter);
    args = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());
    //Exit if the program is unable to get the second parenthesis from the command or if there is no info between parenthesis 
    if(pos == 0 || pos == sql.npos){
        return -1;
    }
    

    delimiter = ", ";

    //Get the values 
    while ((pos = args.find(delimiter)) != args.npos){

        //Get a value from the input string
        token = args.substr(0, pos);

        //Check if the value has a space 
        if(token.find(space) != token.npos){
            return -1;
        }  

        //Append the value to the output string
        output.append(" ");
        output.append(token);
        n_vals++;

        //Remove the current value from the input string 
        args.erase(0, pos + delimiter.length());
    }

    //Check if the value has a space or a coma
    if(args.find(space) != args.npos || args.find(coma) != args.npos){
        return -1;
    } 

    output.append(" ");
    output.append(args);
    n_vals++;

    if(n_vals != n_cols){
        return -1;
    }

    //Write output to file msg.txt
    ofstream out("msg.txt");
    out << output;
    out.close();

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
    if(token.compare("TABLE") != 0){
        return -1;
    }
    string output = "CREATE TABLE";


    //Get the tablename 
    pos = sql.find(delimiter);
    token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());

    //Exit if the program is unable to get the tablename from the command 
    if(sql.npos == pos || pos == 0){
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
    if(pos != 0){
        return -1;
    }

    delimiter = ", ";
    string space = " ";
    string coma = ","; 

    //Get the column names 
    while ((pos = sql.find(delimiter)) != sql.npos){

        //Get a column name from the input string
        token = sql.substr(0, pos);

        //Check if the column name has a space 
        if(token.find(space) != token.npos){
            return -1;
        }  

        //Check if the column name was not used yet
        for(int i = 0; i<colnames.size(); i++){
            if(token.compare(colnames[i]) == 0){
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
    if(token.find(space) != token.npos || token.find(coma) != token.npos){
        return -1;
    }

    //Check if the column name was not used yet
    for(int i = 0; i<colnames.size(); i++){
        if(token.compare(colnames[i]) == 0){
            cout << "Nome repetido" << endl;
            return -1;
        }
    }          
    output.append(" ");
    output.append(token);

    sql.erase(0, pos + delimiter.length());

    //Checks if colnames is empty: "()"
    if(sql.npos == pos || pos == 0){
        return -1;
    }


    cout << output << endl;

    //Write output to file msg.txt
    ofstream out("msg.txt");
    out << output;
    out.close();

    return 0;
}


void handleQuery(string sql)
{
    string delimiter = " ";
    size_t pos = 0;
    char systemcall[512] = "";

    //Get the first word of the command 
    pos = sql.find(delimiter);
    string token = sql.substr(0, pos);
    sql.erase(0, pos + delimiter.length());

    //Exit if the program is unable to get a word from the command 
    if(sql.npos == pos || pos == 0){
        cerr << "Invalid command" << endl;
        exit(1);
    }

    if(token.compare("CREATE") == 0)
    {   
        if(create(sql) == -1)
        {
            cerr << "Invalid command" << endl;
            sprintf(systemcall, "rm Client%dQuery", n_client);
            system(systemcall);
            exit(1);
        }
    }
    
    else if(token.compare("INSERT") == 0)
    {   
        cout << "INSERT" << endl;
        if(insert(sql) == -1){
            cerr << "Invalid command" << endl;
            sprintf(systemcall, "rm Client%dQuerry", n_client);
            system(systemcall);
            exit(1);
        }

    }
        
    else if(token.compare("DELETE") == 0)
    {
        cout << "DELETE" << endl;
    }

    else if(token.compare("SELECT") == 0)
    {
        cout << "SELECT" << endl;
    }

    else{
        cout << "Invalid command" << endl;
        exit(1);
    }

    return;
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


    cout << "Input Command:";
    //getline(cin,sql);
    sql = "INSERT INTO oi (1, 2) VALUES (2, 3)";

    sprintf(systemcall, "mkdir Client%dQuery", n_client);
    system(systemcall);

    handleQuery(sql);

    
    sprintf(systemcall, "mv msg.txt Clients/Client%d", n_client);
    system(systemcall);

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

    //Send Query to server
    sprintf(systemcall, "mv Client%dQuery Server/Queries", n_client);
    system(systemcall);


    //Delete non encrypted version of the message in the client folder
    sprintf(systemcall, "cd Clients/Client%d && rm msg.txt", n_client);
    system(systemcall);


    cout << "end of client api" << endl;
    getline(cin, sql);
    sprintf(systemcall, "./serverapi -cid %d", n_client);
    system(systemcall);
    return 0;
}
