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
    int clientcount = 0, i = 1;
    string sql;
    char cmdout[256] = "";
    char systemcall[512] = "";
    char directory[50] = "";
    char filename[50] = "";
    char signedfile[50] = "";
    char authority[50] = "";

    sprintf(directory, "Clients/Client%d", i);
    sprintf(filename, "c%dpk.key", i);
    sprintf(signedfile, "c%dpk_signed.txt", i);
    sprintf(authority, "CAcert.crt");
    cout << verifysgn(directory, filename, signedfile, authority) << endl;

    sprintf(directory, "Clients/Client%d", i);
    sprintf(filename, "c%d-cert.crt", i);
    sprintf(signedfile, "c%d-cert_signed.txt", i);
    sprintf(authority, "CAcert.crt");
    cout << verifysgn(directory, filename, signedfile, authority) << endl;

    sprintf(directory, "Clients/Client%d", i);
    sprintf(filename, "DBprivate_key.txt");
    sprintf(signedfile, "DBprivate_key_signed.txt");
    sprintf(authority, "CAcert.crt");
    cout << verifysgn(directory, filename, signedfile, authority) << endl;

    sprintf(directory, "Clients/Client%d", i);
    sprintf(filename, "DBpublic_key.txt");
    sprintf(signedfile, "DBpublic_key_signed.txt");
    sprintf(authority, "CAcert.crt");
    cout << verifysgn(directory, filename, signedfile, authority) << endl;


    cout << "Input Command:";
    getline(cin,sql);
    ofstream out("msg.txt");
    out << sql;
    out.close();
    sprintf(systemcall, "mv msg.txt Clients/Client%d", i);
    system(systemcall);
    // Obtain server Public key and encrypt message
    sprintf(systemcall, "cd Clients/Client%d && openssl x509 -pubkey -in server-cert.crt -out /tmp/serverpub.key ", i);
    system(systemcall);
    sprintf(systemcall, "cd Clients/Client%d && openssl rsautl -encrypt -pubin -inkey /tmp/serverpub.key -in msg.txt -out msg.txt.enc",i);
	system(systemcall);
    // Sign message with private key from client
    sprintf(systemcall, "cd Clients/Client%d && openssl dgst -sha256 -sign c%dpk.key -out /tmp/sign.sha256 msg.txt.enc", i,i);
    system(systemcall);
    sprintf(systemcall, "cd Clients/Client%d && openssl base64 -in /tmp/sign.sha256 -out msg_signed.txt.enc %s", i,cmdout);
    system(systemcall);

    // Send Encrypted message
    sprintf(systemcall, "cd Clients/Client%d && mv msg.txt.enc msg_signed.txt.enc ../../Server", i);
    system(systemcall);

    system("./serverapi -cid 1");
    return 0;
}
