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

    return 0;
}

/*
    sprintf(systemcall, "cd Clients/Client%d && openssl base64 -d -in c%dpk_signed.txt -out /tmp/sign.sha256");
    system(systemcall);
    sprintf(systemcall, "cd Clients/Client%d && openssl x509 -pubkey -in CAcert.crt -out CApubkey.pem ");
    system(systemcall);
    sprintf(systemcall, "cd Clients/Client1 && openssl dgst -sha256 -verify CApubkey.pem -signature /tmp/sign.sha256 c1pk.key");
    exec(systemcall);
*/