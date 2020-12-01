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

    sprintf(directory, "Server");
    sprintf(filename, "c%d-cert.crt", i);
    sprintf(signedfile, "c%d-cert_signed.txt", i);
    sprintf(authority, "CAcert.crt");
    cout << verifysgn(directory, filename, signedfile, authority) << " - Client Public Key" << endl;

    //Verify signature of message
    sprintf(directory, "Server");
    sprintf(filename, "msg.txt.enc");
    sprintf(signedfile, "msg_signed.txt.enc");
    sprintf(authority, "c%d-cert.crt",i);
    cout << verifysgn(directory, filename, signedfile, authority) << " - Message Signature Key" << endl;

    sprintf(systemcall,"cd Server && openssl rsautl -decrypt -inkey server_pk.key -in msg.txt.enc -out msg.txt");
    system(systemcall);
    cout << "Message Decrypted" << endl;

    ifstream msg;

    msg.open("../Server/msg.txt");

    while (msg){
        getline(msg, line);
        cout << line << endl;
    }
    msg.close();

    return 0;
}
