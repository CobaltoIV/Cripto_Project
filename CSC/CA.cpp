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

int main(int argc, char *argv[])
{
    int clientcount =  0;
    char cmdout[256] = "";
    char systemcall[512] = "";

	//Handling input parameters
	for (int i = 0; i < argc; ++i)
	{
		if (strcmp(argv[i], "-c") == 0) 
			clientcount = atoi(argv[++i]);

		//if (strcmp(argv[i], "-o") == 0) //verbose mode, using /dev/null to suppress console output
		//	strcpy(cmdout, " > /dev/null 2>&1");
	}

	if (clientcount <= 0) // We need to have clients
	{
		cerr << "Invalid number of clients: Must bigger than 0"<< endl;
		exit(1);
	}

	//Removes previous database configuration
	system("rm -r Admin");
	system("rm -r Server");
	system("rm -r ClientApp");
	//SEAL inits and keys generation used throughout the election process
	EncryptionParameters parms(scheme_type::bfv);
	size_t poly_modulus_degree = 8192;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
	SEALContext context(parms);
	KeyGenerator keygen(context);
	PublicKey public_key;
    keygen.create_public_key(public_key);
	SecretKey private_key = keygen.secret_key();
    //saving keys to txt files
    cout << "Creating SEAL keys\n"
		 << endl;
	fstream fs("DBpublic_key.txt", fstream::binary | fstream::out);
	public_key.save(fs); 
	fs.close();
	fs.open("DBprivate_key.txt", fstream::binary | fstream::out);
	private_key.save(fs);
	fs.close();
	

	Encryptor encryptor(context, public_key);
	
    // Filesystem creation
	cout << "Create Database filesystem" << endl;

	system("mkdir Admin");

    cout << "CA created"<< endl;

	system("mkdir Server");

    cout << "Server created"<< endl;

	system("mkdir ClientApp");

    cout << "ClientApp created"<< endl;
    system("mv DBpublic_key.txt Admin");
    /*
	//generating a 32 byte (256 bit) symmetric key
	system("openssl rand 32 > /tmp/symmetric.key");

	//encrypting the original homormophic private key
	sprintf(systemcall, "openssl aes-256-cbc -a -salt -in DBprivkey.txt -out Admin/DBprivkey.txt.enc -pass file:/tmp/symmetric.key%s", cmdout);
	system(systemcall);
    // deleting original
	system("rm -r DBprivkey.txt");
	
    cout << "Private key sucessfully encrypted" << endl;
    */
	//Generate a root CA certificate and private key
	cout << "Generating CA cert" << endl;
	sprintf(systemcall, "openssl req -x509 -sha512 -nodes -days 365 -newkey rsa:2048 -keyout CAprivate_key.key -out CAcert.crt -subj \"/C=PT/ST=Lisbon/L=Lisbon/O=Cripto/OU=CSC-Project/CN=CA\"%s && mv CAprivate_key.key CAcert.crt Admin", cmdout);
	system(systemcall);
    cout << "Operation successful"<<endl;

	//Install the root certificate and tally's own certificate and private key in the tally official app

	
	//Signing the database public key with the CA private key
	cout << "Signing the database public key with the CA cert" << endl;
	sprintf(systemcall, "openssl dgst -sha512 -sign Admin/CAprivate_key.key -out /tmp/sign.sha512 Admin/DBpublic_key.txt%s",cmdout);
	system(systemcall);
	sprintf(systemcall, "openssl base64 -in /tmp/sign.sha512 -out Admin/DBpublic_key_signed.txt%s", cmdout);
	system(systemcall);
	cout << "Creating client key pairs and signing them with CA.cert"
		 << endl;
	//procedure to affect each voter
	for (int i = 1; i <= clientcount; ++i)
	{
		//creating the voter directory
		sprintf(systemcall, "cd ClientApp && mkdir Client%d", i);
		system(systemcall);

		//installing the election public key and respective signature
		sprintf(systemcall, "cp Admin/DBpublic_key_signed.txt /DBpublic_key.txt ClientApp/Client%d", i);
		system(systemcall);

		//installing the root CA cert
		sprintf(systemcall, "cp Admin/CAcert.crt ClientApp/Client%d", i);
		system(systemcall);

		//generating clients key pairs 
		sprintf(systemcall, "cd Admin && openssl genrsa -out c%dpk.key 1024%s && openssl req -new -key c%dpk.key -out c%d-cert.csr -subj \"/C=PT/ST=Lisbon/L=Lisbon/O=Cripto/OU=CSC-Project/CN=c%d\" %s", i,cmdout, i, i, i,cmdout);
		system(systemcall);

		//signing the client private key with the CA private key
		sprintf(systemcall, "cd Admin && openssl dgst -sha512 -sign CAprivate_key.key -out /tmp/sign.sha512 c%dpk.key %s", i,cmdout);
		system(systemcall);
		sprintf(systemcall, "cd Admin && openssl base64 -in /tmp/sign.sha512 -out c%dpk_signed.txt %s", i,cmdout);
		system(systemcall);

		//installing private key and its signture into Client dir
		sprintf(systemcall, "cd Admin && mv c%dpk_signed.txt c%dpk.key ../ClientApp/Client%d", i, i, i);
		system(systemcall);

		//converting certificate request into actual certificate and signing it with CA private key
		sprintf(systemcall, "cd Admin && openssl x509 -req -in c%d-cert.csr -out c%d-cert.crt -sha1 -CA CAcert.crt -CAkey CAprivate_key.key -CAcreateserial -days 3650 %s", i, i, cmdout);
		system(systemcall);
		cout << "Client Certificate created sucessfully" << endl;
		sprintf(systemcall, "cd Admin && openssl dgst -sha512 -sign CAprivate_key.key -out /tmp/sign.sha512 c%d-cert.crt %s", i,cmdout);
		system(systemcall);
		sprintf(systemcall, "cd Admin && openssl base64 -in /tmp/sign.sha512 -out c%d-cert_signed.txt %s", i,cmdout);
		system(systemcall);

		//installing voter certificate
		sprintf(systemcall, "cd Admin && mv c%d-cert_signed.txt c%d-cert.crt ../ClientApp/Client%d", i, i, i);
		system(systemcall);
	}

	/*
	//generating a bad key to be used by an ill intensioned voter
	sprintf(systemcall, "cd CA && openssl genrsa -out hackerpk.key 1024%s",cmdout);
	system(systemcall);

	//we've usec the symmetric key to encrypt the election private key, it will now be split
	//first we need to load it from the file so we can split
	memset(data, 0, sizeof(data));
	cout << "Splitting symetric key among trustees\n"
		 << endl;
	fstream fb;
	fb.open("/tmp/sym_key.key", fstream::in | fstream::binary);
	if (fb.is_open())
	{
		//file is exactly 32 bytes, as expected...
		fb.read(stringex, 32);
		memcpy(&data, &stringex, 32);
		fb.close();
	}
	else
		cout << "Unable to open file";

	//splitting the secret
	sss_create_shares(shares, data, trusteecount, 30);

	for (int i = 1; i <= trusteecount; ++i)
	{
		//saving the share in a file
		sprintf(stringex, "trustees/trustee%d", i);
		fstream file(stringex, fstream::out | fstream::binary);
		if (file.is_open())
		{
			file.write((char *)shares[i - 1], 113);
			file.close();

			//signing the share
			sprintf(systemcall, "openssl dgst -sha256 -sign CA/CAprivKey.key -out /tmp/sign.sha256 trustees/trustee%d%s", i,cmdout);
			system(systemcall);
			sprintf(systemcall, "openssl base64 -in /tmp/sign.sha256 -out trustees/trustee%dsgn", i);
			system(systemcall);
		}
		else
			cout << "Unable to open file";
	}

	//program asks the administrator for the weights of the voters
	string line;
    int d;
	Ciphertext weight;
	for (int i = 1; i <= clientcount; ++i)
	{
		sprintf(stringex, "Enter weight of Voter %d:\n", i);
        cout << stringex << endl;
        while (getline(cin, line))
        {   
            stringstream ss(line);
            if (ss >> d)
            {
                if (ss.eof())
                {   // Success
                    if (d >= 1 && d <= 10)
					{
						//first we need to encode the weight...
						Plaintext x_plain(to_string(d));

						//so we can then encrypt it
						encryptor.encrypt(x_plain, weight);

						//saving the file
						sprintf(stringex, "tallyApp/weight%d.txt", i);
						ofstream ofs(stringex, ofstream::binary);
						weight.save(ofs);
						ofs.close();

						//and signing the weight file
						sprintf(systemcall, "openssl dgst -sha256 -sign CA/CAprivKey.key -out /tmp/sign.sha256 tallyApp/weight%d.txt%s", i,cmdout);
						system(systemcall);
						sprintf(systemcall, "openssl base64 -in /tmp/sign.sha256 -out tallyApp/weight%dsgn.txt%s", i, cmdout);
						system(systemcall);
                    	break;						
					}
                }
                std::cout << "Error! Only weights values between 1 and 10" << std::endl;
            }
            sprintf(stringex, "Insert valid weight for voter %d: ", i);
            cout << stringex;
		}	
	}
	cout << "Election is now ready to begin\n" << endl;
	return 0;
    */
}
