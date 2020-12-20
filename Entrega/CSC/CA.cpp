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
	int clientcount = 0;
	char cmdout[55] = "";
	char systemcall[512] = "";

	//Handling input parameters
	for (int i = 0; i < argc; ++i)
	{
		if (strcmp(argv[i], "-c") == 0)
			clientcount = atoi(argv[++i]);

		if (strcmp(argv[i], "-o") == 0) //verbose mode, using /dev/null to suppress console output
			strcpy(cmdout, " > /dev/null 2>&1");
	}

	if (clientcount <= 0) // We need to have clients
	{
		cerr << "Invalid number of clients: Must bigger than 0" << endl;
		exit(1);
	}

	//Removes previous database configuration
	system("rm -r -f Admin");
	system("rm -r -f Server");
	system("rm -r -f Clients");
	//SEAL keys generation
	EncryptionParameters parms(scheme_type::bfv);
	size_t poly_modulus_degree = 16384;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(256);
	SEALContext context(parms);
	KeyGenerator keygen(context);
	PublicKey public_key;
	keygen.create_public_key(public_key);
	SecretKey private_key = keygen.secret_key();
	RelinKeys relin_keys;
	keygen.create_relin_keys(relin_keys);
	//saving keys 
	cout << "Creating SEAL keys\n"
		 << endl;
	fstream fs("DBpublic_key.txt", fstream::binary | fstream::out);
	public_key.save(fs);
	fs.close();
	fs.open("DBprivate_key.txt", fstream::binary | fstream::out);
	private_key.save(fs);
	fs.close();
	fs.open("Relin_key.txt", fstream::binary | fstream::out);
	relin_keys.save(fs);
	fs.close();

	Encryptor encryptor(context, public_key);

	// Filesystem creation
	cout << "Create Database filesystem" << endl;

	system("mkdir Admin");

	cout << "CA created" << endl;

	system("mkdir Server");

	cout << "Server created" << endl;

	system("cd Server && mkdir Queries && mkdir Result");

	cout << "Server Queries created" << endl;

	system("cd Server && mkdir Database");

	cout << "Server Database created" << endl;

	system("mkdir Clients");

	cout << "Clients created" << endl;
	// move DB keys to the Admin folder
	system("mv DBpublic_key.txt Admin");
	system("mv DBprivate_key.txt Admin");
	system("mv Relin_key.txt Admin");

	//Generate a root CA certificate and private key
	cout << "Generating CA cert" << endl;
	sprintf(systemcall, "openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout CAprivate_key.key -out CAcert.crt -subj \"/C=PT/ST=Lisbon/L=Lisbon/O=Cripto/OU=CSC-Project/CN=CA\"%s && mv CAprivate_key.key CAcert.crt Admin", cmdout);
	system(systemcall);

	//Signing the database public key with the CA private key
	cout << "Signing the database public key with the CA key" << endl;
	sprintf(systemcall, "openssl dgst -sha256 -sign Admin/CAprivate_key.key -out /tmp/sign.sha256 Admin/DBpublic_key.txt%s", cmdout);
	system(systemcall);
	sprintf(systemcall, "openssl base64 -in /tmp/sign.sha256 -out Admin/DBpublic_key_signed.txt%s", cmdout);
	system(systemcall);

	cout << "Signing the database private key with the CA key" << endl;
	sprintf(systemcall, "openssl dgst -sha256 -sign Admin/CAprivate_key.key -out /tmp/sign.sha256 Admin/DBprivate_key.txt%s", cmdout);
	system(systemcall);
	sprintf(systemcall, "openssl base64 -in /tmp/sign.sha256 -out Admin/DBprivate_key_signed.txt%s", cmdout);
	system(systemcall);

	cout << "Signing the database private key with the CA key" << endl;
	sprintf(systemcall, "openssl dgst -sha256 -sign Admin/CAprivate_key.key -out /tmp/sign.sha256 Admin/Relin_key.txt%s", cmdout);
	system(systemcall);
	sprintf(systemcall, "openssl base64 -in /tmp/sign.sha256 -out Admin/Relin_key_signed.txt%s", cmdout);
	system(systemcall);


	// installing the root CA cert and Relinearization keys
	sprintf(systemcall, "cp Admin/CAcert.crt Admin/Relin_key.txt Admin/Relin_key_signed.txt Server");
	system(systemcall);
	cout << "Generating Server Private Key and certificate request" << endl;
	sprintf(systemcall, "cd Server && openssl genrsa -out server_pk.key 1024%s && openssl req -new -key server_pk.key -out server-cert.csr -subj \"/C=PT/ST=Lisbon/L=Lisbon/O=Cripto/OU=CSC-Project/CN=Server\" %s", cmdout, cmdout);
	system(systemcall);
	cout << "Signing Server Certificate with CA Private Key" << endl;
	//Signing the server certificate with the CA private key
	sprintf(systemcall, "cd Server && openssl x509 -req -in server-cert.csr -out server-cert.crt -sha1 -CA CAcert.crt -CAkey ../Admin/CAprivate_key.key -CAcreateserial -days 3650 %s", cmdout);
	system(systemcall);

	cout << "Creating client key pairs and signing them with CA.cert" << endl;
	for (int i = 1; i <= clientcount; ++i)
	{
		//creating the voter directory
		sprintf(systemcall, "cd Clients && mkdir Client%d", i);
		system(systemcall);

		//installing the Database Key Server and CA certificates
		sprintf(systemcall, "cp Admin/DBpublic_key.txt Admin/DBprivate_key.txt Server/server-cert.crt Admin/CAcert.crt Admin/DBprivate_key_signed.txt Admin/DBpublic_key_signed.txt Clients/Client%d", i);
		system(systemcall);

		//generating clients key pairs
		sprintf(systemcall, "cd Admin && openssl genrsa -out c%dpk.key 1024%s && openssl req -new -key c%dpk.key -out c%d-cert.csr -subj \"/C=PT/ST=Lisbon/L=Lisbon/O=Cripto/OU=CSC-Project/CN=c%d\" %s", i, cmdout, i, i, i, cmdout);
		system(systemcall);

		//signing the client private key with the CA private key
		sprintf(systemcall, "cd Admin && openssl dgst -sha256 -sign CAprivate_key.key -out /tmp/sign.sha256 c%dpk.key %s", i, cmdout);
		system(systemcall);
		sprintf(systemcall, "cd Admin && openssl base64 -in /tmp/sign.sha256 -out c%dpk_signed.txt %s", i, cmdout);
		system(systemcall);

		//installing private key into Client dir
		sprintf(systemcall, "cd Admin && mv c%dpk_signed.txt c%dpk.key ../Clients/Client%d", i, i, i);
		system(systemcall);

		//converting certificate request into actual certificate and signing it with CA private key
		sprintf(systemcall, "cd Admin && openssl x509 -req -in c%d-cert.csr -out c%d-cert.crt -sha1 -CA CAcert.crt -CAkey CAprivate_key.key -CAcreateserial -days 3650 %s", i, i, cmdout);
		system(systemcall);


		sprintf(systemcall, "cd Admin && openssl dgst -sha256 -sign CAprivate_key.key -out /tmp/sign.sha256 c%d-cert.crt %s", i, cmdout);
		system(systemcall);
		sprintf(systemcall, "cd Admin && openssl base64 -in /tmp/sign.sha256 -out c%d-cert_signed.txt %s", i, cmdout);
		system(systemcall);

		//installing client certificate
		sprintf(systemcall, "cd Admin && cp c%d-cert_signed.txt c%d-cert.crt ../Server", i, i);
		system(systemcall);
		sprintf(systemcall, "cd Admin && mv c%d-cert_signed.txt c%d-cert.crt ../Clients/Client%d", i, i, i);
		system(systemcall);
	}

	cout << "Database is now ready\n"
		 << endl;
	return 0;
}
