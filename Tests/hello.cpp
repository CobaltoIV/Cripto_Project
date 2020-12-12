#include <iostream>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <dirent.h>
#include <CompFunc/CompFunc.h>
#include <HelpFunc/HelpFunc.h>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main()
{
    SEALContext context = create_context(8192, 32);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    cout << "Creating SEAL keys\n"
		 << endl;
	fstream fs;
    fs.open("DBpublic_key.txt", fstream::binary | fstream::out);
	public_key.save(fs);
	fs.close();
	fs.open("DBprivate_key.txt", fstream::binary | fstream::out);
	secret_key.save(fs);
	fs.close();
    fs.open("Relin_key.txt", fstream::binary | fstream::out);
	relin_keys.save(fs);
	fs.close();

}

