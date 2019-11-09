#include <string>
using std::string;
#include <cryptopp/modes.h>
using CryptoPP::CBC_Mode;
#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <fstream>
using std::ifstream;
using std::ofstream;

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
using std::ios;
using std::ios_base;
using std::getline;

#include <cstdlib>
using std::exit;

#include <sstream>
#include <cerrno>
#include <client/base64.h>
#include <client/base64.cpp>



class CustomCipher
{
public:
	CustomCipher() {}

	void decrypt(CBC_Mode< AES >::Decryption d, string fileName, string outputName) {
		try {
			ofstream outfile;
			outfile.open(outputName);
			ifstream cipher;
			cipher.open(fileName);

			string line;
			while (getline(cipher, line)) {
				string output, decoded = base64_decode(line);
				StringSource s(decoded, true,
					new StreamTransformationFilter(d,
						new StringSink(output)
					)
				);

				outfile << output << endl;
			}

			cipher.close();
			outfile.close();

			remove(fileName.c_str());
			rename(outputName.c_str(), fileName.c_str());
		}
		catch (const CryptoPP::Exception & e) {
			exit(1);
		}
	}
};

