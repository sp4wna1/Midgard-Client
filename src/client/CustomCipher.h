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
	void encrypt(CBC_Mode< AES >::Encryption e, string fileName, string outputName) {
		try {
			printf("----------------------------------------------------------------");
			printf("\nEncrypting %s", fileName.c_str());

			ofstream outfile;
			outfile.open(outputName);

			ifstream plain;
			plain.open(fileName);

			string line;
			while (getline(plain, line)) {
				string cipher;
				StringSource s(line, true,
					new StreamTransformationFilter(e,
						new StringSink(cipher),
						StreamTransformationFilter::PKCS_PADDING
					)
				);

				string encoded = base64_encode((unsigned char*)cipher.c_str(), cipher.size());
				outfile << encoded << endl;
			}

			plain.close();
			outfile.close();

			remove(fileName.c_str());
			rename(outputName.c_str(), fileName.c_str());


			printf("\n%s finished.", fileName.c_str());
			printf("\n----------------------------------------------------------------\n");
		}
		catch (const CryptoPP::Exception & e) {
			printf("\n%s failed", fileName.c_str());
			printf(e.what());
			exit(1);
		}
	}

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

