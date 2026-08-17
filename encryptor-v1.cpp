#include <cryptopp/rijndael.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <fstream>
#include <iostream>
#include <string>
#include <cstring>
using namespace std;

void descifrarArchivo(const string& archivoEntrada, const string& archivoSalida, const CryptoPP::byte* clave, unsigned int claveLongitud) {
     ifstream in(archivoEntrada, ios::binary);
     ofstream out(archivoSalida, ios::binary);

     CryptoPP::byte key[16];
     memcpy(key, clave, claveLongitud);

     CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption encryptor;
     encryptor.SetKeyWithIV(key, claveLongitud, key, claveLongitud);

     CryptoPP::FileSource fuente(in, true,
         new CryptoPP::StreamTransformationFilter(encryptor,
             new CryptoPP::FileSink(out)
        )
    );
}
void cifrarArchivo( const string& archivoEntrada, const string& archivoSalida, const CryptoPP::byte* clave, unsigned int claveLongitud) {
     ifstream in(archivoEntrada, ios::binary);
     ofstream out(archivoSalida, ios::binary);

     CryptoPP::byte key[16];
     memcpy(key, clave, claveLongitud);

     CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor;
     encryptor.SetKeyWithIV(key, claveLongitud, key, claveLongitud);

     CryptoPP::FileSource fuente(in, true,
         new CryptoPP::StreamTransformationFilter(encryptor,
             new CryptoPP::FileSink(out)
        )
    );
}
int main(int argc, char* argv[]) {
  cout<<R"(                    ███████████            
                  ████       ████          
                 ███          ░███         
                ███             ███        
                ███             ███        
                ███             ███        
                ███             ███        
             █████████████████████████     
             █████████████████████████     
             ███████████▒░░███████████     
             ██████████░    ██████████     
             ███████████   ███████████     
             ███████████   ███████████     
             ███████████   ███████████     
             ██████████░░░░░██████████     
             █████████████████████████     
             █████████████████████████     )"<<endl;
  cout << " _____ _   _  ____ ______   ______ _____ ___  ____  \n"
          "| ____| \\ | |/ ___|  _ \\ \\ / /  _ \\_   _/ _ \\|  _ \\ \n"
          "|  _| |  \\| | |   | |_) \\ V /| |_) || || | | | |_) |\n"
          "| |___| |\\  | |___|  _ < | | |  __/ | || |_| |  _ < \n"
          "|_____|_| \\_|\\____|_| \\_\\|_| |_|    |_| \\___/|_| \\_\\\n" << endl;
  int opcion;
  cout << "Choose an option [1]Encrypt or [2]Decrypt: ";
  cin >> opcion;
  cin.ignore();
    string inputFile;
    string outputFile;
    string passwd;

    cout<<"Enter the input file: ";
    getline(cin, inputFile);
    cout<<"Enter the output file: ";
    getline(cin, outputFile);
    cout<<"Enter 16 characters password: ";
    getline(cin, passwd);

    if (passwd.size() != 16) {
        cerr << "Error: The key must be exactly 16 characters long!" << endl;
        return 1;
    }

    if ( opcion == 2 ) {
      descifrarArchivo(inputFile, outputFile,
          reinterpret_cast<const CryptoPP::byte*>(passwd.data()),
          passwd.size());
    cout << "File Decrypted Successfully :) " << endl;
    return 0;
    }
    if ( opcion == 1 ) {
      cifrarArchivo(inputFile, outputFile,
          reinterpret_cast<const CryptoPP::byte*>(passwd.data()),
          passwd.size());
    cout << "file successfully encrypted :) " << endl;
    return 0;
    }
    else {
      cout << "Select a valid option " << endl;
      return 1;
    }
}