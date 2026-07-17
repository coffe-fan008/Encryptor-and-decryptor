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
  int opcion;
  cout << "Choose an option [1]Encrypt or [2]Decrypt: ";
  cin >> opcion;
    if (argc != 4) {
        cerr << "Use: " << argv[0] << " <File_Input> <File_output> <key>" << endl;
        return 1;
    }
    string archivoEntrada = argv[1];
    string archivoSalida = argv[2];
    string claveTexto = argv[3];

    if (claveTexto.size() != 16) {
        cerr << "Error: The key must be exactly 16 characters long." << endl;
        return 1;
    }

    if ( opcion == 2 ) {
      descifrarArchivo(archivoEntrada, archivoSalida,
          reinterpret_cast<const CryptoPP::byte*>(claveTexto.data()),
          claveTexto.size());
    cout << "File Decrypted Successfully " << endl;
    return 0;
    }
    if ( opcion == 1 ) {
      cifrarArchivo(archivoEntrada, archivoSalida,
          reinterpret_cast<const CryptoPP::byte*>(claveTexto.data()),
          claveTexto.size());
    cout << "file successfully encrypted " << endl;
    return 0;
    }
    else {
      cout << "Select a valid option " << endl;
      return 1;
    }
}
