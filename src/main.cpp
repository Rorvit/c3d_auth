#include "c3d_auth.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

// Читает содержимое файла в строку
std::string read_file(const std::string& path) 
{
    std::ifstream file(path);
    if (!file.is_open()) throw std::runtime_error("Cannot open file: " + path);
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <public_key_file_or_pem>" << std::endl;
        return 1;
    }

    std::string public_key;
    std::string arg = argv[1];
    
    if (arg.find("-----BEGIN") == std::string::npos) 
    {
        try 
        {
            public_key = read_file(arg);
        }
        catch (const std::exception& e) 
        {
            std::cerr << e.what() << std::endl;
            return 1;
        }
    }
    else 
    {
        public_key = arg;
    }

    bool ok = check_authorization(public_key);
    std::cout << (ok ? "Authorization passed" : "Authorization failed") << std::endl;
    return ok ? 0 : 1;
}