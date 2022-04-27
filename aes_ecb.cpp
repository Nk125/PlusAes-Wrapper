#include <iostream>
#include "binaryhandler.hpp"
#include "plusaes_wrapper.hpp"

int main(int argc, char* argv[]) {
    std::string type, in, out, pass, iv, con, aes_str, prefix;
    bool decrypt_mode;
    int pass_sz;
    nk125::plusaes_wrapper aes;
    nk125::binary_file_handler b;

    if (argc <= 1) {
        std::cerr << "Usage: -d/-e [Input File] [Output File] [Password] [IV]\n";
        return 1;
    }
    if (argc <= 2) {
        std::cerr << "Input file isn't defined!\n";
        return 1;
    }
    else if (argc <= 3) {
        std::cerr << "Output file isn't defined!\n";
        return 1;
    }
    else if (argc <= 4) {
        std::cerr << "Password isn't defined!\n";
        return 1;
    }
    else if (argc <= 5) {
        std::cerr << "IV isn't defined!\n";
        return 1;
    }
    else {
        type.assign(argv[1]);
        in.assign(argv[2]);
        out.assign(argv[3]);
        pass.assign(argv[4]);
        iv.assign(argv[5]);
        pass_sz = pass.size();
        decrypt_mode = type == "-d";
        if (!decrypt_mode && type != "-e") {
            std::cerr << "Unknown option: " << type << "\n";
            return 1;
        }

        prefix = (decrypt_mode ? "De" : "En");

        switch (pass_sz) {
            case 16:
                aes_str = "AES-128";
                break;
            case 24:
                aes_str = "AES-192";
                break;
            case 32:
                aes_str = "AES-256";
                break;
            default:
                std::cerr << "You need a password with 16, 24 or 32 bytes/chars size!\n";
                return 1;
                break;
        }

        pass_sz = 0;

        try {
            // Sets IV converting string to char* and finally casting to unsigned char*
            aes.set_iv(reinterpret_cast<unsigned char*>(iv.data()));
            con = b.read_file(in);

            if (!decrypt_mode) {
                con = aes.ecb_encrypt(con, pass);
            }
            else {
                con = aes.ecb_decrypt(con, pass);
            }

            // Maximize the security deleting the size and undefining password after use
            pass = "";

            if (con.empty()) {
                std::cerr << "Error at " << prefix << "crypting\n";
                return 1;
            }

            b.write_file(out, con);
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown: " << e.what() << "\n";
            return 2;
        }
    }

    std::cout << "Finished!\n" << prefix << "crypted file succesfully with " << aes_str << "\n";
    return 0;
}
