#include <iostream>
#include <vector>
#include "ntlm.h"
using namespace std;

class Cracker {
    public:
        string username;
        string hash;

        std::vector<string> generate(string username) {
            std::vector<string> vec = {"chingiz1", "chingiz2", "chingiz3", "chingiz4", "chingiz5"};
            // std::cout << vec[1] << " Wordlist";
            return vec;
        }

        bool crack(std::vector<string> wordlist){
            // string wordlist = "3008C87294511142799DCA1191E69A0F";
            for (int i = 0; i < 5; i++) {
                std::cout << wordlist[i] << " : Wordlist\n";
                if (hash == wordlist[i] && i == 4) {
                    std::cout << "Password Cracked!";
                    return true;
                }
            }
            return false;
        }
};

int main() {
    Cracker C;
    C.username = "chingiz";
    std::vector<string> wl = C.generate(C.username);
    bool resp = C.crack(wl);
    const char* hash = gen_ntlm("Hello");
    cout << hash << " Response\n"; 
    return 0;
}
