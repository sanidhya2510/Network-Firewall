#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <regex>
#include <vector>
#include <unordered_map>
#include "parser.cpp"

const std::string FILE_NAME = "./tmp/rules.txt";
const std::string COUNT_FILE_NAME = "./tmp/rule_count.txt";

// Function Declarations
void printUsage();
void listRules();
void removeLine(int line_no);
bool isValidIPAddress(const std::string &ipAddress);
bool isValidPortNumber(const std::string &portNumber);
bool isValidFilePath(const std::string &filePath);
bool isValidProtocol(const std::string &protocol);

// Main Function
int main(int argc, char *argv[])
{
    if (argc < 2) {
        printUsage();
        return 1;
    }

    int argi = 1;

    std::string command = std::string(argv[argi]);
    if (command == "add") {
        argi++;
        if (argc - argi <= 0) {
            std::cout << "Usage: nfw add -p <protocol> -f <file_path> -s <source_ip> -d <dest_ip> -port <port_no>" << std::endl;
            return 1;
        }

        std::string protocol = "-";
        std::string file_path = "-";
        std::string source_ip = "-";
        std::string dest_ip = "-";
        std::string port_no = "-";
        std::unordered_map<std::string, std::string> rules_map;

        while (argi < argc) {
            if (std::string(argv[argi]) == "-p") {
                argi++;
                if (protocol != "-") {
                    std::cout << "Error: -p parameter cannot be repeated." << std::endl;
                    return 1;
                }
                if (argi == argc) {
                    std::cout << "Error: no argument passed." << std::endl;
                    return 1;
                }
                protocol = argv[argi];
                // Check if the protocol is valid
                if (!isValidProtocol(protocol)) {
                    std::cout << "Error: Invalid protocol." << std::endl;
                    return 1;
                }
                rules_map["protocol"] = protocol;
            }
            else if (std::string(argv[argi]) == "-f") {
                argi++;
                if (file_path != "-") {
                    std::cout << "Error: -f parameter cannot be repeated." << std::endl;
                    return 1;
                }
                if (argi == argc) {
                    std::cout << "Error: no argument passed." << std::endl;
                    return 1;
                }
                file_path = argv[argi];
            
                // Check if the file path is valid
                if (!isValidFilePath(file_path)) {
                    std::cout << "Error: Invalid file path." << std::endl;
                    return 1;
                }
                rules_map["file_path"] = file_path;
            }
            else if (std::string(argv[argi]) == "-s") {
                argi++;
                if (source_ip != "-") {
                    std::cout << "Error: -s parameter cannot be repeated." << std::endl;
                    return 1;
                }
                if (argi == argc) {
                    std::cout << "Error: no argument passed." << std::endl;
                    return 1;
                }
                source_ip = argv[argi];

                // Check if the source IP is in a valid format
                if (!isValidIPAddress(source_ip)) {
                    std::cout << "Error: Invalid source IP address." << std::endl;
                    return 1;
                }
                rules_map["source"] = source_ip;
            }
            else if (std::string(argv[argi]) == "-d") {
                argi++;
                if (dest_ip != "-") {
                    std::cout << "Error: -d parameter cannot be repeated." << std::endl;
                    return 1;
                }
                if (argi == argc) {
                    std::cout << "Error: no argument passed." << std::endl;
                    return 1;
                }
                dest_ip = argv[argi];

                // Check if the destination IP is in a valid format
                if (!isValidIPAddress(dest_ip)) {
                    std::cout << "Error: Invalid destination IP address." << std::endl;
                    return 1;
                }
                rules_map["destination"] = dest_ip;
            }
            else if (std::string(argv[argi]) == "-port") {
                argi++;
                if (port_no != "-") {
                    std::cout << "Error: -port parameter cannot be repeated." << std::endl;
                    return 1;
                }
                if (argi == argc) {
                    std::cout << "Error: no argument passed." << std::endl;
                    return 1;
                }
                port_no = argv[argi];

                // Check if the port number is in a valid range
                if (!isValidPortNumber(port_no)) {
                    std::cout << "Error: Invalid port number." << std::endl;
                    return 1;
                }
                rules_map["port"] = port_no;
            }
            else {
                std::cout << "Error: Unrecognized parameter '" << argv[argi] << "'" << std::endl;
                return 1;
            }

            argi++;
        }

        std::ifstream inFile(COUNT_FILE_NAME);
        std::string line;

        int rule_no = 0;

        if (!inFile) {
            rule_no = 1;
        }
        else {
            while (std::getline(inFile, line)) {
                if (!line.empty()) {
                    rule_no = std::stoi(line);
                }
            }
            rule_no++;
        }
        inFile.close();

        std::ofstream outFile(COUNT_FILE_NAME);
        if (outFile) {
            outFile << rule_no;
            outFile.close();
            std::cout << "Assigned rule number: " << rule_no << std::endl;
        }
        else {
            std::cerr << "Error writing to file." << std::endl;
            return 1;
        }

        std::ofstream file(FILE_NAME, std::ios::app);
        if (file.is_open()) {
            file << rule_no << " " << protocol << " " << file_path << " " << source_ip << " " << dest_ip << " " << port_no << std::endl;
            file.close();
            std::cout << "Rule added." << std::endl;
        }
        else {
            std::cerr << "Error: Unable to open the file for writing." << std::endl;
            return 1;
        }
        // rules_map["name"] = std::to_string(rule_no);
        parsergen(std::to_string(rule_no), rules_map);
    }
    else if (command == "list") {
        argi++;
        if (argc - argi > 0) {
            std::cout << "Usage: nfw list" << std::endl;
            return 1;
        }

        listRules();
    }
    else if (command == "remove") {
        argi++;
        if (argc - argi <= 0 || argc - argi > 1) {
            std::cout << "Usage: nfw remove <line_no>" << std::endl;
            return 1;
        }

        int line_no = std::stoi(argv[argi]);
        removeLine(line_no);
    }
    else if (command == "clear") {
        argi++;
        if (argc - argi > 0) {
            std::cout << "Usage: nfw clear" << std::endl;
            return 1;
        }

        std::ifstream file(FILE_NAME);
        if (!file.is_open()) {
            std::cerr << "Error: Unable to open the file." << std::endl;
            return 1;
        }

        std::string line;
        while(std::getline(file, line)) {
            removeLine(1);
        }
    }
    else {
        printUsage();
        return 1;
    }

    return 0;
}

// Function Implementations
void printUsage()
{
    std::cout << "Usage: nfw [add|list|remove|clear]" << std::endl;
}

void listRules()
{
    std::ifstream file(FILE_NAME);
    if (!file.is_open()) {
        std::cerr << "Error: Unable to open the file." << std::endl;
        return;
    }

    std::string line;
    int line_number = 1;

    // std::cout << "Rule_No Protocol File_Path Source_IP Destination_IP Port_No" << std::endl;
    while (std::getline(file, line)) {
        std::cout << line_number << ": " << line << std::endl;
        line_number++;
    }

    file.close();
}

void removeLine(int line_no)
{
    //before removing the line, we need to get the rule number of the line
    std::string rule_no;

    std::ifstream file(FILE_NAME);
    if (!file.is_open()) {
        std::cerr << "Error: Unable to open the file." << std::endl;
        return;
    }

    std::string line;
    int line_count = 0;
    while (std::getline(file, line)) {
        line_count++;
    }

    if (line_no < 1 || line_no > line_count) {
        std::cout << "Invalid line number." << std::endl;
        file.close();
        return;
    }

    file.clear();
    file.seekg(0, std::ios::beg);
    std::ofstream tempFile("temp.txt");

    int current_line = 0;
    while (std::getline(file, line)) {
        current_line++;
        if (current_line != line_no) {
            tempFile << line << std::endl;
        }  else {
            rule_no = line.substr(0, line.find(" "));
        }
    }

    file.close();
    tempFile.close();

    std::remove(FILE_NAME.c_str());
    if (std::rename("temp.txt", FILE_NAME.c_str()) != 0) {
        std::cerr << "Error: Renaming the temporary file failed." << std::endl;
        return;
    }

    std::cout << "Rule " << rule_no << " has been removed." << std::endl;
    removeModule(rule_no);
}

bool isValidIPAddress(const std::string &ipAddress)
{
    std::regex ipPattern("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    return std::regex_match(ipAddress, ipPattern);
}

bool isValidPortNumber(const std::string &portNumber)
{
    int port = std::stoi(portNumber);
    return (port >= 0 && port <= 65535);
}

bool isValidFilePath(const std::string &filePath)
{
    std::ifstream file(filePath);
    return file.good();
}

bool isValidProtocol(const std::string &protocol)
{
    std::vector<std::string> addedProtocols = {"icmp", "tcp", "udp"};
    return std::find(addedProtocols.begin(), addedProtocols.end(), protocol) != addedProtocols.end();
}
