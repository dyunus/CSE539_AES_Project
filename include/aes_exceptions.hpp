#ifndef AES_EXCEPTIONS_H
#define AES_EXCEPTIONS_H

#include <stdexcept>
#include <unordered_map>

class aes_error : public std::runtime_error {
public:
    explicit aes_error(const char* err_msg)
            : std::runtime_error(err_msg) {}
};

/**
 * Used to identify where an exception of type testbench_error was raised for easier debugging
 **/
enum class Tests {
  KEY_EXPANSION,
  NO_CACHE,
  MANUAL_SBOX,
  OFM,
  CBC,
  ECB,
  CTR,
  CFB
};

const std::unordered_map<Tests, std::string> tests_to_str {
    { Tests::KEY_EXPANSION, "Key Expansion Test" },
    { Tests::NO_CACHE, "No Cache Test"},
    {Tests::MANUAL_SBOX, "Manual SBOX Test"},
    {Tests::OFM, "OFM Accuracy"},
    {Tests::CBC, "CBC Accuracy"},
    {Tests::ECB, "ECB Accuracy"},
    {Tests::CTR, "CTR Accuracy"},
    {Tests::CFB, "CFB Accuracy"},
};

class testbench_error : public std::runtime_error {
  Tests test_type;
public:
    testbench_error(const char* err_msg, Tests test_type_)
        : std::runtime_error(err_msg), test_type (test_type_) {}

    [[nodiscard]] auto where() const -> std::string {
        auto iter = tests_to_str.find(test_type);
        return (iter != tests_to_str.end()) ? iter->second : "";
    }

};

#endif // end AES_EXCEPTIONS_H
