#include <gtest/gtest.h>
#include "c3d_auth.h"
#include <fstream>
#include <sstream>

// Вспомогательная функция для чтения файла
std::string read_test_file(const std::string& path) {
    std::ifstream t(path);
    std::stringstream buffer;
    buffer << t.rdbuf();
    return buffer.str();
}

TEST(AuthTest, ValidPublicKey) {
    // Предполагаем, что в текущей директории есть файл correct_public.pem,
    // который соответствует зашитому приватному ключу.
    // Для теста мы сгенерируем его заранее (см. шаг 7)
    std::string pub_key = read_test_file("correct_public.pem");
    EXPECT_TRUE(check_authorization(pub_key));
}

TEST(AuthTest, InvalidPublicKey) {
    // Файл wrong_public.pem – другой ключ, не соответствующий приватному
    std::string pub_key = read_test_file("wrong_public.pem");
    EXPECT_FALSE(check_authorization(pub_key));
}

TEST(AuthTest, MalformedKey) {
    EXPECT_FALSE(check_authorization("not a valid key"));
}