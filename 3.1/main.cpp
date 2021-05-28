#include <unittest++/UnitTest++.h>
#include "modAlphaCipher.h"

SUITE(KeyTest) {
    TEST(ValidKey) {
        CHECK_EQUAL("ÁÂÃÁÂ",modAlphaCipher("ÁÂÃ").encrypt("ÀÀÀÀÀ"));
    }
    TEST(LongKey) {
        CHECK_EQUAL("ÁÂÃÄÅ",modAlphaCipher("ÁÂÃÄÅÆÇÈÉÊ").encrypt("ÀÀÀÀÀ"));
    }
    TEST(LowCaseKey) {
        CHECK_EQUAL("ÁÂÃÁÂ",modAlphaCipher("áâã").encrypt("ÀÀÀÀÀ"));
    }
    TEST(DigitsInKey) {
        CHECK_THROW(modAlphaCipher cp("Á1"),cipher_error);
    }
    TEST(PunctuationInKey) {
        CHECK_THROW(modAlphaCipher cp("Á!!!"),cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(modAlphaCipher cp("ÁÂ Ã"),cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(modAlphaCipher cp(""),cipher_error);
    }
    TEST(WeakKey) {
        CHECK_THROW(modAlphaCipher cp("ÀÀÀ"),cipher_error);
    }
}

struct KeyB_fixture {
    modAlphaCipher * p;
    KeyB_fixture() {
        p = new modAlphaCipher("Á");
    }
    ~KeyB_fixture() {
        delete p;
    }
};

SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("ÁÂÃÄÅÆ",
                    p->encrypt("ÀÁÂÃÄÅ"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL("ÁÂÃÄÅÆ",
                    p->encrypt("àáâãäå"));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL("ÁÂÃÄÅÆÇÈÊ",
                    p>encrypt("ÀÁÂ ÃÄÅ ÆÇÈ!!!"));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        CHECK_EQUAL("ÁÂÃÄ", p->encrypt("ÀÁÂÃ123"));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(""),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt("1234+4321=5555"),cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("ÀÁÂÃÄÅ",
                    modAlphaCipher("ß").encrypt("ßÀÁÂÃÄ"));
    }
}

SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("ÀÁÂÃÄÅ",
                    p->decrypt("ÁÂÃÄÅÆ"));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p->decrypt("ÁÂÃäåæ"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p>decrypt("ÁÂ,ÃÄÅ ÆÇ!!!"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p->decrypt("ÁÂÃ123"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p->decrypt("1234+4321=5555"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(""),cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("ßÀÁÂÃÄ",
                    modAlphaCipher("ß").decrypt("ÀÁÂÃÄÅ"));
    }
}

int main()
{
    return UnitTest::RunAllTests();
}