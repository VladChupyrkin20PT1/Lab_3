#include <UnitTest++/UnitTest++.h>
#include <modCipher.h>
#include <iostream>
#include <locale>
#include <codecvt>
using namespace std;
struct KeyB_fixture {
	modCipher * p;
	KeyB_fixture()
	{
		p = new modCipher(L"4");
	}
	~KeyB_fixture()
	{
		delete p;
	}
};
wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> codec;
SUITE(KeyTest)
{
	TEST(ValidKey) {
		CHECK_EQUAL("В-И-РТПЕ", codec.to_bytes(modCipher(L"4").encrypt(L"ПРИВЕТ")));
	}
	TEST(LongKey) {
		CHECK_EQUAL("ТЕВИРП",codec.to_bytes(modCipher(L"6").encrypt(L"ПРИВЕТ")));
	}
	TEST(NegativeKey) {
		CHECK_THROW(modCipher cp(L"-5"),cipher_error);
	}
	TEST(WhitespaceInKey) {
		CHECK_THROW(modCipher cp(L"1 1"),cipher_error);
	}
	TEST(EmptyKey) {
		CHECK_THROW(modCipher cp(L""),cipher_error);
	}
	TEST(AlphaAndPunctuationInKey) {
		CHECK_THROW(modCipher cp(L"ПРИВЕТ!"),cipher_error);
	}
}
SUITE(EncryptTest)
{
	TEST_FIXTURE(KeyB_fixture, UpCaseString) {
		CHECK_EQUAL("В-И-РТПЕ",
		            codec.to_bytes(p->encrypt(L"ПРИВЕТ")));
	}
	TEST_FIXTURE(KeyB_fixture, LowCaseString) {
		CHECK_EQUAL("В-И-РТПЕ",
		            codec.to_bytes(p->encrypt(L"привет")));
	}
	TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
		CHECK_EQUAL("В-И-РТПЕ",
		            codec.to_bytes(p->encrypt(L"П!РИ В Е,Т")));
	}
	TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
		CHECK_EQUAL("В-И-РТПЕ", codec.to_bytes(p->encrypt(L"ПР11И3ВЕ1Т")));
	}
	TEST_FIXTURE(KeyB_fixture, EmptyString) {
		CHECK_THROW(p->encrypt(L""),cipher_error);
	}
	TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
		CHECK_THROW(p->encrypt(L"228+614=842"),cipher_error);
	}
}
SUITE(DecryptText)
{
	TEST_FIXTURE(KeyB_fixture, UpCaseString) {
		CHECK_EQUAL("ПРИВЕТ",
		            codec.to_bytes(p->decrypt(L"В-И-РТПЕ")));
	}
	TEST_FIXTURE(KeyB_fixture, LowCaseString) {
		CHECK_THROW(p->decrypt(L"В-и-РТПЕ"),cipher_error);
	}
	TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
		CHECK_THROW(p->decrypt(L"В -И-РТПЕ"),cipher_error);
	}
	TEST_FIXTURE(KeyB_fixture, DigitsString) {
		CHECK_THROW(p->decrypt(L"В-И-54РТПЕ"),cipher_error);
	}
	TEST_FIXTURE(KeyB_fixture, PunctString) {
		CHECK_THROW(p->decrypt(L"В,-И-РТ,ПЕ"),cipher_error);
	}
	TEST_FIXTURE(KeyB_fixture, EmptyString) {
		CHECK_THROW(p->decrypt(L""),cipher_error);
	}
}
int main(int argc, char **argv)
{
	locale loc("ru_RU.UTF-8");
	locale::global(loc);
	return UnitTest::RunAllTests();
}
