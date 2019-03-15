#include "HexStrings.h"
#include "BigStorm.h"
#include "SRP3.h"


int main(void) {
	unsigned char ClientK[40]; memset(ClientK, 0, 40);
	unsigned char ServerK[40]; memset(ServerK, 0, 40);

	char Username[] = "Srp3Test";
	char Password[] = "asdfasdf";
	BYTE salt[BIGINT_SIZE]; memset(salt, 0, BIGINT_SIZE);
	BYTE verify[BIGINT_SIZE]; memset(verify, 0, BIGINT_SIZE);

  HexToString((const UCHAR *)"81FED8FA060B290EEADB5932A1EDFB8BA5EB3958B6942AA5BD6D358BCBB36F35", 64, salt);
  HexToString((const UCHAR *)"C89ACC7D299403E935C179EB9F1BF8D3140F987E10EA3CD5E6CF2A56CE3DA382", 64, verify);

	SRP3 Client(Username, Password, NULL);
	SRP3 Server(Username, NULL, salt, verify); //server knows s, v upon creation.

	BigStorm A = Client.GetClientSessionPublicKey();
	A.class_name("C: Client A");
	Client.SetClientA(A);
	A.class_name("S: Client A");
	Server.SetClientA(A);
	BigStorm B = Server.GetServerSessionPublicKey();
	Client.SetSalt(salt);
	B.class_name("S: Client B");
	Server.SetServerB(B);
	B.class_name("C: Client B");
	Client.SetServerB(B);

	Client.GetHashedClientSecret(ClientK);
	Server.GetHashedServerSecret(ServerK);

	std::string outdata = "";
	StringToHex(ClientK, 40, outdata);
	printf_s("client k: %s\n", outdata.c_str());
	StringToHex(ServerK, 40, outdata);
	printf_s("server k: %s\n", outdata.c_str()); //Not sure if bugged or if this is what it really should be lol....

	system("pause");


  return 1;
}
