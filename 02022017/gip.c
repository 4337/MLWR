#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <Windns.h>
/* run this program using the console pauser or add your own getch, system("pause") or input loop */
#define DNS_NAME "tradeboard.mefound.com:433"

//Nie mog� skompilowa� bo dev c++ x64 nie ma statycznej biblioteki 
//a niechce mi si� via LoadLibrary...

BOOL hProxy = FALSE;  //W �rodowiskach korpo proxy to w�a�ciwie standard wi�c warto�� tej flagi b�dzie wynosi� TRUE
                      //w innych �rodowiskach np. analitycznych ju� niekonicznie 
unsigned short getPortFromAddr(char*);
unsigned short getPortFromAddr(char* addr) {
	     char* ptr = addr;
	     while(*ptr++ != ':');
	     *(ptr - 1) = '\0';
	     unsigned short ret = (unsigned short)strtoul(ptr,NULL,0);
	     return ret;
}

int main(int argc, char *argv[]) {
	
	char name[256+1] = {0};
	PDNS_RECORD dnsOut = NULL;
	
	strncpy(&name[0],(char*)DNS_NAME,256);
	
	dnsOut = (PDNS_RECORD)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(DNS_RECORD));	
	if(dnsOut != NULL) {
	   DWORD ip = 0;
	   unsigned short port = getPortFromAddr(name);	
	   if( DNSQuery(name, 0x01, 0x08, NULL,&dnsOut,NULL) ) {
	   	   ip = dnsOut->Data.A.IpAddress;
	   	   if(hProxy == FALSE) {    //je�li trojan nie wykryje ustawie� proxy w systemie 
	   	      ip ^= 0x4F833D5B;	    //xoruje uzyskany z serwer�w dns adres IP
		   }                        //nast�pnie ta warto�� b�dzie wykorzystana w strukturze IN_ADDR przy nawi�zywaniu po��czenia (bez proxy)
		   DnsRecordListFree(dnsOut,1); //w przeciwynym wypadku uzyskany adres poprostu nie b�dzie modyfikowany 
		   HeapFree(GetProcessHeap(),HEAP_ZERO_MEMORY,dnsOut);
		   dnsOut = NULL;
	   }
	}
	
	return 0;

}
