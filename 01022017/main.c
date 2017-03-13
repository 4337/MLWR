#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

/* 
* v 1.0 (bugged)
*/

char initKey[] = {0x6b,0xea,0xf5,0x11,
                  0xdf,0x18,0x6d,0x74,
				  0xaf,0xf2,0xd9,0x30,
				  0x8d,0x17,0x72,0xe4,
				  0xbd,0xa1,0x45,0x2d,
				  0x3f,0x91,0xeb,0xde,
				  0xdc,0xf6,0xfa,0x4c,
				  0x9e,0x3a,0x8f,0x98};
				  
typedef struct {
	    char INITBUFF[256];
		unsigned char a_0x105;
	    unsigned char b_0x102;
	    unsigned char c_0x100;
	    unsigned char d_0x101;
	    unsigned char x_0x104;
	    unsigned char f_0x103;
	    unsigned int  counter;
}THEALGO,*PTHEALGO;

THEALGO DECRYPT_ENV = {0};

void decryptInitBuff(char*);
void decryptInitBuff(char* iBuff) {
	 int i;
	 for(i=0;i<256;i++) {
	 	 iBuff[i] = i;
	 }
}

void swap4(unsigned char,char*);
void swap4(unsigned char mKeyChar,char* iBuff) {
	 unsigned char a = (unsigned char)iBuff[mKeyChar];
	 unsigned char b = (unsigned char)iBuff[DECRYPT_ENV.counter];
	 iBuff[DECRYPT_ENV.counter] = a;
	 iBuff[mKeyChar] = b;
	 ++DECRYPT_ENV.counter;  //counter jest incrementowany gdzie indziej (check)
}

void set1(char*);
void set1(char* iBuff) {
	 unsigned char v1 = 0;
	 unsigned char v2 = 0;
	 unsigned char a = 0;
	 unsigned char b = 0;
	 unsigned char c = 0;
	 DECRYPT_ENV.c_0x100 += DECRYPT_ENV.a_0x105;
	 b = iBuff[DECRYPT_ENV.c_0x100];  
	 b += DECRYPT_ENV.d_0x101;
	 c = iBuff[b];
	 c += DECRYPT_ENV.b_0x102;
	 DECRYPT_ENV.d_0x101 = c;
	 a = iBuff[DECRYPT_ENV.d_0x101];
	 a += DECRYPT_ENV.b_0x102;
	 a += DECRYPT_ENV.c_0x100;
	 DECRYPT_ENV.b_0x102 = a;
	 v1 = iBuff[DECRYPT_ENV.c_0x100];
	 v2 = iBuff[DECRYPT_ENV.d_0x101];
	 iBuff[DECRYPT_ENV.c_0x100] = v2;
	 iBuff[DECRYPT_ENV.d_0x101] = v1;
}

void swap6(char*);
void swap6(char* iBuff) {
	 int i;
	 for(i=0;i<0x80;i++) {
	 	 set1(iBuff);
	 	 set1(iBuff);
	 	 set1(iBuff);
	 	 set1(iBuff);
	 }
	 DECRYPT_ENV.a_0x105 += 2;
}

void swap7(char*);
void swap7(char* iBuff) {
	int i,j = 0xff;
	unsigned char a = 0;
	unsigned char b = 0;
	for(i=0;i<0x80;i++) {
		a = iBuff[i];
		b = iBuff[j];
		if(a >= b) {
		   iBuff[i] = b;
		   iBuff[j] = a;
		}
		--j;
	}
}

void swap5(char*);
void swap5(char* iBuff) {
	 swap6(iBuff);
	 swap7(iBuff);
	 swap6(iBuff);
	 swap7(iBuff);
	 swap6(iBuff);
	 DECRYPT_ENV.x_0x104 = 0;
}

char swap3(char,char*,int);
char swap3(char mKeyChar,char* iBuff,int rIndex) {

	 int mKChar = (int)mKeyChar;
	 if(!(DECRYPT_ENV.counter != 0x80)) {
	 	swap5(iBuff);
	 } 
	 mKChar = (mKChar & 0x0000000f) + 0x80;
	 swap4(mKChar,iBuff);  //swap4
	 return (DECRYPT_ENV.counter == 1) ? initKey[DECRYPT_ENV.counter - 1] : initKey[rIndex];	
}

void swap2(char*,char*,char,int);
void swap2(char* iKey,char* iBuff,char kChar,int rIndex) {
	 int i;
	 int tKChar = kChar;
	 //finx: tKChar &= 
	 if(!((tKChar & 0x8000000f) >= 0)) {
	 	 --tKChar;
	 	 tKChar |= 0x0fffffff;
	 	 ++tKChar;
	 }
	 for(i=0;i<2;i++) {
	 	 tKChar = swap3(tKChar,iBuff,rIndex);
	 	 tKChar >>= 4;
	 }
}

void swap1(char*,char*,unsigned int);
void swap1(char* iBuff,char* iKey,unsigned int kLen) {
	 int i;
	 char kChar;
	 for(i=0;i<kLen;i++) {
	 	 kChar = iKey[i];
	 	 swap2(iKey,iBuff,kChar,i);
	 } 
}


unsigned char getXorVal(char*);
unsigned char getXorVal(char* iBuff) {
	     unsigned char a = 0;
	     unsigned char b = 0;
	     if(DECRYPT_ENV.x_0x104 != 0) {
	     	swap5(iBuff);
		 }
		 set1(iBuff);
		 a = DECRYPT_ENV.b_0x102;
		 b = DECRYPT_ENV.f_0x103;
		 a += b;  
		 //prawdopodobnie powinno byc tak (int)a &= 0x800000ff 
		 if(!((int)a & 0x800000ff) >= 0) {
	 	     --a;
	 	     a |= 0xffffff00;
	 	     ++a;
	     }
	     a = iBuff[a];
	     a += DECRYPT_ENV.c_0x100;
	     if(!((int)a  & 0x800000ff) >= 0) {
	 	     --a;
	 	     a |= 0xffffff00;
	 	     ++a;
	     }
	     a = iBuff[a];
	     a += DECRYPT_ENV.d_0x101;
	     if(!((int)a  & 0x800000ff) >= 0) {
	    	 --a;
	 	     a |= 0xffffff00;
	 	     ++a;
	     }
	     a = iBuff[a];
	     DECRYPT_ENV.f_0x103 = a;
	     return a;
}      

void decrypt(char*,char*,unsigned int);
void decrypt(char* encData,char* iBuff,unsigned int encLen) {
	 unsigned int i;
	 unsigned char rKeyChar = 0;
	 for(i=0;i<encLen;i++) {
	 	 rKeyChar = getXorVal(iBuff);
	 	 rKeyChar ^= encData[i]; //niezależnie od długości klucza mamy 256 możliwości + 256 / 2 w przypadku signed char, taka sytuacja
	 	 encData[i] = rKeyChar;  //ofc jako ortodox nieużywam hexrejsów czy innego softu dla ekspertów. Wniosek jest taki że nie ma żadnych wniosków :)
	 	// printf("0x%02x ",(unsigned char)encData[i]);  //poza tym że bruteforece dla ~rc4 to char ^= encDtata[len(encData)], niby banał, ale jak bardzo jest istotne to czego szukamy
		 //                                                np. w przypadku gdy jesteśmy pewni że szukamy tekstów alfa-numerysznych (pisanych) zakres można zawęzić, co i tak daje tyle możliwości że 
	         //                                                że dla współczensych koputerów kryptigrafia staje się ciekawa ? 
	 }
}

void printme(char*,int);
void printme(char* data,int len) {
	 int i;
	 for(i=0;i<len;i++) {
	 	 printf("0x%02x ",(unsigned char)data[i]);
	 }
}

void decryptMain(char*,char*,unsigned int,unsigned int);
void decryptMain(char* encData,char* initKey,unsigned int encLen,unsigned int iKeyLen) {
	 DECRYPT_ENV.a_0x105 = 1;
	 decryptInitBuff(DECRYPT_ENV.INITBUFF);
	 swap1(DECRYPT_ENV.INITBUFF,initKey,32);
	 if(DECRYPT_ENV.counter != 0) {
	 	swap5(DECRYPT_ENV.INITBUFF);
	 }
	 decrypt(encData,DECRYPT_ENV.INITBUFF,encLen);
	 //...
}


typedef struct {
	    HANDLE hFile;
	    CHAR*  encBuff;
	    DWORD  fSize;
}ENV,*PENV;


int help(void);
int help(void) {
	 printf("[+] use prog.exe P:/ath/2/encrypted/file\r\n");
	 return -1;
}

BOOL initEnv(ENV*,CONST CHAR*);
BOOL initEnv(ENV* rEnv,CONST CHAR* fPath) {
	         rEnv->hFile = CreateFile(fPath,GENERIC_READ,FILE_SHARE_READ,NULL,
			                         OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	         if(rEnv->hFile != INVALID_HANDLE_VALUE) {
	         	rEnv->fSize = GetFileSize(rEnv->hFile,NULL);
	         	if(rEnv->fSize != INVALID_FILE_SIZE) {
				   rEnv->encBuff = (CHAR*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,rEnv->fSize + 1); 
				   if(rEnv->encBuff != NULL) return TRUE;
				}
			 }
			 return FALSE;
}

VOID clearEnv(ENV*);
VOID clearEnv(ENV* rEnv) {
	 if((rEnv->hFile != NULL) && 
	    (rEnv->hFile != INVALID_HANDLE_VALUE)) {
	     CloseHandle(rEnv->hFile);
		 rEnv->hFile = NULL;  	
	  }
	  if(rEnv->encBuff != NULL) {
	  	 HeapFree(GetProcessHeap(),HEAP_ZERO_MEMORY,rEnv->encBuff);
	  }	
}

int main(int argc, char *argv[]) {
    int ret = -1;
  	ENV RT_Env = {0};
	if(argc < 2) return help();
	if(initEnv(&RT_Env,argv[1])) {
	   printf("[+] Encrypted file : %s\r\n"
	          "[+] File size : %d (0x%02x)\r\n",argv[1],RT_Env.fSize,RT_Env.fSize);	
	   if(!ReadFile(RT_Env.hFile,RT_Env.encBuff,RT_Env.fSize,NULL,NULL)) {
	   	  printf("[-] ReadFile error !\r\n");
	   } else {
	   	 UINT pLen = (UINT)strlen(argv[1]);
	   	      pLen += 10;
	   	 CHAR* dcFile = (CHAR*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,pLen); 
	   	 if(dcFile == NULL) {
            printf("[-] Write 2 file HeapAlloc error!\r\n");
         } else {
		    HANDLE outFile = NULL;
	   	    strncpy(dcFile,argv[1],pLen - 10);  
	   	    strcat(dcFile,".out");
	 	    outFile = CreateFile(dcFile,GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL ,NULL);
	 	    if(outFile == INVALID_HANDLE_VALUE) {
	 	       printf("[-] Write 2 file CreateFile error!\r\n");
			 } else {
		        printf("[+] Decrypting\r\n");
	   	        decryptMain(RT_Env.encBuff,initKey,RT_Env.fSize,32);
	   	        if(WriteFile(outFile,RT_Env.encBuff,RT_Env.fSize,NULL,NULL)) ret = 0; 
				else {
					printf("[-] Write 2 file WriteFile error!\r\n");
				} 
			    printf("[+] Out file : %s (binary file so open in hex-editor)\r\n",dcFile);
				CloseHandle(outFile);
	   	    }
	   	    HeapFree(GetProcessHeap(),HEAP_ZERO_MEMORY,dcFile);
	     }
	   }
	   clearEnv(&RT_Env);
	} else {
	  printf("[+] Ivalid file !\r\n");	
	}
	return ret;
}
