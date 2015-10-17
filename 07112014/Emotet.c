#include <windows.h>
#include <stdio.h>
#include <Wininet.h>
#include <Windns.h>

/* Emotet DGA algorithm  */
/* Author: marcin.ressel@*****.com*/

typedef BOOL NTSYSAPIBOOLEAN;
typedef NTSYSAPIBOOLEAN (WINAPI *_mRtlTimeToSecondsSince1970)(PLARGE_INTEGER,PULONG);

void help(const char*);
void help(const char* path) {
     printf("Emotet DGA implementation\r\n"
            "Author: marcin.ressel@*****.com\r\n"
            "Use %s -p proxyaddress eg. xxx.xxx.xxx.xxx:8080 (oprtional)\r\n",path);     
}

unsigned long ulTimeStampOne;
unsigned long ulTimeStampTwo;
CRITICAL_SECTION criticalSection;
/*BOOL secondTimeStampInited;*/

BOOL __stdcall initFirstTimeStamp(const char*);

BOOL __stdcall initFirstTimeStamp(const char* proxy){
     register BOOL  ret  = FALSE;
     DWORD accessType = (proxy != NULL) ? INTERNET_OPEN_TYPE_PROXY : INTERNET_OPEN_TYPE_DIRECT;
     const char* pByPass = (accessType == INTERNET_OPEN_TYPE_PROXY) ? "localhost" : NULL;
     HINTERNET hInternet = InternetOpen("Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0",
                                        accessType,(LPCSTR)proxy,(LPCSTR)pByPass,0);
     if(hInternet != NULL)
     {
        DWORD dContext = 0;
        HINTERNET hUrl = InternetOpenUrl(hInternet,"http://www.microsoft.com",NULL,
                                         0,INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_AUTH | 
                                         INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_NO_CACHE_WRITE,0);
        if(hUrl != NULL) {
           DWORD oBufLen = 1024;     
           char oBuf[1024 + 1] = {0};     
           ret = HttpQueryInfo(hUrl,0x40000009,oBuf,&oBufLen,0);
           if(ret == TRUE) {
              FILETIME fTime = {0};
              SYSTEMTIME* sTime = (SYSTEMTIME*)oBuf;  
              ret = SystemTimeToFileTime(sTime,&fTime);
              if(ret == TRUE) {
                 HMODULE hLib = (HMODULE)GetModuleHandle("ntdll.dll");
                 if(hLib != NULL) {
                    _mRtlTimeToSecondsSince1970 RtlTimeSince1970 = (_mRtlTimeToSecondsSince1970)GetProcAddress(hLib,"RtlTimeToSecondsSince1970");
                    if( RtlTimeSince1970 != NULL) {
                       LARGE_INTEGER lInt = {0};
                                     lInt.LowPart  = fTime.dwLowDateTime;
                                     lInt.HighPart = fTime.dwHighDateTime;
                       ret = (RtlTimeSince1970(&lInt,&ulTimeStampOne) > 0) ? TRUE : FALSE;
                    } 
                 } 
              }    
           }
           InternetCloseHandle(hUrl);     
        }
        InternetCloseHandle(hInternet);
     }                                   
     return ret;
}

BOOL __stdcall initSecondTimeStamp(void);

BOOL __stdcall initSecondTimeStamp(void) {
     HMODULE hLib     = NULL;
     FILETIME fTime   = {0};
     SYSTEMTIME sTime = {0};
                sTime.wYear  = 0x7DE;
                sTime.wMonth = 0x0a;
                sTime.wDay   = 0x1c; 
     SystemTimeToFileTime(&sTime,&fTime);   
     hLib = (HMODULE)GetModuleHandle("ntdll.dll");
     if(hLib != NULL) {     
        _mRtlTimeToSecondsSince1970 RtlTimeSince1970 = (_mRtlTimeToSecondsSince1970)GetProcAddress(hLib,"RtlTimeToSecondsSince1970");
        if( RtlTimeSince1970 != NULL) {
            LARGE_INTEGER lInt = {0};
                          lInt.LowPart  = fTime.dwLowDateTime;
                          lInt.HighPart = fTime.dwHighDateTime;
            RtlTimeSince1970(&lInt,&ulTimeStampTwo);                 
            return TRUE;          
        }     
     }  
     return FALSE;
}

void __stdcall dgaGen(char*);

void __stdcall dgaGen(char* domout) {
     register int i;
     long int tmp1;
     unsigned long copyTSone = ulTimeStampTwo;
     unsigned long int key = 0x51eb851f;
     copyTSone++;
     copyTSone *= 0x7fed;
     copyTSone &= 0x0fffffff;
     for(i=0;i<0x10;i++) {
         unsigned char leter = 0;
         long int tmpLong    = 0;
         unsigned long long int tmp = (unsigned long long int)copyTSone * key;  
         long int tmp1 =  tmp >> 32;     /*higher part of int*/  
         tmp1 >>= 0x03;
         tmpLong = (long int)(tmp1 & 0x000000ff);
         tmp1 *= 0x0d;
         tmpLong *= 0x19;
         leter = (char)((copyTSone & 0x000000ff) - (tmpLong & 0x000000ff));
         leter += 0x61;
         domout[i] = leter;    
         copyTSone = tmp1;
     }
     strncat(domout,".eu",0x03);   /* .*/
}

void __stdcall dga(void);

void __stdcall dga(void){
     char domain[0x10 + 0x03 + 0x01] = {0};
     DNS_STATUS dnsStat = 0;
     PDNS_RECORD dnsRec = {0};
     for(;;) {
        BOOL end = FALSE;
        EnterCriticalSection(&criticalSection); 
        if(ulTimeStampTwo <= ulTimeStampOne){
           ulTimeStampTwo += 0x384;
           end = TRUE;
        }
        LeaveCriticalSection(&criticalSection); 
        if(end == FALSE) return;
        dgaGen(domain);
        dnsStat = DnsQuery(domain,0x01,0x108,0,&dnsRec,0);
        if(dnsStat == 0) break;
        EnterCriticalSection(&criticalSection);
        printf("[!]. Fake Domain %s    \r",domain);
        LeaveCriticalSection(&criticalSection);  
        memset(domain,0,sizeof(domain));     
     }
     EnterCriticalSection(&criticalSection);
     printf("[+]. Active Domain %s\r\n",domain);
     LeaveCriticalSection(&criticalSection);
     DnsRecordListFree(dnsRec,1);
}

void __stdcall spawnThreads(void);

void __stdcall spawnThreads(void){
     register unsigned int i;
     HANDLE hThreads[0x10];
     for(i=0;i<0x10;i++) {
         hThreads[i] = (HANDLE)CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)dga,NULL,0,NULL);                
     }
     WaitForMultipleObjects(0x10,hThreads,TRUE,INFINITE);
     for(i=0;i<0x10;i++) {
         CloseHandle(hThreads[i]);                    
     }
}

int main(int argc,char** argv) {
    BOOL initRet      = FALSE;
    const char* proxy = NULL;
    if(argc == 3) {
       if((argv[1][0] == '-') && (argv[1][1] == 'p')) {
           proxy = (const char*)argv[2];              
       }
    }
    InitializeCriticalSectionAndSpinCount(&criticalSection,0);
    help((const char*)argv[0]);
    initRet = initFirstTimeStamp(proxy);
    if(initRet  != FALSE) {
       printf("[+]. Init first time stamp value hex(0x%x) dec(%d)\r\n",
              ulTimeStampOne,ulTimeStampOne);   
       initRet = initSecondTimeStamp();
       if(initRet != FALSE) {
          printf("[+]. Init second time stamp value hex(0x%x) dec(%d)\r\n",
                 ulTimeStampTwo,ulTimeStampTwo);     
          printf("[+]. Run Threads !\r\n");     
          spawnThreads();
       }       
    }
    DeleteCriticalSection(&criticalSection);
    return 0;   
}
