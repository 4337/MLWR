#include <stdio.h>   
#include <stdlib.h>
#include <memory.h>
/* Emotet Trojan IP CC Decryptor marcin.ressel@****.com */
/*
$ ==>    >0A 4E 7B 6D AC 33 36 42  .N{m?36B
$+8      >67 80 A1 6C ED 1D D2 C3  g??l????

$+10     >2E F9 23 05 C3 39 9F 05  .?#??9??
$+18     >AF 46 D2 CE 8B BB 50 58  ?F???PX

$+20     >88 AE 5D BC 07 03 85 82  ??]?????
$+28     >C0 4F 90 A2 CF 5A 6E 4F  ?O???ZnO

$+30     >11 CC 12 48 6E 0D 81 D4  ???Hn.??
$+38     >F8 3D E4 42 35 98 AB C1  ?=?B5???

$+40     >ED FE BB 81 76 C8 F8 B2  ????v???
$+48     >B6 13 F2 85 ED F3 9A C3  ????????

$+50     >4D 85 ED 50 A3 EE FF 9E  M??P????
$+58     >C0 AE C6 5B 12 EC 69 2E  ???[??i.

$+60     >69 8B BA CD 75 31 0A 48  i???u1.H
$+68     >DD 36 F2 85 62 42 01 C6  ?6??bB??

$+70     >6B 0B FB 94 6E 9A D0 D5  k???n???
$+78     >CF 56 FB 94 16 01 4D D4  ?V????M?
*/
#pragma comment(lib,"msvcrt.lib")
int i = 0;
char url_buff[0x100 + 1] = {0};     //0x100
unsigned int val_array[0x1e + 4] = {
                       0x0a4e7b6d,0xac333642,0x6780a16c,0xed1dd2c3,
                       0x2ef92305,0x3c399f05,0xaf46d2ce,0x8bbb5058,
                       0x88ae5dbc,0x07038582,0xc04f90a2,0xcf5a6e4f,
                       0x11cc1248,0x6e0d81d4,0xf83de442,0x3598abc1,
                       0xedfebb81,0x76c8f8b2,0xb613f285,0xedf39ac3,
                       0x4d85ed50,0xa3eeff9e,0xc0aec65b,0x12ec692e,
                       0x698bbacd,0x75310a48,0xdd36f285,0x624201c6,
                       0x6b0bfb94,0x6e9ad0d5,0xcf56fb94,0x16014dd4
                       };    //120b

#define PORT 8080

void generate_url() {
    unsigned int tmp = 0;
    unsigned char last_octet,fri_octet,sec_octet,first_octet;
     for(i=0;i<0x1e;i++) {
         unsigned int xor_value_1 = 0x85e66417;
         unsigned int array_val   = val_array[i];
         int subdir2     = xor_value_1 ^ 0x47738654;
         int subdir1     = xor_value_1;
         last_octet    = (unsigned char)array_val & 0x000000ff;
         tmp = array_val >> 0x08;
         fri_octet = (unsigned char)tmp & 0x000000ff;
         tmp = array_val >> 0x10; 
         sec_octet = (unsigned char)tmp & 0x000000ff;    
         tmp = array_val >> 0x10;
         tmp >>= 0x08;
         first_octet  = (unsigned char)tmp & 0x000000ff;
        _snprintf(url_buff,0x100,"http://%u.%u.%u.%u:%u/%x/%x/",last_octet,fri_octet,sec_octet,first_octet,
                                                                (unsigned int)PORT,subdir1,subdir2);
         //if(chck_connect(ip_buff) == SUCCESS) break;
         printf("Url <%d> : %s\r\n ",i,url_buff);
     }
     i=0;
}

int __cdecl main(void) {
     generate_url();
return 0;
}