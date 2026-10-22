Hello mọi người hôm nay mình sẽ đi phân tích bài ransomware palimpsest nhé!

Mô tả đề bài(README.md):
![image](https://hackmd.io/_uploads/BkH8o1v3zl.png)

Mục tiêu của mình là khôi phục service đã bị ransomware mã hóa

Đầu tiên mình sẽ đi reverse file ransomware binary nhé!
Thông tin cơ bản của file:
![image](https://hackmd.io/_uploads/Hyq-a1vnze.png)

Đi vào phân tích hàm main(sub_400CFA) nhé:
![image](https://hackmd.io/_uploads/HJRNayw3fl.png)

Đầu tiên chương trình sẽ check id xem có chạy root hay không, check biến PALIMPSEST_ALLOW_NON_ROOT có được khởi tạo hay không, nếu 1 trong 2 điều kiện trên không thỏa mãn => in “palimpsest: error: root privileges required (please run with sudo)\n”

Tiếp theo ở Label 17 chứa hàm sub_400896 chỉ cách sử dụng của file này:
- in ./palimpsest identity xuất ra binary data là PALID2 
- in ./palimpsest profile xuất ra binary data là PALHOST1
- in ./palimpsest encrypt <manuscript.svg> <absolute-target>: nhận input mã hóa là file .svg, chỉ đường dẫn tuyệt đối, đọc 48-byte ở frame của PRI1 

Hàm so sánh identity, profile, encrypt với các hàm tương ứng là sub_4008F1, sub_4008F1 và sub_400A95.

Đầu tiên mình sẽ đi xem hàm so sánh identity trước nhé:
    
#sub_4008f1:
```
_BOOL8 sub_4008F1()
{
  size_t v1; // rax
  bool v2; // [rsp+7h] [rbp-819h]
  size_t n; // [rsp+8h] [rbp-818h] BYREF
  _BYTE ptr[2056]; // [rsp+10h] [rbp-810h] BYREF
  unsigned __int64 v5; // [rsp+818h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  n = 0;
  if ( (unsigned __int8)sub_4062BD(ptr, 0x800u, (__int64 *)&n) != 1 )
    return 1;
  v1 = fwrite(ptr, 1u, n, stdout);
  v2 = v1 == n;
  OPENSSL_cleanse(ptr, 2048);
  return !v2;
}
```
    
Ở đầu ta có thể thấy hàm này nó cấp phát stack 2056 byte(ptr) kèm theo stack canary chống bị khai thác qua buffer overflow(https://www.sans.org/blog/stack-canaries-gingerly-sidestepping-the-cage). sub_4062BD đọc 2048 byte(0x800), lưu vào ptr, check kích thước data qua n, nếu khác 1 báo lỗi. Hàm sài stdout in dữ liệu ra ngoài màn hình, rồi cuối cùng dọn 2048 đã lưu vào stack của ptr trước đó.

#sub_4062BD:
```
__int64 __fastcall sub_4062BD(void *a1, unsigned __int64 a2, __int64 *a3)
{
  __int64 v5; // [rsp+28h] [rbp-218h] BYREF
  char v6[128]; // [rsp+30h] [rbp-210h] BYREF
  char v7[128]; // [rsp+B0h] [rbp-190h] BYREF
  char v8[128]; // [rsp+130h] [rbp-110h] BYREF
  char v9[136]; // [rsp+1B0h] [rbp-90h] BYREF
  unsigned __int64 v10; // [rsp+238h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  if ( !a1 || !a3 || a2 <= 7 )
    return 0;
  if ( geteuid() && !getenv("PALIMPSEST_ALLOW_NON_ROOT") )
    return 0;
  sub_40604E(v7);
  sub_4060A3(v6);
  sub_4060DF(v8, v7);
  sub_405E54(v9);
  if ( !v6[0] || !v7[0] || !v8[0] || !v9[0] )
    return 0;
  memcpy(a1, "PALID2", 8u);
  v5 = 8;
  if ( (unsigned __int8)sub_4061C2((__int64)a1, a2, &v5, 1, v6) != 1
    || (unsigned __int8)sub_4061C2((__int64)a1, a2, &v5, 2, v7) != 1
    || (unsigned __int8)sub_4061C2((__int64)a1, a2, &v5, 3, v8) != 1
    || (unsigned __int8)sub_4061C2((__int64)a1, a2, &v5, 4, v9) != 1 )
  {
    return 0;
  }
  *a3 = v5;
  return 1;
}
```
Hàm đầu tiên sẽ check xem lên đã root chưa, chưa thì báo lỗi 0
Từng hàm nhỏ sẽ chưa một thông tin cần lấy trên máy victim lưu vào ptr:
- sub_40604E:đọc product_uuid hoặc k đc uuid thì đọc machine-id
![image](https://hackmd.io/_uploads/SyiNegw3fe.png)
                           
- sub_4060A3: đọc machine id 
![image](https://hackmd.io/_uploads/HyFIggP2fx.png)
                          
- sub_4060DF: đọc device serial
![image](https://hackmd.io/_uploads/HkcPlewnMg.png)
                           
- sub_405E54: đọc MAC address của card mạng
![image](https://hackmd.io/_uploads/SkMFegD2Ml.png)
                           
Nếu thông tin 1 trong 4 hàm đó bị rỗng thì báo lỗi 0. Sau khi không lỗi gì thì hàm ghi PALID2 vào đầu ptr cho đủ 2056 byte trong stack để làm file signature nối identity kiểu: `PALID2||machine-id ||product_uuid||device serial||MAC address` vào v5, lưu v5 trỏ a3 rồi thì báo thành công

Tiếp đến sẽ là bên encrypt
#sub_400A95:
```
__int64 __fastcall sub_400A95(const char *a1, __int64 a2, size_t a3)
{
  bool v4; // al
  bool v6; // [rsp+29h] [rbp-1037h]
  bool v7; // [rsp+2Ah] [rbp-1036h]
  bool v8; // [rsp+2Bh] [rbp-1035h]
  unsigned int v9; // [rsp+2Ch] [rbp-1034h]
  char v10[272]; // [rsp+30h] [rbp-1030h] BYREF
  _BYTE s[480]; // [rsp+140h] [rbp-F20h] BYREF
  __int64 v12; // [rsp+320h] [rbp-D40h] BYREF
  void *v13[398]; // [rsp+390h] [rbp-CD0h] BYREF
  _BYTE v14[32]; // [rsp+1000h] [rbp-60h] BYREF
  _BYTE v15[4]; // [rsp+1020h] [rbp-40h] BYREF
  _BYTE v16[60]; // [rsp+1024h] [rbp-3Ch] BYREF

  *(_QWORD *)&v16[52] = __readfsqword(0x28u);
  if ( (unsigned __int8)sub_400826((__int64)v15, 0x30u) != 1 )
  {
    fwrite("The manuscript remains sealed.\n", 1u, 0x1Fu, stderr);
    return 2;
  }
  else
  {
    v7 = sub_402AEE(a1, (__int64)v13);
    v4 = v7 && sub_400FD8((__int64)v13, (__int64)v14);
    v8 = v4;
    v6 = 0;
    if ( v4 && !(unsigned int)CRYPTO_memcmp(v15, "PRI1", 4) )
    {
      memset(s, 0, 0x248u);
      sub_40564C(v10);
      if ( sub_4040D6((__int64)v13, (__int64)v10, 0, 0, (__int64)s) )
        v6 = (unsigned int)CRYPTO_memcmp(&v12, v16, 32) == 0;
      sub_404C58((__int64)s);
      OPENSSL_cleanse(v10, 272);
    }
    if ( v7 )
      sub_400F1B(v13);
    if ( v8 && v6 )
      v9 = sub_4073F0(a2, a3, (__int64)v15, v14);
    else
      v9 = 2;
    OPENSSL_cleanse(v15, 48);
    OPENSSL_cleanse(v14, 32);
    if ( v9 )
      fwrite("The manuscript remains sealed.\n", 1u, 0x1Fu, stderr);
    return v9;
  }
}
```  
Đầu tiên hàm sẽ gọi hàm sub_400826 để check 48 byte, nếu thiếu thì in ra “The manuscript remains sealed.\n “ và trả mã lỗi 2, đủ thì lưu 48 byte vào v15. Sau đó hàm dùng hàm sub_402AEE để đưa data file manuscript.svg từ a1 vào v13 rồi dùng sub_400FD8 để trích xuất dữ liệu từ .svg file.Rồi hàm check 4 byte đầu của 48 byte có phải `PRI1` không, nếu có thì khởi tạo v10 lưu dữ liệu của  sub_40564C, sau đó truyền v13,v10 vào sub_4040D6. Rồi hàm so sánh kết quả mã hóa gồm 32 byte của v12(EVP_sha256 trong sub_4040D6) với 32 byte của v16(hash nội bộ) để check xem file .svg hợp lệ không. Nếu oke hết dọn dẹp data của v10 cùng với việc gọi sub_400F1B để nhận data file từ v13 để dọn dẹp.sub_400F1B nhận data file từ v13 để dọn dẹp. Nếu phần so sánh oke thì gọi sub_4073F0 xử lý file ở đường dẫn tuyệt đối, không thì chỉnh v9 với mã lỗi 2 , rồi in ra : "The manuscript remains sealed.\n". Cuối cùng nó dọn 48 byte ở v15 và 32 byte ở v14 thôi.

#sub_402AEE:
```
_BOOL8 __fastcall sub_402AEE(const char *a1, __int64 a2)
{
  bool v3; // al
  bool v4; // al
  bool v5; // [rsp+16h] [rbp-10Ah]
  char v6; // [rsp+17h] [rbp-109h]
  int j; // [rsp+18h] [rbp-108h]
  int v8; // [rsp+1Ch] [rbp-104h]
  __int64 v9; // [rsp+20h] [rbp-100h] BYREF
  size_t i; // [rsp+28h] [rbp-F8h]
  size_t nmemb; // [rsp+30h] [rbp-F0h]
  void *ptr; // [rsp+38h] [rbp-E8h]
  __int64 File; // [rsp+40h] [rbp-E0h]
  __int64 RootElement; // [rsp+48h] [rbp-D8h]
  char *v15; // [rsp+50h] [rbp-D0h]
  __int64 v16; // [rsp+58h] [rbp-C8h]
  struct stat buf; // [rsp+60h] [rbp-C0h] BYREF
  _BYTE s1[8]; // [rsp+F0h] [rbp-30h] BYREF
  __int16 v19; // [rsp+F8h] [rbp-28h]
  __int16 v20; // [rsp+FAh] [rbp-26h]
  char v21; // [rsp+FCh] [rbp-24h]
  unsigned __int64 v22; // [rsp+118h] [rbp-8h]

  v22 = __readfsqword(0x28u);
  if ( !a1 || !a2 )
    return 0;
  memset((void *)a2, 0, 0xC68u);
  if ( stat(a1, &buf) || buf.st_size <= 0 || buf.st_size > 0x800000uLL )
    return 0;
  if ( (unsigned __int8)sub_32533BC((_QWORD *)a2) != 1 )
    return 0;
  nmemb = *(unsigned __int8 *)(a2 + 5) * (unsigned __int64)*(unsigned __int8 *)(a2 + 6);
  ptr = calloc(nmemb, 0xCu);
  if ( ptr )
  {
    File = xmlReadFile((__int64)a1, 0, 67680);
    if ( !File || *(_QWORD *)(File + 80) || *(_QWORD *)(File + 88) )
    {
      if ( File )
        xmlFreeDoc(File);
      free(ptr);
      sub_400F1B((void **)a2);
      return 0;
    }
    else
    {
      RootElement = xmlDocGetRootElement(File);
      v9 = 0;
      v3 = RootElement
        && !strcmp(*(const char **)(RootElement + 16), "svg")
        && (unsigned __int8)sub_4028FA(RootElement, a2, (__int64)ptr, &v9);
      v5 = v3;
      if ( v3 )
      {
        *(_QWORD *)(a2 + 64) = calloc(nmemb, 0xCu);
        v5 = *(_QWORD *)(a2 + 64) != 0;
      }
      for ( i = 0; v5 && i < nmemb; ++i )
      {
        v15 = (char *)ptr + 12 * i;
        if ( *(_WORD *)v15 != 511 )
        {
          v5 = 0;
          break;
        }
        v8 = ((unsigned __int8)v15[7] << 18) & 0xC0000
           | (((unsigned __int8)(16 * v15[5]) | v15[6] & 0xF) << 10)
           | ((unsigned __int8)v15[4] << 7) & 0x380
           | (16 * v15[3]) & 0x70
           | v15[2] & 0xF
           | ((unsigned __int8)v15[8] << 20) & 0xF00000;
        v6 = (16 * v15[9]) | v15[10];
        for ( j = 0; j <= 7; ++j )
          s1[j] = *(_QWORD *)(a2 + 40) >> (8 * (unsigned __int8)j);
        v19 = i;
        v20 = v8;
        v21 = BYTE2(v8);
        if ( v6 != (unsigned __int8)sub_400EAF((__int64)s1, 0xDu) )
        {
          v5 = 0;
          break;
        }
        v16 = *(_QWORD *)(a2 + 64) + 12 * i;
        *(_BYTE *)v16 = v15[2];
        *(_BYTE *)(v16 + 1) = v15[3];
        *(_BYTE *)(v16 + 2) = v15[4];
        *(_BYTE *)(v16 + 3) = (16 * v15[5]) | v15[6];
        *(_BYTE *)(v16 + 4) = v15[7];
        *(_BYTE *)(v16 + 5) = v15[8];
        *(_BYTE *)(v16 + 6) = v6;
        *(_DWORD *)(v16 + 8) = v8;
      }
      if ( v5 )
      {
        v4 = sub_400FD8(a2, (__int64)s1) && !memcmp(s1, &unk_3255400, 0x20u);
        v5 = v4;
      }
      xmlFreeDoc(File);
      free(ptr);
      if ( !v5 )
        sub_400F1B((void **)a2);
      return v5;
    }
  }
  else
  {
    sub_400F1B((void **)a2);
    return 0;
  }
}
```                           
Hàm này bắt đầu với việc check dung lượng file với điều kiện: 0 <=  file < 8mb. Nếu pass rồi thì nó gọi hàm  sub_32533BC để khởi tạo config cho a1.Rồi nó check file xem có phải là file svg hợp lệ không
- Nó gọi hàm sub_4028FA dùng scan cấu trúc file:
+) check a4( số node đã quét) nếu >0x4E20 thì sẽ bị nghi là bị ddos trả lập tức trả mã lỗi 0
+) check nếu đúng file xml thì bắt đầu lọc xem có phải polygon,circle,rect,line hay svg/g không,nếu không thì nó trả mã lỗi 0, rồi nếu oke thì nó duyệt đệ quy cây XML
    
Tiếp đến nó tiến hành giải mã bằng bitwise, checksum bằng sub_400EAF(sài CRC-8(https://docs.mtoolstec.com/software-and-apps/mtools-app/crc-8-and-crc-16) ) so với v6, nếu lệch thì cho v5 = 0, rồi cuối nó lại sài sub_400FD8, so sánh 0x20 byte  s1 từ sub_400EAF với 0x20 byte unk_3255400  (chữ ký mẫu trong program)

#sub_40564C 
Hàm này đơn giản chỉ là xóa sạch data tại a1, sau đó đọc dòng chip phần cứng đang chạy(AMD/intel) đưa vào v2 rồi dùng sub_404FA4 làm sạch để đưa vào a1, rồi đưa thêm vào a1 system config, system info, serial máy và mac address  

#sub_4040D6 
```
bool __fastcall sub_4040D6(__int64 a1, __int64 a2, int a3, const void *a4, __int64 a5)
{
  __int64 v6; // rax
  char v7; // al
  char *v8; // rax
  char v9; // al
  char v10; // al
  char v11; // al
  __int64 v12; // rax
  __int64 v13; // rbx
  __int64 v14; // rbx
  __int64 v15; // rbx
  __int64 v16; // rbx
  __int64 v17; // rdx
  __int64 v18; // rdx
  char v22; // [rsp+30h] [rbp-2D0h]
  unsigned __int8 i; // [rsp+31h] [rbp-2CFh]
  unsigned __int8 j; // [rsp+32h] [rbp-2CEh]
  char v25; // [rsp+34h] [rbp-2CCh]
  unsigned __int8 v26; // [rsp+35h] [rbp-2CBh]
  unsigned __int8 v27; // [rsp+36h] [rbp-2CAh]
  unsigned __int8 v28; // [rsp+37h] [rbp-2C9h]
  unsigned __int8 v29; // [rsp+38h] [rbp-2C8h]
  unsigned __int8 v30; // [rsp+39h] [rbp-2C7h]
  unsigned __int8 v31; // [rsp+3Ah] [rbp-2C6h]
  char v32; // [rsp+3Bh] [rbp-2C5h]
  int v33; // [rsp+3Ch] [rbp-2C4h] BYREF
  int v34; // [rsp+40h] [rbp-2C0h] BYREF
  int v35; // [rsp+44h] [rbp-2BCh] BYREF
  unsigned int v36; // [rsp+48h] [rbp-2B8h]
  int k; // [rsp+4Ch] [rbp-2B4h]
  unsigned int v38; // [rsp+50h] [rbp-2B0h]
  unsigned int v39; // [rsp+54h] [rbp-2ACh]
  __int64 v40; // [rsp+58h] [rbp-2A8h]
  char *v41; // [rsp+60h] [rbp-2A0h]
  unsigned __int8 *v42; // [rsp+68h] [rbp-298h]
  __int64 v43; // [rsp+74h] [rbp-28Ch] BYREF
  unsigned int v44; // [rsp+7Ch] [rbp-284h]
  _QWORD v45[4]; // [rsp+80h] [rbp-280h] BYREF
  __int64 v46; // [rsp+A0h] [rbp-260h] BYREF
  __int64 v47; // [rsp+A8h] [rbp-258h]
  char src; // [rsp+C0h] [rbp-240h] BYREF
  unsigned __int8 v49; // [rsp+C1h] [rbp-23Fh]
  char v50; // [rsp+C2h] [rbp-23Eh]
  char v51; // [rsp+C3h] [rbp-23Dh]
  char v52; // [rsp+C4h] [rbp-23Ch]
  unsigned __int8 v53; // [rsp+C5h] [rbp-23Bh]
  unsigned int v54; // [rsp+26Ch] [rbp-94h]
  __int64 v55; // [rsp+270h] [rbp-90h]
  char v56; // [rsp+278h] [rbp-88h]
  char v57; // [rsp+279h] [rbp-87h]
  char v58; // [rsp+27Ah] [rbp-86h]
  _QWORD v59[4]; // [rsp+280h] [rbp-80h] BYREF
  _QWORD v60[8]; // [rsp+2A0h] [rbp-60h] BYREF
  char v61; // [rsp+2E0h] [rbp-20h]
  unsigned __int64 v62; // [rsp+2E8h] [rbp-18h]

  v62 = __readfsqword(0x28u);
  if ( !a1 || !a5 )
    return 0;
  memset((void *)a5, 0, 0x248u);
  v40 = a1;
  sub_403313(&src, a1, a3, a4);
  sub_4030D9(v45);
  sub_4030D9(&v46);
  sub_403107((__int64)&v46, "PALSEAL2", 8u);
  sub_403296(&v46, *(_QWORD *)(a1 + 40));
  sub_4031FF((__int64)&v46, *(_BYTE *)(a1 + 5));
  sub_4031FF((__int64)&v46, *(_BYTE *)(a1 + 6));
  sub_4031FF((__int64)&v46, a3);
  v22 = 0;
  while ( !v56 )
  {
    if ( v54 >= *(_DWORD *)(v40 + 16) )
    {
      v22 = 1;
      break;
    }
    v57 = 0;
    v38 = *(unsigned __int8 *)(v40 + 5) * v49 + (unsigned __int8)src;
    v6 = *(_QWORD *)(a1 + 64) + 12LL * v38;
    v43 = *(_QWORD *)v6;
    v44 = *(_DWORD *)(v6 + 8);
    v36 = v44;
    if ( *(_BYTE *)(a1 + 3168) )
    {
      for ( i = 0; i < *(_BYTE *)(a1 + 3168); ++i )
      {
        if ( v38 == *(unsigned __int16 *)(16LL * i + *(_QWORD *)(a1 + 3160)) )
        {
          if ( (((int)v53 >> i) & 1) != 0 )
            v36 = *(_DWORD *)(16LL * i + *(_QWORD *)(a1 + 3160) + 8) & 0xFFFFFF;
          else
            v36 = *(_DWORD *)(16LL * i + *(_QWORD *)(a1 + 3160) + 4) & 0xFFFFFF;
          break;
        }
      }
    }
    v25 = v36 & 0xF;
    v26 = (v36 >> 4) & 7;
    v27 = (v36 >> 7) & 7;
    v28 = v36 >> 10;
    v29 = (v36 >> 18) & 3;
    v30 = (v36 >> 20) & 0xF;
    v41 = (char *)(48LL * (v36 & 0xF) + 768LL * (v51 & 1) + 1536LL * (v52 & 1) + 64 + a1 + 8);
    v7 = *v41;
    if ( (unsigned __int8)*v41 > 3u )
      v7 = 3;
    v31 = v7;
    sub_403229(&v46, v54);
    sub_4031FF((__int64)&v46, src);
    sub_4031FF((__int64)&v46, v49);
    sub_4031FF((__int64)&v46, v50);
    sub_4031FF((__int64)&v46, v51);
    sub_4031FF((__int64)&v46, v52);
    sub_4031FF((__int64)&v46, v53);
    sub_4031FF((__int64)&v46, v25);
    sub_4031FF((__int64)&v46, v31);
    for ( j = 0; j < v31; ++j )
    {
      v8 = &v41[12 * j];
      v42 = (unsigned __int8 *)(v8 + 4);
      v32 = v8[4];
      v33 = -1;
      v34 = -1;
      v35 = -1;
      sub_403490((unsigned __int8)v8[5], v26, v27, &v33);
      sub_403490(v42[2], v26, v27, &v34);
      sub_403490(v42[3], v26, v27, &v35);
      v39 = sub_40351A(v42[4], *((unsigned int *)v42 + 2), v28, v30, v29);
      sub_4031FF((__int64)&v46, v32);
      v9 = v33 < 0 ? -1 : v33;
      sub_4031FF((__int64)&v46, v9);
      v10 = v34 < 0 ? -1 : v34;
      sub_4031FF((__int64)&v46, v10);
      v11 = v35 < 0 ? -1 : v35;
      sub_4031FF((__int64)&v46, v11);
      sub_403229(&v46, v39);
      sub_4031FF((__int64)&v46, v42[5]);
      sub_3253189((unsigned __int8 *)&src, *v42, v33, v34, v35, v39, v42[5], a1, a2, (__int64)v45);
      if ( v58 || v56 )
        break;
    }
    if ( v58 )
    {
      v22 = 2;
      break;
    }
    v51 ^= v41[1] & 1;
    if ( !v56 && !v57 )
    {
      if ( v41[2] )
      {
        if ( v41[2] != 1 )
        {
          if ( v41[2] != 2 )
          {
            v58 = 1;
            v22 = 2;
            break;
          }
          sub_4035DB(&src, *(unsigned __int8 *)(v40 + 5), *(unsigned __int8 *)(v40 + 6), 2);
        }
      }
      else
      {
        sub_4035DB(&src, *(unsigned __int8 *)(v40 + 5), *(unsigned __int8 *)(v40 + 6), 1);
      }
    }
    sub_4031FF((__int64)&v46, src);
    sub_4031FF((__int64)&v46, v49);
    sub_4031FF((__int64)&v46, v50);
    sub_4031FF((__int64)&v46, v51);
    sub_4031FF((__int64)&v46, v52);
    sub_4031FF((__int64)&v46, v53);
    sub_4031FF((__int64)&v46, v56 != 0);
    sub_403296(&v46, v55);
    ++v54;
  }
  memcpy((void *)a5, &src, 0x1C0u);
  *(_QWORD *)(a5 + 448) = v45[0];
  *(_QWORD *)(a5 + 456) = v45[1];
  sub_403107((__int64)&v46, "PALEND2", 7u);
  sub_4031FF((__int64)&v46, v22);
  sub_403229(&v46, v54);
  LODWORD(v43) = 0;
  v12 = EVP_sha256();
  if ( (unsigned int)EVP_Digest(v46, v47, v59, &v43, v12, 0) != 1 || (_DWORD)v43 != 32 )
  {
    memset(v59, 0, sizeof(v59));
    v22 = 2;
  }
  for ( k = 0; k <= 31; ++k )
    snprintf((char *)v60 + 2 * k, 3u, "%02x", *((unsigned __int8 *)v59 + k));
  v61 = 0;
  *(_QWORD *)(a5 + 464) = v46;
  *(_QWORD *)(a5 + 472) = v47;
  v13 = v60[1];
  *(_QWORD *)(a5 + 512) = v60[0];
  *(_QWORD *)(a5 + 520) = v13;
  v14 = v60[3];
  *(_QWORD *)(a5 + 528) = v60[2];
  *(_QWORD *)(a5 + 536) = v14;
  v15 = v60[5];
  *(_QWORD *)(a5 + 544) = v60[4];
  *(_QWORD *)(a5 + 552) = v15;
  v16 = v60[7];
  *(_QWORD *)(a5 + 560) = v60[6];
  *(_QWORD *)(a5 + 568) = v16;
  *(_BYTE *)(a5 + 576) = v61;
  v17 = v59[1];
  *(_QWORD *)(a5 + 480) = v59[0];
  *(_QWORD *)(a5 + 488) = v17;
  v18 = v59[3];
  *(_QWORD *)(a5 + 496) = v59[2];
  *(_QWORD *)(a5 + 504) = v18;
  *(_BYTE *)(a5 + 577) = v22;
  return v22 != 2;
}
```
Đầu tiên nó xóa vùng nhớ kết quả, rồi khởi tạo chuỗi băm mã hóa và gắn PALSEAL2 để khóa dữ liệu. Rồi nó duyệt qua từng phần dữ liệu, tra cứu bảng, bitwise, trích xuất config và gọi hàm sub_3253189 (dùng để liên tục nhận dữ liệu từ các hình khối của file SVG, biến đổi cùng với các khóa nội bộ bằng bitwise để biến đổi trạng thái của toàn bộ chương trình sau mỗi loop)  . Mọi trạng thái, tham số và kết quả trong loop đều được nạp liên tục vào tiến trình băm để đảm bảo không bị chỉnh sửa. Cuối cùng chương trình gắn thêm PALEND2 và mã trạng thái, đưa data và event qua hàm băm sha-256 để tạo mã băm.
                      
#sub_4073F0 
```
__int64 __fastcall sub_4073F0(__int64 a1, size_t a2, __int64 a3, const void *a4)
{
  char v7; // [rsp+2Fh] [rbp-841h]
  size_t v8; // [rsp+30h] [rbp-840h] BYREF
  __int64 v9; // [rsp+38h] [rbp-838h]
  size_t v10; // [rsp+40h] [rbp-830h]
  size_t i; // [rsp+48h] [rbp-828h]
  size_t j; // [rsp+50h] [rbp-820h]
  void *ptr; // [rsp+58h] [rbp-818h]
  _BYTE v14[2056]; // [rsp+60h] [rbp-810h] BYREF
  unsigned __int64 v15; // [rsp+868h] [rbp-8h]

  v15 = __readfsqword(0x28u);
  if ( !a1 || !a2 || a2 > 0x40 )
    return 2;
  v8 = 0;
  if ( (unsigned __int8)sub_4062BD(v14, 0x800u, (__int64 *)&v8) != 1 )
    return 2;
  ptr = calloc(a2, 0x28u);
  if ( !ptr )
    return 2;
  v9 = 0;
  v10 = 0;
  v7 = 1;
  while ( v10 < a2 )
  {
    if ( (unsigned __int8)sub_406A16(*(const char **)(8 * v10 + a1), v14, v8, a3, a4, (__int64)ptr + 40 * v10) != 1
      || (unsigned __int64)(0x20000000 - v9) < *((_QWORD *)ptr + 5 * v10 + 2) )
    {
      v7 = 0;
      break;
    }
    v9 += *((_QWORD *)ptr + 5 * v10++ + 2);
  }
  if ( v7 )
  {
    for ( i = 0; i < a2; ++i )
    {
      if ( (unsigned __int8)sub_407118((const char **)ptr + 5 * i) != 1 )
      {
        v7 = 0;
        break;
      }
    }
  }
  for ( j = 0; j < a2; ++j )
  {
    if ( *((_QWORD *)ptr + 5 * j + 1) )
    {
      OPENSSL_cleanse(*((_QWORD *)ptr + 5 * j + 1), *((_QWORD *)ptr + 5 * j + 2));
      free(*((void **)ptr + 5 * j + 1));
    }
  }
  OPENSSL_cleanse(v14, 2048);
  free(ptr);
  if ( v7 )
    return 0;
  else
    return 2;
}
```                      
                      
Đầu tiên hàm sẽ check xem  a1(sub_40564C) và a2(số phần tử trong mảng) có rỗng không, đồng thời có lớn hơn 64 không, nếu có thì trả mã lỗi 2.Rồi nó gọi sub_4062BD để làm như ở trên đã giải thích, lưu vào v14 với kích thước 2048 byte.Tiếp theo nó cấp phát 0x28 bộ nhớ cho ptr rồi nó gọi sub_406A16 cấp phát động 40 byte cho mỗi phần tử, mở file lên tại v10, đọc kết quả và điền trực tiếp kết quả vào (__int64)ptr + 40 * v10, file được nạp chỉ tối đa 512mb, nếu quá thì sẽ v7=0 và break vòng lặp.Tiếp đến nó chạy tiếp một vòng lặp gọi hàm sub_407118 truyền vào từng khối cấu trúc 40 bytes để thực thi quá trình ghi, đồng bộ toàn bộ hàng loạt file kết quả ra đĩa cứng một cách an toàn.Và cuối cùng hàm dọn dẹp lại với OPENSSL_cleanse và trả lại bộ nhớ ptr đã sài.
    
#sub_406A16
```
__int64 __fastcall sub_406A16(const char *a1, const void *a2, size_t a3, __int64 a4, const void *a5, __int64 a6)
{
  size_t v7; // rax
  size_t v8; // rax
  _QWORD *v9; // rcx
  __int64 v10; // rdx
  __int64 v11; // rdx
  char *v12; // rcx
  __int64 v13; // rdx
  char *v14; // rax
  __int64 v15; // rax
  unsigned __int8 v20; // [rsp+33h] [rbp-14Dh]
  int v21; // [rsp+34h] [rbp-14Ch] BYREF
  int v22; // [rsp+38h] [rbp-148h] BYREF
  unsigned int v23; // [rsp+3Ch] [rbp-144h]
  void *dest; // [rsp+40h] [rbp-140h]
  size_t v25; // [rsp+48h] [rbp-138h]
  void *ptr; // [rsp+50h] [rbp-130h]
  size_t size; // [rsp+58h] [rbp-128h]
  FILE *stream; // [rsp+60h] [rbp-120h]
  __int64 v29; // [rsp+68h] [rbp-118h]
  struct stat buf; // [rsp+70h] [rbp-110h] BYREF
  __int64 v31; // [rsp+10Ch] [rbp-74h] BYREF
  __int64 v32; // [rsp+114h] [rbp-6Ch] BYREF
  int v33; // [rsp+11Ch] [rbp-64h]
  _QWORD v34[2]; // [rsp+120h] [rbp-60h] BYREF
  _QWORD v35[4]; // [rsp+130h] [rbp-50h] BYREF
  _BYTE v36[40]; // [rsp+150h] [rbp-30h] BYREF
  unsigned __int64 v37; // [rsp+178h] [rbp-8h]

  v37 = __readfsqword(0x28u);
  ptr = nullptr;
  dest = nullptr;
  v20 = 0;
  if ( !sub_4065A7(a1) || stat(a1, &buf) || (buf.st_mode & 0xF000) != 0x8000 )
    return 0;
  if ( buf.st_size > 0x10000000uLL )
    return 0;
  size = buf.st_size;
  if ( buf.st_size )
    v7 = size;
  else
    v7 = 1;
  ptr = malloc(v7);
  if ( !ptr )
    return 0;
  stream = fopen(a1, "rb");
  if ( stream )
  {
    if ( !size || size == fread(ptr, 1u, size, stream) )
    {
      fclose(stream);
      if ( (unsigned int)RAND_bytes((__int64)v34, 16) == 1
        && (unsigned int)RAND_bytes((__int64)&v32, 12) == 1
        && (unsigned int)RAND_bytes((__int64)&v31, 8) == 1 )
      {
        v8 = strlen(a1);
        if ( sub_4066E3((__int64)a1, v8, (__int64)v35)
          && (unsigned __int8)sub_406887((__int64)v34, a2, a3, a4, a5, (__int64)v36) == 1 )
        {
          v25 = size + 116;
          dest = malloc(size + 116);
          if ( dest )
          {
            memcpy(dest, "SBC2026", 8u);
            *((_BYTE *)dest + 8) = 2;
            *((_BYTE *)dest + 9) = 1;
            sub_4064E3((_WORD *)dest + 5, buf.st_mode & 0xFFF);
            sub_406561((__int64)dest + 12, size);
            sub_406561((__int64)dest + 20, size);
            v9 = (char *)dest + 28;
            v10 = v35[1];
            *(_QWORD *)((char *)dest + 28) = v35[0];
            v9[1] = v10;
            v11 = v35[3];
            v9[2] = v35[2];
            v9[3] = v11;
            v12 = (char *)dest + 60;
            v13 = v34[1];
            *(_QWORD *)((char *)dest + 60) = v34[0];
            *((_QWORD *)v12 + 1) = v13;
            v14 = (char *)dest + 76;
            *(_QWORD *)((char *)dest + 76) = v32;
            *((_DWORD *)v14 + 2) = v33;
            *((_QWORD *)dest + 11) = v31;
            v23 = sub_400E3C(dest, 96);
            sub_406512((char *)dest + 96, v23);
            v29 = EVP_CIPHER_CTX_new();
            v21 = 0;
            v22 = 0;
            if ( v29
              && (v15 = EVP_chacha20_poly1305(), (unsigned int)EVP_EncryptInit_ex(v29, v15, 0, 0, 0) == 1)
              && (unsigned int)EVP_CIPHER_CTX_ctrl(v29, 9, 12, 0) == 1
              && (unsigned int)EVP_EncryptInit_ex(v29, 0, 0, v36, &v32) == 1
              && (unsigned int)EVP_EncryptUpdate(v29, 0, &v21, dest, 100) == 1
              && (unsigned int)EVP_EncryptUpdate(v29, (char *)dest + 100, &v21, ptr, (unsigned int)size) == 1
              && (unsigned int)EVP_EncryptFinal_ex(v29, (char *)dest + v21 + 100, &v22) == 1
              && size == v21 + v22
              && (unsigned int)EVP_CIPHER_CTX_ctrl(v29, 16, 16, (char *)dest + size + 100) == 1 )
            {
              EVP_CIPHER_CTX_free(v29);
              *(_QWORD *)a6 = a1;
              *(_QWORD *)(a6 + 8) = dest;
              *(_QWORD *)(a6 + 16) = v25;
              *(_DWORD *)(a6 + 24) = buf.st_mode & 0xFFF;
              *(_DWORD *)(a6 + 28) = buf.st_uid;
              *(_DWORD *)(a6 + 32) = buf.st_gid;
              dest = nullptr;
              v20 = 1;
            }
            else if ( v29 )
            {
              EVP_CIPHER_CTX_free(v29);
            }
          }
        }
      }
      OPENSSL_cleanse(v36, 32);
      if ( ptr )
      {
        OPENSSL_cleanse(ptr, size);
        free(ptr);
      }
      if ( dest )
      {
        OPENSSL_cleanse(dest, v25);
        free(dest);
      }
      return v20;
    }
    else
    {
      fclose(stream);
      OPENSSL_cleanse(ptr, size);
      free(ptr);
      return 0;
    }
  }
  else
  {
    free(ptr);
    return 0;
  }
}
```
Hàm này đầu tiên nó gọi sub_4065A7 kiểm tra tính hợp lệ của đường dẫn xem có dùng dấu / không, check xem có sài path traversal(https://community.owasp.org/attacks/Path_Traversal) hay không để tránh bị đọc/ ghi đè, cùng lúc đó nó check xem có a1 trong buffer chưa, và check này có phải là file bình thường trong linux không (0x8000), check file xem có vượt quá 256 mb không, oke rồi thì nó để file chế độ read binary và nạp nội dung file vào ptr. Rồi nó sài RAND_bytes để sinh IV và chuỗi phụ trợ cho thuật toán chacha20(ở đoạn dưới có đề cập EVP_chacha20_poly1305). Tiếp đến nó gọi hàm sub_406887 check 4 byte đầu có phải “PRI1” không, nếu có thì sẽ đóng gói lại theo cấu trúc nội bộ bắt đầu với chuỗi “PALIKM4” rồi nó gọi hàm sub_406768 để tiếp tục mã hóa. Rồi hàm sau đó build-up header tệp với magic là “SBC2026” và hàm dùng mã hóa đối xứng chacha20-Poly1305 (https://en.wikipedia.org/wiki/ChaCha20-Poly1305) để build buffer dest dạng sau: `header 100 byte (AAD) || ciphertext || tag 16 byte`. Cuối cùng nó gọi OPENSSL_cleanse để dọn ptr và dest trước khi trả lại bộ nhớ của chúng.
    
#sub_406768
```
_BOOL8 __fastcall sub_406768(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
  __int64 v4; // rax
  __int64 v6; // rax
  bool v7; // al
  bool v10; // [rsp+2Bh] [rbp-55h]
  int v11; // [rsp+2Ch] [rbp-54h] BYREF
  _BYTE dest[32]; // [rsp+30h] [rbp-50h] BYREF
  _BYTE v13[40]; // [rsp+50h] [rbp-30h] BYREF
  unsigned __int64 v14; // [rsp+78h] [rbp-8h]

  v14 = __readfsqword(0x28u);
  v11 = 0;
  v4 = EVP_sha256();
  if ( !HMAC(v4, a1, 16, a2, a3, v13, &v11) || v11 != 32 )
    return 0;
  memcpy(dest, "PALINFO-VAULT-v4", 0x10u);
  dest[16] = 1;
  v6 = EVP_sha256();
  v7 = HMAC(v6, v13, 32, dest, 17, a4, &v11) && v11 == 32;
  v10 = v7;
  OPENSSL_cleanse(v13, 32);
  return v10;
}
```
Hàm này sử dụng a1 làm key, lấy ptr làm input nhằm sinh ra một mã băm HMAC-SHA256(https://viblo.asia/p/hmacsha256-khi-ban-goc-va-chia-khoa-tao-nen-loi-the-bao-mat-AY4qQgay4Pw) dài 32 byte lưu vào v13 (check đủ 32 byte không bằng v11). Tiếp theo nó lấy chuỗi kết hợp của “PALINFO-VAULT-v4” + dest làm input và kết quả v13 ở bước trước làm khóa để tạo ra một mã băm mới lưu vào a4 ( hay khóa mã chacha20 ở hàm sub_406A16).
    
Cuối cùng đến với hàm so sánh profile:
```
_BOOL8 sub_4009AE()
{
  bool v0; // al
  bool v2; // [rsp+7h] [rbp-529h]
  __int64 n; // [rsp+8h] [rbp-528h]
  _DWORD v4[68]; // [rsp+10h] [rbp-520h] BYREF
  char ptr[1032]; // [rsp+120h] [rbp-410h] BYREF
  unsigned __int64 v6; // [rsp+528h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  sub_40564C(v4);
  n = sub_405995((__int64)v4, ptr, 0x400u);
  v0 = n && n == fwrite(ptr, 1u, n, stdout);
  v2 = v0;
  OPENSSL_cleanse(v4, 272);
  OPENSSL_cleanse(ptr, 1024);
  return !v2;
}
```
Đầu tiên hàm gọi hàm sub_40564C để xử lý như ở trên đã giải thích. Sau khi nhận dữ liệu qua v4 của sub_40564C thì chương trình sẽ gọi sub_405995 để nó gom nhặt thông tin phần cứng từ cấu trúc nội bộ của chương trình, đóng gói chúng thành một gói định dạng nhị phân chuẩn có PALHOST1 theo cấu trúc TLV, dùng cho việc định danh thiết bị hoặc xuất thông tin profile hệ thống.

Sau khi đào hết con ransomware này lên thì đầu tiên mình sẽ đi viết code kết hợp quy tắc giải file .svg từ file ransomware ở sub_4028FA lại:
```
import hashlib
import math
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET
import zlib


def pick(win, wsl):
    return win if os.path.exists(win) else wsl

BIN = sys.argv[1] if len(sys.argv) > 1 else pick(
    r"D:\cockcock Down\palimpsest-challenge-original\palimpsest-challenge-original\opt\palimpsest\palimpsest",
    "/mnt/d/cockcock Down/palimpsest-challenge-original/palimpsest-challenge-original/opt/palimpsest/palimpsest")
SVG = sys.argv[2] if len(sys.argv) > 2 else pick(
    r"D:\cockcock Down\palimpsest-team-23\team\archivist.svg",
    "/mnt/d/cockcock Down/palimpsest-team-23/team/archivist.svg")

blob = open(BIN, "rb").read()
svg = open(SVG, "rb").read()

assert blob[:4] == b"\x7fELF"
off = blob.find(b"PAL1")                      
print("blob 'PAL1': file offset 0x%08x   (vaddr trong IDA = 0x%08x)" % (off, off + 0x400000))
(magic, ver, W, H, flags, ex, ey, edir, phase, dialect, muts, maxsteps,
 goff, loff, poff, moff, total, PID, reserved, hcrc) = struct.unpack(
    "<4sBBBBHHBBBBIIIIIIQ12sI", blob[off:off + 64])

want = sorted(list(range(16)) * 4)            
SIZES = [("a", 8), ("b", 8), ("imm_hi", 16), ("imm_lo", 16),
         ("aux", 16), ("crc_hi", 16), ("crc_lo", 16), ("mode", 4)]
token, tab = None, None
for m in re.finditer(rb"[\x00-\x0f]{64,}", blob):      
    run, base = m.group(), m.start()
    for s in range(len(run) - 63):
        if sorted(run[s:s + 64]) != want:
            continue
        cur, got = base + s + 64, {}
        for name, n in SIZES:
            v = blob[cur:cur + n]
            if sorted(v) != list(range(n)):              
                break
            got[name], cur = list(v), cur + n
        else:
            token, tab = list(run[s:s + 64]), got
            break
    if tab:
        break
assert tab, "codec tables not found"

CS, OX, OY = 30.0, 48.0, 48.0
CORE = ("#58a6ff", "#3fb950", "#d29922", "#bc8cff", "#f85149", "#39c5cf", "#db61a2", "#a5d6ff")
REG_A, REG_B, MODE = "#f0883e", "#79c0ff", "#e6edf3"
IMM_HI, IMM_LO, AUX = "#e3b341", "#d2a8ff", "#7ee787"
CRC_HI, CRC_LO = "#ff7b72", "#ffa657"
ORBIT = ((0, -10), (7, -7), (10, 0), (7, 7), (0, 10), (-7, 7), (-10, 0), (-7, -7))

def nearest(v, cands, tol):
    i = min(range(len(cands)), key=lambda k: abs(v - cands[k]))
    assert abs(v - cands[i]) <= tol, "geometry %.3f not on lattice" % v
    return i

slot = [dict() for _ in range(W * H)]
for el in ET.fromstring(svg).iter():
    tag = el.tag.rsplit("}", 1)[-1]
    a = el.attrib
    fill, stroke = a.get("fill", "").lower(), a.get("stroke", "").lower()

    if tag == "polygon" and fill in CORE:                    
        p = [tuple(map(float, q.split(","))) for q in a["points"].split()]
        cx, cy = sum(x for x, _ in p) / len(p), sum(y for _, y in p) / len(p)
        i = int((cy - OY) // CS) * W + int((cx - OX) // CS)
        slot[i]["rune"] = CORE.index(fill) * 8 + len(p) - 3
    elif tag == "circle" and fill in (REG_A, REG_B):        
        cx, cy = float(a["cx"]), float(a["cy"])
        x, y = int((cx - OX) // CS), int((cy - OY) // CS)
        ccx, ccy = OX + x * CS + CS / 2, OY + y * CS + CS / 2
        d = min(range(8), key=lambda k: math.hypot(cx - ccx - ORBIT[k][0], cy - ccy - ORBIT[k][1]))
        slot[y * W + x]["a" if fill == REG_A else "b"] = d
    elif tag == "circle" and fill == "none" and stroke == MODE:
        cx, cy, r = float(a["cx"]), float(a["cy"]), float(a["r"])
        i = int((cy - OY) // CS) * W + int((cx - OX) // CS)
        slot[i]["mode"] = nearest(r, [7.4 + k * 0.7 for k in range(4)], 0.2)
    elif tag == "rect" and fill in (IMM_HI, IMM_LO, CRC_HI, CRC_LO):
        rx, ry, rw, rh = (float(a[k]) for k in ("x", "y", "width", "height"))
        cx, cy = rx + rw / 2, ry + rh / 2
        x, y = int((cx - OX) // CS), int((cy - OY) // CS)
        ccx, ccy = OX + x * CS + CS / 2, OY + y * CS + CS / 2
        key = {IMM_HI: "imm_hi", IMM_LO: "imm_lo", CRC_HI: "crc_hi", CRC_LO: "crc_lo"}[fill]
        slot[y * W + x][key] = nearest(cx, [ccx - 11.25 + k * 1.5 for k in range(16)], 0.2) \
            if fill in (IMM_HI, IMM_LO) else \
            nearest(cy, [ccy - 11.25 + k * 1.5 for k in range(16)], 0.2)
    elif tag == "line" and stroke == AUX:
        x1, y1, x2, y2 = (float(a[k]) for k in ("x1", "y1", "x2", "y2"))
        x, y = int(((x1 + x2) / 2 - OX) // CS), int(((y1 + y2) / 2 - OY) // CS)
        ccy = OY + y * CS + CS / 2
        slot[y * W + x]["aux"] = nearest((y1 + y2) / 2, [ccy - 11.25 + k * 1.5 for k in range(16)], 0.2)


def crc8(buf):
    c = 0
    for byte in buf:
        c ^= byte
        for _ in range(8):
            c = ((c << 1) ^ 0x07) & 0xFF if c & 0x80 else (c << 1) & 0xFF
    return c


pid_b = struct.pack("<Q", PID)
cells, ok = [], 0
for i, s in enumerate(slot):
    assert len(s) == 9, "cell %d: %d/9 fields" % (i, len(s))
    low = (token[s["rune"]]
           | tab["a"][s["a"]] << 4
           | tab["b"][s["b"]] << 7
           | ((tab["imm_hi"][s["imm_hi"]] << 4) | tab["imm_lo"][s["imm_lo"]]) << 10
           | tab["mode"][s["mode"]] << 18
           | tab["aux"][s["aux"]] << 20)
    chk = (tab["crc_hi"][s["crc_hi"]] << 4) | tab["crc_lo"][s["crc_lo"]]
    good = crc8(pid_b + struct.pack("<H", i) + struct.pack("<I", low)[:3]) == chk
    ok += good
    cells.append(low | chk << 24)


grid = b"".join(struct.pack("<I", c) for c in cells)
print("decoded cells            : %d" % len(cells))
print("CRC-8 matching the SVG   : %d/1024" % ok)
print("sha256(decoded grid)     : %s" % hashlib.sha256(grid).hexdigest())
print("program_id (from ELF)    : 0x%016x  entry=(%d,%d)" % (PID, ex, ey))
for i in (0, 928, 517):
    c = cells[i]
    print("  cell %3d: low24=0x%06x crc=0x%02x -> rune=%2d a=%d b=%d imm=0x%02x mode=%d aux=%d"
          % (i, c & 0xFFFFFF, c >> 24, c & 0xF, (c >> 4) & 7, (c >> 7) & 7,
             (c >> 10) & 0xFF, (c >> 18) & 3, (c >> 20) & 0xF))


assert zlib.crc32(blob[off:off + 60]) & 0xFFFFFFFF == hcrc, "header CRC32 sai"
grid_size = loff - goff
lex_size, portal_size, mut_size = poff - loff, moff - poff, total - moff
assert grid_size == W * H * 4 and len(grid) == grid_size


BIN_CHUNKS = {"lexicon": 0x2E7D8C0, "portal": 0x2E7E4C0, "mutation": 0x2E7E500}


lex = blob[BIN_CHUNKS["lexicon"]:BIN_CHUNKS["lexicon"] + lex_size]
portal = blob[BIN_CHUNKS["portal"]:BIN_CHUNKS["portal"] + portal_size]
mut = blob[BIN_CHUNKS["mutation"]:BIN_CHUNKS["mutation"] + mut_size]
assert len(lex) == lex_size and len(portal) == portal_size and len(mut) == mut_size


out = bytearray(total)
out[0:64] = blob[off:off + 64]
out[goff:goff + grid_size] = grid
out[loff:loff + lex_size] = lex
out[poff:poff + portal_size] = portal
out[moff:moff + mut_size] = mut


OUT = sys.argv[3] if len(sys.argv) > 3 else os.path.join(
    os.getcwd(), os.path.splitext(os.path.basename(SVG))[0] + ".recovered.pal")
open(OUT, "wb").write(out)
print()
print("reconstructed file       : %s" % os.path.abspath(OUT))
print("  size                   : %d B  (header %d | grid %d | lexicon %d | portal %d | mutation %d)"
      % (len(out), 64, grid_size, lex_size, portal_size, mut_size))
print("  sha256                 : %s" % hashlib.sha256(out).hexdigest())

```
Output:
![image](https://hackmd.io/_uploads/r1uuieD2ze.png)

Việc của mình bây giờ là tìm 12 byte cuối ở đây trước 

Đầu tiên ta đọc code của file .pal kia đã:
Lệnh đầu của nó là 

  `  0 st   0 ( 0,29) d1p0 rune15 BRANCH   `

   Có thể hiểu như sau:

```
zero_turn    = imm & 3;          // R7 == 0  
nonzero_turn = (imm >> 2) & 3;   // R7 != 0 
turn = (regs[src_a] == 0) ? zero_turn : nonzero_turn;
```

Với imm = 4 thì zero_turn = 0, nonzero_turn = 1. Hay R7 = 0 thì đi thẳng, R7 khác 0 thì rẽ 90 độ. 

Để tìm được 12 byte cuối thì mình sẽ trace bằng cách để R7=1 với đầu vào là 12 byte 0 rồi ghi ra text:
```
import sys
sys.path.insert(0, r"D:\cockcock Down\palimpsest-team-23\solve")
from palvm import *
sys.path.insert(0, r"D:\cockcock Down\palimpsest-team-23")
from reference.pal_format import PalProgram


data=open(r"D:\cockcock Down\palimpsest-team-23\team\archivist.private.pal","rb").read()
prog=PalProgram.from_bytes(data)
log=[]
r=vm_run(prog, Host(), mode=1, candidate=bytes(12), log=log)
mt=r["micro"]
with open(r"D:\cockcock Down\palimpsest-team-23\solve\micro_m1.txt","w") as f:
    for i,m in enumerate(mt):
        f.write(f"{i:4d} st{m['step']:4d} ({m['x']:2d},{m['y']:2d}) d{m['dialect']}p{m['phase']} "
                f"rune{m['rune']:2d} {NAMES.get(m['op'],'?'):7s} dst={m['dst']:2d} sa={m['sa']:2d} "
                f"sb={m['sb']:2d} imm={m['imm']:#010x} flags={m['flags']} cellimm={m['cell_imm']:#04x} aux={m['aux']}\n")
print("micro count",len(mt))

```
Output sẽ là 1 file txt(ở đây là micro.m1.txt)
    
Chúng ta sẽ có 1 file .txt cho 530 dòng, giờ cần lọc ra để có thể tìm được đúng 12 byte ấy

Ví dụ cách đọc 1 line nhé:
`12 st  12 ( 9,26) d1p0 rune 1 CONST   dst= 3 sa=-1 sb=-1 imm=0x00000040 flags=0 cellimm=0x40 aux=0`
Ta có
+ Số 12 đầu: số thứ tự dòng micro-op
+ Số 12 sau: số bước
+ (9,26): toạ độ ô
+ d1p0: dialect lúc chạy
+ rune: lệnh trong ô
+ CONST: tên lệnh
+ dst: đích
+ sa:nguồn 1
+ sb: nguồn 2
+ imm: Immediate value đã resolve
+ cellimm: byte thô trong ô

Đầu tiên để tìm được 12 byte đó thì mình sẽ xác định 12 byte output của nó
Do hơi rối nên mình đã nhờ sức mạnh của công nghệ để lọc registry ra để đọc 
![image](https://hackmd.io/_uploads/rkxeaxvhMl.png)

Có thể rút ra những điều sau :
+ r1 được ghi đúng 3 lần, nhưng nó lại là base của 108/108 lệnh bộ nhớ vậy nên r1 là con trỏ nền
+ r3 nhận 60 lệnh CONST nên đây là thanh ghi riêng của  hằng số 

Do r1 là con trỏ nên mỗi lần ghi là một lần duyệt bộ nhớ mới, mình lọc r1 ra:
![image](https://hackmd.io/_uploads/H1NX6ePnze.png)
    
Phán đoán của mình là cụm 10 và cụm 205 thì nó chỉ lặp lại quy trình 1 block là LOAD8 rồi CONST rồi XOR rồi CONST rồi ADD rồi STORE8, chủ yếu là biến đổi, còn với cụm 400 trở lên, nó lặp lại 1 block là LOAD8 rồi CONST rồi XOR rồi ADD dst=5(r5) để so sánh . Vậy nên 16 byte sẽ được lấy từ cụm 400 hay mem[0x30..0x3b] (cụm so sánh)

Giờ mình sẽ lấy các CONST mà dst =3(do phép XOR lấy r2 làm dữ liệu và r3 làm hằng cần so sánh) từ block 400+ để tìm được 12 byte target nhé:
![image](https://hackmd.io/_uploads/Hy8qTgv3ze.png)
Vậy ta có 12 byte target là a3e6f36eaf951ec8d9fbfb30

Do ta có 2 thuật toán lồng nhau để biến đổi ở cụm 10 và cụm 205 nên giờ chỉ cần xây dựng thuật toán đảo ngược từ target về plaintext ban đầu thôi 

Ở cụm thứ nhất, khi lọc CONST ta có được khóa XOR là 4001cb161fabaa050dac4022 và khóa ADD là 30c7fbb67ebf51a21376fdeb

Ở cụm thứ 2 khóa XOR là ba9952436e5eebee0d1e83ed và khóa ADD là a13d0d4ee2404dec95ddbf80

Code để giải mã 12 byte cuối là:
```
import struct
M32 = (1 << 32) - 1


def rol(v, n):
    n &= 31; v &= M32
    return v if n == 0 else (((v << n) | (v >> (32 - n))) & M32)


ROUNDS = [
    ([2,4,11,1,0,3,10,7,5,9,6,8],
     "4001cb161fabaa050dac4022", "30c7fbb67ebf51a21376fdeb",
     [0xB284B148, 0x7208A81E, 0x6269928D], [19, 11, 24]),
    ([7,0,11,2,8,5,3,1,6,4,9,10],
     "ba9952436e5eebee0d1e83ed", "a13d0d4ee2404dec95ddbf80",
     [0xE525D5C4, 0x8C9B00C9, 0x1DC6D9BC], [14, 19, 24]),
]


def round_inv(y, prm):
    P, xk, ak, C, R = prm
    xk, ak = bytes.fromhex(xk), bytes.fromhex(ak)
    w1, w2, w3 = struct.unpack("<III", y)
    o1 = w1 ^ rol((w3 + C[2]) & M32, R[2])      
    o3 = (w3 - rol(w2 ^ C[1], R[1])) & M32      
    o2 = w2 ^ rol((o1 + C[0]) & M32, R[0])  
    mid = struct.pack("<III", o1, o2, o3)      
    pre = bytearray(12)
    for k in range(12):
        pre[P[k]] = ((mid[k] - ak[k]) & 0xFF) ^ xk[k]  
    return bytes(pre), mid


target = bytes.fromhex("a3e6f36eaf951ec8d9fbfb30")
y = target
for i in (1, 0):                      
    y, mid = round_inv(y, ROUNDS[i])
print(y.hex())

```
Output:
![image](https://hackmd.io/_uploads/Bk_RagD3zg.png)

Vậy là ta đã có 12 byte cuối rồi

Tiếp theo mình sẽ đi tìm 32 byte trước đó bằng cách debug con ransomware này với profile của vm ci-runner bài cho để dump được transcript chuẩn của nó gồm $rdi là địa chỉ buffer và  $rsi là độ dài ra một file .bin, lấy sha256 chuỗi đó. Kết quả sau khi làm 32 byte đó là: `0f055d859d363d52edc6d6f123af744e9103da887e41af39886fdeb954da8d19`
    
Do từ file ransomware chúng ta đã rev được input của key là : "PALIKM4" ‖ LE16(len(identity)) ‖ identity ‖ 32 byte dump ‖ 12 byte từ target ‖ SHA-256 của chương trình, và các thành phần còn lại từ file bị mã hóa gồm key sẽ được tạo từ key = hkdf_sha256(hay là HMAC-SHA256)(input, offset của từng file bị mã hóa từ 60 đến 76 (hay là salt), PALINFO-VAULT-v4, 32), IV(12 byte sau salt),AAD(100 byte header),ciphertext(nằm giữa tag và AAD), tag(16 byte cuối sau ciphertext) thì ta có thể xây dựng thuật toán giải mã như sau:
```
import argparse
import hashlib
import hmac
import os
import posixpath
import struct
import sys
import zlib

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
    
MAGIC = b"SBC2026\x00"
HDR = 0x64
TAG = 16
INFO = b"PALINFO-VAULT-v4"
    
def _rotl(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)

def chacha20_block(key, counter, nonce):
    st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    st += list(struct.unpack("<8I", key))
    st += [counter & 0xFFFFFFFF]
    st += list(struct.unpack("<3I", nonce))
    w = st[:]
    for _ in range(10):
        _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13)
        _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12)
        _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w[i] + st[i]) & 0xFFFFFFFF for i in range(16)])

def chacha20_xor(key, nonce, data, counter=1):
    out = bytearray(len(data))
    for off in range(0, len(data), 64):
        ks = chacha20_block(key, counter + off // 64, nonce)
        blk = data[off:off + 64]
        for i, b in enumerate(blk):
            out[off + i] = b ^ ks[i]
    return bytes(out)

def poly1305_mac(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for off in range(0, len(msg), 16):
        blk = msg[off:off + 16]
        n = int.from_bytes(blk + b"\x01", "little")
        acc = ((acc + n) * r) % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")

def aead_decrypt(key, nonce, aad, ct, tag):
    otk = chacha20_block(key, 0, nonce)[:32]
    mac_data = aad + b"\x00" * (-len(aad) % 16) + ct + b"\x00" * (-len(ct) % 16)
    mac_data += struct.pack("<QQ", len(aad), len(ct))
    want = poly1305_mac(otk, mac_data)
    if not hmac.compare_digest(want, tag):
        raise ValueError("Wrong Key")
    return chacha20_xor(key, nonce, ct)

def hkdf_sha256(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]

def derive_key(identity, frame, program_digest, salt):
    if frame[:4] != b"PRI1" or len(frame) != 48:
        raise ValueError("Not start with 'PRI1'")
    ikm = (b"PALIKM4" + struct.pack("<H", len(identity)) + identity
           + frame[4:48] + program_digest)
    return hkdf_sha256(ikm, salt, INFO, 32)

def open_stub(data, key, want_path):
    if data[:8] != MAGIC:
        raise ValueError("Magic not SBC2026")
    ver, cid = data[8], data[9]
    mode = struct.unpack_from("<H", data, 10)[0] & 0o7777
    orig, ctlen = struct.unpack_from("<QQ", data, 12)
    path_hash = data[28:60]
    salt, nonce = data[60:76], data[76:88]
    crc = struct.unpack_from("<I", data, 96)[0]
    if ver != 2 or cid != 1:
        raise ValueError("version/cipher Error")
    if (zlib.crc32(data[:96]) & 0xFFFFFFFF) != crc:
        raise ValueError("header CRC32 wrong")
    if hashlib.sha256(posixpath.normpath(want_path).encode()).digest() != path_hash:
        raise ValueError("path binding mismatch: %s" % want_path)
    ct = data[HDR:HDR + ctlen]
    tag = data[HDR + ctlen:HDR + ctlen + TAG]
    pt = aead_decrypt(key, nonce, data[:HDR], ct, tag)
    if len(pt) != orig:
        raise ValueError("lenght plaintext false")
    return mode, pt, salt
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", required=True, help="path to the challenge folder")
    ap.add_argument("--identity", required=True, help="vm-id.bin")
    ap.add_argument("--frame", required=True, help="48 byte")
    ap.add_argument("--prog", required=True, help="archivist.recovered.pal")
    ap.add_argument("--out", default="restored", help="Output decrytion")
    a = ap.parse_args()


    identity = open(a.identity, "rb").read()
    frame = open(a.frame, "rb").read()
    prog = open(a.prog, "rb").read()
    digest = hashlib.sha256(prog).digest()


    print("identity : %s  %d B  (%s…)" % (a.identity, len(identity), identity[:8].hex()))
    print("frame    : %s  %d B  seal=%s…  soul=%s"
          % (a.frame, len(frame), frame[4:36].hex()[:16], frame[36:48].hex()))
    print("program  : %s  %d B  sha256=%s" % (a.prog, len(prog), digest.hex()[:32]))
                            
    stubs = []
    for root, _dirs, files in os.walk(a.archive):
        for f in sorted(files):
            p = os.path.join(root, f)
            with open(p, "rb") as fh:
                if fh.read(8) != MAGIC:
                    continue
            stubs.append((os.path.relpath(p, a.archive).replace("\\", "/"), p))
    stubs.sort()
    print("\nFOUND %d file SBC2026 in %s\n" % (len(stubs), a.archive))


    rows, total = [], 0
    for rel, p in stubs:
        data = open(p, "rb").read()
        salt = data[60:76]
        key = derive_key(identity, frame, digest, salt)
        try:
            mode, pt, _ = open_stub(data, key, "/" + rel)
        except Exception as e:
            print("  %-42s ERROR: %s" % (rel, e))
            rows.append((rel, None, None, None))
            continue
        out = os.path.join(a.out, *rel.split("/"))
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        with open(out, "wb") as fh:
            fh.write(pt)
        try:
            os.chmod(out, mode)
        except Exception:
            pass
        total += len(pt)
        h = hashlib.sha256(pt).hexdigest()
        print("  %-42s %8d B  mode %04o  sha256=%s…" % (rel, len(pt), mode, h[:16]))
        rows.append((rel, len(pt), mode, h))


    ok = [r for r in rows if r[1] is not None]
    print("\n%d/%d file decrypt fine, All %d B write in %s/" % (len(ok), len(rows), total, a.out))
    if not ok:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())

```
Giải thích cách dùng script này 1 tí: input để chạy gồm đường dẫn tới folder challenge, file chứa 44 byte sau PRI1, file archivist.recovered.pal làm ở trên, và tên folder output 

Output:
![image](https://hackmd.io/_uploads/SJFgybw2zg.png)
Vậy là ta đã khôi phục xong service bị con ransomware này mã hóa rồi đấy OwO!
                            
Cảm ơn mọi người đã đọc write-up của mình nhé!



    
                           
