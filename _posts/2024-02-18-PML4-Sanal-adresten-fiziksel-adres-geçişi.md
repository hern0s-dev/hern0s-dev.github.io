---
layout: "post"
title : "PML4 Seviyesinde Sanal Adresten Fiziksel Adrese Geçiş"
image: images/post1/PML43.png
---

Bu postumda bazı kelimeleri ingilizce kullanmayı tercih edeceğim. Dil alışkanlığı olduğundan dolayı. O yüzden şimdiden kusuruma bakmayınız :slightly_smiling_face:	

> Bu Postda x64 Adresslemenin Physical geçişinden bahsedilmiştir x86 Adresslemede bu işlem benzer olsada bir kaç adım olarak farklıdır.
{: .prompt-warning }

## Terimler
1. Process  = Uygulama
2. Virtual  = Sanal
3. Physical = Fiziksel
4. Variable = Değer
5. Memory Management = Hafıza Yönetimi

## Virtual Adress vs Physical Adress

Virtual adressler her processin kendine özgün  sanal adresleme alanlarıyken Physical tam olarak ismindende anlaşılacağı üzere donanınımızın yani RAM'imizin üzerindeki lokasyonlarıdır. Bilgisayarimizda çalışan her processin kendine ait bir Virtual adress alanı vardır. İşletim sistemleri Processlerin birbirlerinin memory alanlarına müdahale etmemeleri karışmamaları için onların memorylerini ayırır ve onlara bir Virtual adress alanları verir. Diğer türlü düşünsenize A processindeki 0x4000000 adressinde bir variable tutulduğunu ve tesadüfen B processinde aynı 0x4000000 adresinde farklı bir variablenin tutulduğunu. Bu variableler birbirlerinden farklı iken bir process bu adressdeki variableyi değiştirdiği vakit bir diğer processdeki variableyi de değiştirmiş olurdu.
![Desktop View](/images/post1/img1.png){: width="385" height="355" }
_Processler arası Virtual adress ilişkisini gösteren bir fotoğraf_
#### Memory Management
 İşletim sistemimizin içinde bulunan Memory Management komponenti sayesinde bu Virtual adress alanlarını barındıran sayfaları tek tek ilmek ilmek işleyerek onların Physical adress sayfalarındaki lokasyonlara yerleştirilmesini, yeri geldiği zaman onları oradan okunmasını, yeri geldiği zaman değiştirilmesini ve hatta oradan silinmesini sağlar.Virtual adresslemede, memory , Physical adress sayfalarına yerleştirilirken ardışık bir şekilde yerleştirilmek zorunda değiller. Örneğin Virtual adresslemede 0x4000000 Virtual adressindeki bir değişken Physical adressde 0x7DCB00'da iken Virtual adresslemede 0x4000001 daki bir değer Physical adressde 0x8BFC01'de olabilir. 0x7DCB00 ve 0x8BFC01 birbirinden ne kadar farklı değil mi ? Halbuki bir Processin Virtual adressinde onlar ardışıktı :slightly_smiling_face:	

## x64 Virtual Adress Yapısı
x64 Adresslemede ismindende anlaşılacağı üzere, bir adress 64 adet bitden oluşmaktadır. Bu bitler Virtual adressin sırasıyla `PML4` `PDPT` `PD` `PT` ve `Page Offset` Indexlerini belirtir. 
![Desktop View](/images/post1/img2.png){: width="640" height="486" }

Peki, Ne ulan bu `PML4` `PDPT` `PD` `PT` `Page Offset` ? Dediğinizi duyar gibiyim :stuck_out_tongue:

Bunlar bizim işletim sistemimizin Virtual Adressleri Physical adresslere yerleştirirken kullandığı sayfalar arkadaşlar.

![Desktop View](/images/post1/PML4.png){: width="1430" height="1022" }

Yukarıdaki örnekte gördüğünüz üzere Virtual adressimizin 39 ve 47.bitleri arasında barınan değer bizim `PML4` sayfasındaki hangi indexe ulaşmamız gerektiğini belirler. Bu sayede zincirin bir sonraki aşamasına geçebilir ve `PDPT`sayfamızın base adresine ulaşırız. Bu sayfalar arka arkaya entry barındırır ve hepsi birer pointerd olduğundan dolayı 8 bytelık bir sizeları vardır. Bir nevi pointer array gibi düşünebilirsiniz. Bizim amacımız ise bu arraydan ilgili pointeri bulup onun sayesinde zincirin bir sonraki aşamasına ulaşmak. Bu zinciri aynı şekilde takip ettiğimizde durumda ise en son adımda bulduğumuz değer bizim Virtual Adressimizin Physical adressini vericektir. Birazdan örneklerle göstericeğim.

Bizim ilgili entrydeki bulduğumuz Physical adress değeri içerisinde bazı bit flaglar ve değerler barındırır. Bunlardan bazıları bu memory sayfası daha önce okundu mu , Üzerinde değişilik işlemi yapıldı mı. Yazma izinleri var mı veya Usermode'dan erişilebilir mi vs gibi bu sayfanın özelliklerini barındırır. Barındırdığı değerlerden birisi ise `PFN(Page Frame Number)` Bu değer zincirin bir sonrasındaki aşama olan ilgili sayfanın base adressini verir. Bu değeri `0x1000(Yani memorydeki bir sayfanın büyüklüğü)` değeriyle çarptığımız zaman bize bir sonraki sayfanın Physical adressini vericektir.Tabii ki bu işlemi bitmask ve AND işlemi kullanarak daha kafa karıştırıcı olmaktan kurtarabiliriz. Şimdi gelelim uygulama aşamasına.

## Uygulama aşaması

>Birazdan yapıcağım uygulama bir VM içerisinde Microsoftun Windbg programını kullanarak bir `Notepad.exe(Namı değer Not defteri)` processinin contextine bağlanıp içerisindeki modulleri yani DLL'leri listeleyeceğiz. Sonra `Ntdll.dll` modulümüzün Virtual adressini alıp bunu sizlerle beraber manuel olarak hesaplamasını yapıp Physical adresse çevirip Windbg da memory regionlarını karşılaştıracağız.
{: .prompt-tip }

![Desktop View](/images/post1/img3.png){: width="567" height="163" }
_Sistemde çalışan bütün notepad.exe processleri listeleyelim EPROCESS adressini alalım_

Hedef processin içeriğini görebilmemiz onun Virtual adress alanına erişebilmemiz için debuggerimizin contextini o processe çevirmemiz lazım. Şuanda debuggerimiz Kernel yani sistem contextinde çalışıyor. `.process` komutuyla processimizin contextine geçiş yapıcağız. Aynı zamanda `/i /r /p` flaglerini kullanarak sembolleri ve modulleri daha sağlıklı görüntüleyebilmemiz için reload atıcağız.

`.process /p <EPROCESS_address>` komutunu kullanarak sizde aynı işlemi yapabilirsiniz.

![Desktop View](/images/post1/img4.png){: width="820" height="545" }

>Komutun ardından !process komutunuda çalıştırarak şuanda hangi processe bağlı olduğumuzu gördük
{: .prompt-tip }



Image yazan kısımda `Notepad.exe` gördüğümüze göre kaldığımız yerden devam edebiliriz.

Şimdi Windbg programımızda `lm m ntdll` komutunu çalıştırarak contextine bağlı olduğumuz processin içinde yüklenmiş olan ntdll modülünü yani DLL'sini listeleyeceğiz.

![Desktop View](/images/post1/img5.png){: width="781" height="285" }

Modulümüzün base adressini `7fffae410000` bulduk ve `db 7fffae410000` komutunu çalıştırarak memory regionunu gördük ilk 2 byte'ımız `4D 5A` olduğunu görerek bunun bir MS DOS header olduğunu yani DLL başlangıcı olduğunu kanıtladık.`7fffae410000` adresini bir yere not edelim bu bizim DLL'imizin Virtual adressi.

Şimdi modülümüzüde bulduğumuza göre bizim yapmamız gereken process CR3 değerine yani PML4 sayfası base adresine erişmek. Bu değeri yazılımsal olarak EPROCESS classında KPROCESS sturctının içerisindeki `DirectoryTableBase` değerinden okuyabiliriz. Bu değer Windows 11 son sürümde 0x28 offsetinde iken bir başka Windows sürümlerinde offset farklı olabilir

```cpp
struct _EPROCESS
{
    struct _KPROCESS Pcb;                                                   //0x0
    struct _EX_PUSH_LOCK ProcessLock;                                       //0x438
    VOID* UniqueProcessId;                                                  //0x440
    struct _LIST_ENTRY ActiveProcessLinks;         
```

>KPROCESS structı EPROCESS classında 0x0 offsetinde bulunmaktadır büyüklüğü 0x438 dir ve içeriği aşağıda gördüğünüz gibidir.
{: .prompt-tip }

```cpp
struct _KPROCESS
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    struct _LIST_ENTRY ProfileListHead;                                     //0x18
    ULONGLONG DirectoryTableBase;                                           //0x28
    struct _LIST_ENTRY ThreadListHead;                                      //0x30
    ULONG ProcessLock;                                                      //0x40
    ULONG ProcessTimerDelay;                                                //0x44
    ULONGLONG DeepFreezeStartTime;                                          //0x48
    struct _KAFFINITY_EX Affinity;                                          //0x50
    struct _LIST_ENTRY ReadyListHead;                                       //0x158
    struct _SINGLE_LIST_ENTRY SwapListEntry;                                //0x168
    ...
```

Windbg programı bize bu değeri okumamız için kolaylık sağlıyor. Aşağıdaki komutu çalıştırdığınızda size contextine bağlı olduğunuz processin CR3 değerini yani PML4 sayfası başlangıcını vericektir. Yani zincirimizin ilk adımı.

```
kd> r cr3
cr3=0000000086394000
```

Şimdi Virtual adressimizin 39. bitinden 47. bitine kadar olan değeri bit shift ve AND işlemleri yaparak okuyalım. Bunu yazılım vasıtasıyla aşağıdaki kod ile veya hesap makinenizin programmer kısmında bit kaydırma ve AND işlemi yaparakda halledebilirsiniz.

```cpp
uint64_t pml4_index = ((virtualAddress >> 39) & (0x1ffll));
```

Ben sizin anlıyabilmeniz için hesap makinesiyle yapıcağım.

Virtual adressimiz `7fffae410000` sağa 39 bit kaydırdık ve AND işlemi yaparak 47.bite kadar olan değeri aldık yani 39. biti en sağa yasladık ve AND ile değeri okuduk.

>27 hexadecimal bir değerdir ve decimal sayı sisteminde 39 a karşılık gelmektedir.
{: .prompt-tip }

![Desktop View](/images/post1/img6.png){: width="663" height="533" }

Yani bizim ulaşmamız gereken entry PML4 sayfası içerisinde FF = 255.entry 1 entrynin size'ı pointer olduğu için 8 olduğuna göre 255.entrymiz ;

```
uint64_t pml4_offset = 255 * 8 = 0x7F8(2040);
```

PML4 başlangıcından 0x7F8 uzaklıkta.

![Desktop View](/images/post1/img7.png){: width="169" height="468" }

```
kd> !dq 86394000 + (0xFF * 8)
#863947f8 0a000000`863a0867 00000000`00000000
#86394808 00000000`00000000 00000000`00000000
#86394818 00000000`00000000 00000000`00000000
#86394828 0a000000`86395863 00000000`00000000
#86394838 00000000`00000000 00000000`00000000
#86394848 00000000`00000000 00000000`00000000
#86394858 00000000`00000000 00000000`00000000
#86394868 00000000`00000000 00000000`00000000
```

```cpp
uint64_t pdpt_base = pml4_entry & FFFFFF000; //  pml4_entry = 0a000000`863a0867 
// Bir adresse ile FFFFFF000 AND işlemi yapmak onun PFN'ini alıp 0x1000 ile çarpmak demektir = 0x863A0000 PDPT base adressi
```
Indexden okuduğumuz değeri 0xFFFFFF000  ile AND işlemi yaptığımızda elde ettiğimiz sonuç PDPT base adresi oluyor. Bundan sonraki adımlardada aynı işlemleri yapıyoruz ve zincir boyunca ilerliyoruz.

```
//pdpt_index  = (7fffae410000 >> 30 & 0x1FF) == 0x1FE
//pdpt_offset = (0x1FE * 0x8) == 0xFF0
//pdpt_entry  =  (pdpt_base + pdpt_offset) 

kd> !dq 0x863A0000 + 0xFF0
#863a0ff0 0a000000`863a3867 00000000`00000000
#863a1000 00000000`00000000 00000000`00000000
#863a1010 00000000`00000000 00000000`00000000
#863a1020 00000000`00000000 00000000`00000000
#863a1030 00000000`00000000 00000000`00000000
#863a1040 00000000`00000000 00000000`00000000
#863a1050 00000000`00000000 00000000`00000000
#863a1060 00000000`00000000 00000000`00000000

//pdt_base = (0xa000000863a3867 & FFFFFF000) = 0x863A3000

//pdt_index  = (7fffae410000 >> 21 & 0x1FF) == 0x172
//pdt_offset = (0x172 * 0x8) == 0xB90
//pdpt_entry  =  (pdt_base + pdt_offset)  // 0x863A3000 + 0xB90

kd> !dq 0x863A3000 + 0xB90
#863a3b90 0a000000`863a4867 0a000000`863a5867
#863a3ba0 00000000`00000000 00000000`00000000
#863a3bb0 00000000`00000000 00000000`00000000
#863a3bc0 00000000`00000000 00000000`00000000
#863a3bd0 00000000`00000000 00000000`00000000
#863a3be0 00000000`00000000 00000000`00000000
#863a3bf0 00000000`00000000 00000000`00000000
#863a3c00 00000000`00000000 00000000`00000000

//pt_base = (0xa000000863a4867 & FFFFFF000) = 0x863A4000
//pt_index  = (7fffae410000 >> 12 & 0x1FF) == 0x10
//pt_offset = (0x10 * 0x8) == 0x80
//pt_entry  =  (pt_base + pt_offset)  // 0x863A4000 + 0x80

kd> !dq 0x863A4000 + 0x80
#863a4080 86000001`05ada025 06000001`08ce5005
#863a4090 06000001`08ce8025 06000001`08ce7025
#863a40a0 06000001`08ce6025 06000001`08d67025
#863a40b0 06000001`08d6e025 06000001`06e6d025
#863a40c0 06000001`08d6c025 01000001`08d6b025
#863a40d0 01000001`08d6a025 01000001`08d69025
#863a40e0 01000001`06e68005 01000001`05325005
#863a40f0 01000001`05327025 01000001`05326005

//pte_base = (0x8600000105ada025 & FFFFFF000) = 0x105ADA000

```

Yukarıda bulduğumuz `0x105ADA000` zincirimizin son halkası ve tam olarak Virtual adresimizin bulunduğu sayfanın physical memorydeki base adresi. Virtual adressimizin ilk 12 biti bize Physical adress sayfasından başlangıç uzaklığını verdiği yukarıdaki resimlerde vermiştik. Buna göre ;

```cpp
uintptr_t pte_offset = (7fffae410000 & 0xFFF); // Yani 0;
```

>0xFFF'i hesap makinesinin bit kısmında incelerseniz 12 adet bitin 1 olduğunu farkediceksiniz ve bunuda bizim Virtual adressimizle AND yapınca bize ilk 12 bitindeki değeri vericektir.
{: .prompt-tip }

Bizim örneğimizde bu offset 0 olduğu için bizim `7fffae410000` Virtual adressimizin Physical adressdeki yeri `0x105ADA000` Gelin bunu birlikte Windbg'da deniyelim.

>Windbg da ulaşmaya çalıştığımız adress eğer Physical ise db komutunun başına ! işareti koymalıyız çünkü debuggerimiz ona göre okumaya çalışıyor. Eğer Virtual address ise ! işareti koymamıza gerek yok.
{: .prompt-tip }

Ilk olarak `7fffae410000` addresindeki Ntdll.dll modulümüzün memory regionunu Virtual Adress olarak görüntüleyelim.


![Desktop View](/images/post1/img8.png){: width="682" height="191" }

Ve şimdi gelin Physical adressimiz ile bunu görüntüleyelim :nerd_face:

![Desktop View](/images/post1/img9.png){: width="682" height="191" }

Veee evet birebir aynı ! Hedeflediğimiz Virtual adressi ramimizin üzerindeki Physical adressini bulduk :muscle:

Bir başka konuda görüşmek üzere :wave: