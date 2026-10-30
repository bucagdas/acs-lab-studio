# Teknik kullanım kılavuzu

Vantiva EGA225CTRN3 / GENT-R için ACS Lab Studio teknik ayrıntıları. Başlamadan önce [README](README.md) içindeki yedekleme ve sorumluluk notunu okuyun. Sürüm geçmişi [CHANGELOG](CHANGELOG.md) dosyasındadır.

## Başlatma

Aynı klasör/paket üç sistem içindir; Studio çalışma ortamını otomatik algılar. Mac’te Baslat.command, Linux’ta Baslat.sh, Windows’ta Baslat.cmd kullanılır. Python 3.9+, pppd ve OpenSSL gerekir. Linux'ta ayrıca iproute2 ve çekirdekte PPP desteği gerekir. Scapy aynı Python ortamında bulunmalıdır. tcpdump, ek PPP tanılama kaydı için isteğe bağlıdır. Ağ motoru ham Ethernet ve ayrıcalıklı portlar için yönetici yetkisi ister. Mac/Linux bağımlılıkları elle kurulur. Windows için Kurulum.cmd Windows ve WSL Python ortamlarını hazırlar; WSL ve Npcap önceden kurulmalıdır.

### macOS

`Baslat.command` dosyasını çalıştırın. Terminalde istenen parola bilgisayarın yönetici parolasıdır. Bu başlatıcı mevcut Python ortamını kullanır; klasörde `.venv/bin/python3` varsa onu tercih eder.

### Linux - deneysel

Önce Ubuntu/Debian üzerinde gerekli paketleri kurun; bu komutlar ACS Lab Studio klasöründe çalıştırılır:

```sh
sudo apt update
sudo apt install python3 python3-venv ppp iproute2 openssl tcpdump
python3 -m venv .venv
.venv/bin/python3 -m pip install -r requirements.txt
```

Fedora ve diğer dağıtımlarda aynı bileşenleri dağıtımınızın paket yöneticisiyle kurun. Gerekli PPP seçenekleri için pppd 2.4.9 veya 2.5.x kullanın. Bu bölüm yerel Linux içindir. Windows için WSL 2, aşağıdaki özel paket köprüsüyle kullanılır; sıradan WSL sanal ağı üzerinden doğrudan Ethernet seçimi yapılmaz. Konteynerler destek kapsamında değildir.

`/dev/ppp` yoksa çekirdek modüllerini yükleyin:

```sh
sudo modprobe ppp_generic
sudo modprobe ppp_async
```

Başlatın:

```sh
sh Baslat.sh
```

Betik `.venv` ortamını seçip gerektiğinde `sudo` ister. Panel **http://127.0.0.1:8890** adresindedir. Linux ekranının üstünde **Linux · deneysel** yazar. Fiziksel Ethernet adaptörleri `eth0`, `enp3s0`, `enx…` gibi kendi adlarıyla listelenir; Wi-Fi, sanal köprü, veth ve VLAN alt arayüzleri filtrelenir. VLAN 35 etiketi motor tarafından fiziksel adaptör üzerinden gönderilir; ayrı bir VLAN arayüzü oluşturmayın.

Ethernet adaptörünün yönetimsel olarak açık olması gerekir. Bağlantı pasif görünüyorsa kabloyu ve sistem ağ ayarlarını kontrol edin; arayüz kapalıysa kendi adaptör adınızla `sudo ip link set dev enp3s0 up` kullanabilirsiniz. Studio diğer ağ bağlantılarınızı veya NetworkManager ayarlarınızı otomatik değiştirmez.

Linux testinde DNS/NTP yalnızca bilgisayarın PPP test IP'sini, ACS ise PPP ve ACS test IP'lerini dinler. Bu sayede loopback'te çalışan masaüstü DNS servisiyle çakışma önlenir. Aynı test IP/portlarını kullanan başka servis varsa önceki oturumu kapatın. Güvenlik duvarı filtreliyorsa yalnızca izole PPP bağlantısına ait trafiğe izin verilmesi gerekir; Studio güvenlik duvarını değiştirmez.

### Windows - deneysel Npcap + WSL 2

Ayrıntılı kurulum: [WINDOWS.md](WINDOWS.md). Önce 64 bit Python, WSL 2 üzerinde Ubuntu/Debian ve güncel Npcap kurun. Paketi çıkarıp Kurulum.cmd, ardından Kontrol.cmd çalıştırın. Baslat.cmd dosyasını yönetici olarak açın. USB veya dahili Ethernet kartını panelde Windows'taki adıyla seçin.

Fiziksel kart Windows'ta kalır; USB/IP aktarımı gerekmez. Yalnızca seçilen kartın PPPoE paketleri süreç giriş/çıkışı üzerinden WSL'deki Linux motoruna aktarılır. Windows kartının IP/VLAN ayarları veya güvenlik duvarı otomatik değiştirilmez. Sürücü/VLAN uyumluluğu gerçek cihazda ayrıca sınanmalıdır.

### İlk bağlantı

1. Vantiva WAN portunu bilgisayarın Ethernet adaptörüne bağlayın.
2. Panelde adaptörü seçip **Adaptörü kontrol et** düğmesine basın.
3. **WAN cihazını keşfet** ile MAC/VLAN bilgilerini alın; bulunan bağlantıyı seçin. VLAN başlangıç değeri 35'tir.
4. Önce **Salt okunur keşif**, ardından **Standart log aktarımı testi** ile bağlantıyı doğrulayın. Yeni Linux uyarlamasında önce bu iki adımın gerçek cihazda tamamlanması gerekir.
5. Ayar değiştirecekseniz **Seçilen ayarları uygula** veya root parola modunu seçin. Seçenekler ilgili kartın içinde açılır. LAN SSH hesap izni işaretlenince hesap seçimi, açma seçilince ek hesap seçenekleri görünür. Gizli seçenekler isteğe eklenmez.

Yalnızca arayüz önizlemesi; ağ testi başlatamaz:

```sh
python3 app.py --preview
```

## Platform doğrulaması

Mac üzerinde 91 Python testi ve 6 frontend durum testi; Linux adaptör filtreleme, kablo durumu, PPP komutları, geçici IP ekleme, oturuma ait PPP bağlantısını seçme, Linux dinleyici adresleri ve mevcut ACS işlemlerini sınar. Linux sistem yanıtları bu testlerde taklit edilir; bu sonuç gerçek Linux donanım testi değildir. Her iki motorun Linux PPP komutu üretmesi ve yalnızca kendi alt sürecini temizlemesi de sınanır.

Windows testleri; ikili kanalda parçalı okuma/yazma, yalnızca PPPoE aktarımı, USB/dahili kart listesi, kart seçim izinleri, kaynak MAC denetimi, bırakma/kapanış, WSL sanal NAT adaptörünün dışlanması ve güncellemede kurtarma kayıtlarının korunmasını kapsar. Bunlar taklit sürücü yanıtları ve yerel alt süreçlerle sınanır; gerçek Windows/Npcap testi değildir.

Linux ve Windows'ta kalan canlı doğrulama sırası: PADI → PPP/IP → ACS bildirimi → salt okunur sonuç → log aktarımı → yazma/geri alma → seçilen ayarlar. Windows'ta USB ve dahili kartta ayrı ayrı doğrulanmalıdır.

Teknik dayanaklar: [pppd upstream kılavuzu](https://github.com/ppp-project/ppp/blob/master/pppd/pppd.8), [Debian pppd 2.4.9 kılavuzu](https://manpages.debian.org/bookworm/ppp/pppd.8.en.html). Linux için kullanılan `ifname`, `logfd` ve `nodefaultroute` seçenekleri bu kılavuzlarda yer alır.

## İşlem sonrası CWMP

Tüm ACS işlemleri ve doğrulamalar tamamlandıktan sonra aynı operatör altyapısında kullanıma devam edecekseniz, WAN/ONT bağlantısını geri takmadan önce router'ın web arayüzünden **CWMP / TR-069'u kapatın**. Operatör ACS'si mevcut ayarları yeniden uygulayabilir. Studio bu seçeneği otomatik kapatmaz. CWMP test sırasında açık kalmalıdır; erken kapatırsanız ACS işlemleri ve geri alma kesilebilir.

## Bağlantı düzeni

```text
Router WAN  ← Ethernet / VLAN 35 →  Bilgisayar test ACS
Router LAN  ← Wi-Fi             →  Bilgisayar SSH / web yönetimi
```

Operatörün ONT bağlantısı test sırasında WAN'dan ayrılmış olmalı. Araç bilgisayarda çalışır; router'a 192.168.1.131 adresinden kurulmaz. **IP adresleri ve ağ ayarları** bölümünden LAN yönetim IP'si, bilgisayar PPP IP'si, router PPP IP'si ve ACS IP alias değiştirilebilir. LAN yönetim IP'si yalnızca bilgilendirme içindir; ACS işlemleri WAN üzerinden yürür. Varsayılan LAN adresi `192.168.1.131`, test PPP ağı bilgisayar `10.116.13.100` / router `10.116.13.101` olarak ayrıdır. WAN IPv4 bağlantısı kurulduktan sonra cihazın otomatik CWMP denemesi beklenir; her denemede reboot gerekmez. PADI gelmezse WAN bağlantısını yeniden tetiklemek gerekebilir.

Başlatma; tek hedef MAC için PPPoE yanıtlayıcısı, DNS/NTP ve test ACS servisleri açar. macOS'ta ACS/DNS/NTP dinleyicileri mevcut davranışla tüm IPv4 arayüzlerinde, Linux'ta yalnızca test IP adreslerinde dinler. Aracı izole laboratuvarda çalıştırın. Web kontrol paneli yalnızca `127.0.0.1` üzerinde dinler. Test sırasında internet hizmeti sağlanmaz. Güvenlik duvarı ayarı otomatik değiştirilmez.

Başka bir test betiği çalışıyorsa önce onu durdurun. Test dinleyici adreslerinde kullanımda olan 53/80/123/443 portları yeni testin başlamasını engeller. Araç ilgisiz pppd süreçlerini sonlandırmaz.

## İşlem ayrıntıları

### Seçilen ayarları uygula

Web rolü: **Mevcut admin kullanıcısına engineer web rolü ver** seçeneği, `Device.Users.User.` altında kullanıcı adlarını keşfeder. `Username=admin` olan tek kayıt seçilir; numarası sabit kabul edilmez. `X_000E50_Role` alanının yazılabilirliği ve mevcut değeri doğrulanır, `engineer` yazılır ve kullanıcı adı/rol tekrar okunur. Kullanıcı adı ve web parolası değiştirilmez. Admin kaydı veya seçilen herhangi bir alan doğrulanamazsa yazma yapılmaz. Mevcut rol raporda saklanır; otomatik geri alma yapılmaz.

SSH ayarları isteğe bağlıdır. Ayrı hedef, veri modelinden önce okunarak doğrulanan `engineer` (CliUsers.1) veya `superuser` (CliUsers.2) hesabıdır. İşlemler ayrı seçilir:

- LAN SSH erişimini aç: `Access=LAN`, `Enable=1`.
- CLI hesabının SSH erişimini kapat: `Access=NONE`, `Enable=0`.
- RebootPersistent değerini 1 veya 0 yap.
- CLI hesabına yeni parola belirle.

Yalnızca seçilen alanlar tek bir `SetParameterValues` isteğinde yazılır; okunabilir alanlar sonrasında tekrar okunur. Bunlar yapılandırma işlemleridir, test sonunda otomatik geri alınmaz. SSH izninin reboot sonrası korunması RebootPersistent ayarına bağlıdır. `Status=1` cihazın ayarları kabul ettiğini, bazı çalışma zamanı etkilerinin ertelenebileceğini gösterir.

Parola alanı geri okunamaz. Parola yazımı kabul edilirse panel **SSH ile doğrula** sonucunu gösterir; başarılı parola girişini iddia etmez. Parola sadece alt işleme stdin üzerinden aktarılır; ayar/rapor dosyalarına kaydedilmez ve SOAP izinde bu yeni parola maskelenir. İzin verilen karakterler 12–64 adet harf, rakam, `_ . @ + -` ile sınırlıdır; firmware'in shell tabanlı parola işleyicisine komut karakterleri geçirilmez.

Bu hesaplar web `admin` ve Linux `root` hesabından ayrıdır. CLI parolası root parolasını değiştirmez; LAN SSH açmak restricted_shell kısıtını kaldırmaz. Web admin rolü, engineer/superuser SSH hesapları ve Linux root hesabı ayrı işlemlerdir. Web rolü değişince LAN/Wi-Fi üzerinden web arayüzünden çıkış yapıp mevcut admin adı ve mevcut web parolasıyla yeniden giriş yapın. SSH ayarları da seçildiyse ayrıca seçilen SSH hesabıyla giriş yapın.

### Web rolü, SSH hesap izni ve SSH hizmeti

`admin → engineer` yalnızca web arayüzü rolünü değiştirir. Kullanıcı adı admin kalır; admin adlı bir Linux/SSH hesabı oluşturulmaz. SSH listesinde cihazın mevcut engineer ve superuser hesapları bulunur; bu hesaplar sınırlı kabuk kullanır.

**LAN SSH hesap izni** yalnızca seçilen CLI hesabının `Access` ve `Enable` alanlarını değiştirir. Dropbear hizmetini veya root giriş iznini açmaz. **Linux root parolasını değiştir** yalnızca root parolasını değiştirir; SSH hizmetini açmaz. Root SSH bağlantısı için hizmet, root giriş izni ve parola doğrulaması ayrıca açık olmalıdır.

Salt okunur keşif, ACS sunuyorsa LAN Dropbear etkinlik, port ve parola giriş izinlerini okur. Paneldeki **Ayar açık** hizmetin yapılandırmasını belirtir; çalıştığını veya bağlantının başarılı olacağını kanıtlamaz. Sunulmayan alanlar **bilinmiyor / doğrulanmadı** kalır. Mevcut oturumda okuma yapılmadıysa **henüz okunmadı** gösterilir.

### Linux root parolasını ACS ile değiştirme

**Linux root parolasını değiştir** ayrı çalışma modudur. Yeni parolayı iki kez girin ve onay kutusunu işaretleyin. Uygulama, bu firmware’de laboratuvar cihazında denenmiş STS Vendor Configuration aktarımını hedef WAN MAC’i doğrulandıktan sonra başlatır. Bu, stok cihazlarda veya başka firmware sürümlerinde çalışacağına dair garanti değildir.

Parola 12–64 karakter olmalı ve yalnızca harf, rakam, `_ . @ + -` içermelidir. Web arayüzü parola alanlarını istekten sonra temizler; ACS Lab parola içeriğini oturum durumuna, rapora veya uygulama günlüğüne eklemez. Aktarım hatası durumunda sonucu başarısız gösterir. `TransferComplete FaultCode=0` geldiğinde yalnızca **SSH ile doğrulama bekleniyor** gösterir; bunu parola değişti diye raporlamaz.

Ekrandaki `ssh root@<yönetim-IP>` komutunu bilgisayarın terminalinde, Vantiva LAN/Wi-Fi ağına bağlıyken çalıştırın. Yeni parolayla giriş başarıyla tamamlanana kadar mevcut yönetim oturumunu veya erişim yolunu kapatmayın. Parola değişikliği otomatik geri alınmaz. Bu mod diğer seçili ayarlardan bağımsızdır ve admin web rolü veya CLI hesabı parolalarını değiştirmez.

### Salt okunur keşif

`Inform → InformResponse → GetRPCMethods → GetParameterNames → GetParameterValues` akışını yürütür. `Device.Services.X_000E50_AccessManagement.SSH.CliUsers.` altındaki Username, Enable, Access ve RebootPersistent alanlarını okur. Password okumaz veya SetParameterValues göndermez.

### Yazma ve geri alma

İlk olarak `CliUsers.1.Username=engineer`, `Enable=0`, `Access=NONE` ve `RebootPersistent=1` başlangıç koşullarını doğrular. Yalnızca aynı hesabın RebootPersistent değerini 0 yapar, 0 okumasını doğrular, 1'e geri getirir ve 1 okumasını doğrular.

Başarı: `WRITE_TEST_PASS_RESTORED` mesajı **ve** diskte `status=restored, toggle_verified=true` kaydı birlikte gerekir. RPC yanıtının gelmesi tek başına başarı değildir. Status=1 yanıtı çalışma zamanı etkilerinin tamamının hemen uygulandığını kanıtlamaz; rapor parametre okumasını doğrular.

Yazma/geri alma sırasında Durdur devre dışıdır. Testin süresi dolarsa veya bağlantı kesilirse geri alma garanti edilemez; panel bunu **Geri alma gerekli** olarak gösterir. Bekleyen kayıtla yazma testini tekrar başlatmak önce eski değeri geri almaya çalışır. Parola, root kabuğu, Enable veya Access ayarları değiştirilmez.

## Router üzerinde elle geri alma

Router'ın SSH terminalinde:

```sh
transformer-cli set Device.Services.X_000E50_AccessManagement.SSH.CliUsers.1.RebootPersistent 1
transformer-cli apply
transformer-cli get Device.Services.X_000E50_AccessManagement.SSH.CliUsers.1.RebootPersistent
```

Son okuma 1 olmalı. Bekleyen journal varsa yazma testini yeniden başlatın; araç ACS üzerinden geri almayı doğrulamadan kaydı başarılı saymaz. Journal dosyasını silerek başarı üretmeyin.

## Bilgisayarda geçici PPP ayarı

macOS ve Linux pppd, `/etc/ppp/pap-secrets` dosyasını kullandığı için motor test süresince laboratuvar eşine yönelik geçici bir PAP kuralı yazar. Boş secret davranışıyla operatör PPP parolası gerektirmez. Orijinal dosya, modu ve sahipliği özel oturum klasörüne kaydedilir; normal kapanışta geri alınır. `/etc/ppp/ip-up` değiştirilmez.

Program zorla kapatılırsa veya bilgisayar kapanırsa otomatik geri alma tamamlanamayabilir. Bekleyen PAP kurtarma kaydı yeni testi engeller. Önce Studio panelindeki **Ağ ayarını kurtar** düğmesini kullanın. Router bağlı olmak zorunda değildir. Kurtarma yalnızca çalışan test olmadığında yapılır; dosya dışarıdan değiştirilmişse durur. Aynı bilgisayardaki başka bir Studio ağ oturumu da ortak kilitle korunur.

Alternatif olarak Studio kapalıyken, mevcut oturum ve kurtarma kayıtlarını içeren klasörde:

```sh
sudo python3 recover_network.py
```

Bu komut yalnızca dosya hâlâ bu aracın geçici içeriğini taşıyorsa orijinali geri yükler. Dosya dışarıdan değişmişse üzerine yazmaz. `.runs/<oturum>/pap-original` yedeği ve `.state/pap-recovery.json` kaydı inceleme için kalır. Eski, araç dışındaki betiklerin bıraktığı sistem değişikliklerini otomatik düzeltmez.

## Günlükler ve veri

- Panelde canlı, süzülmüş işlem günlüğü gösterilir. **Raporu indir** JSON özeti ve bu günlüğü verir; dosya sahipliğini değiştirmeniz gerekmez.
- `.runs/<oturum>/cwmp-private.log` ham SOAP içerebilir. Yapılandırma modunda yeni girilen CLI parolası bu izde maskelenir. Diğer cihaz bilgileri ve PAP kurtarma yedeği hassastır; özel klasörde tutulur, panelden indirilmez.
- `.runs/<oturum>/configuration-state.json` seçilen alanların önceki değerlerini, istenen okunabilir değerleri ve doğrulama durumunu içerir. Parola içermez.
- `.state/write_probe_state.json` yarıda kalan yazmanın geri alma kaydıdır. `.state/pap-recovery.json` bilgisayardaki geçici PAP ayarının kurtarma kaydıdır.
- Kaynak/ZIP paketi geçmiş log, cihaz anahtarı veya kullanıcıya ait PPP parolası içermez.
- Test sunucusu, mevcut motorla uyumlu laboratuvar ACS kimlik bilgilerini (`ftacs`) kullanır. Bunlar değiştirilmediyse son başarılı denemedeki akışla uyumludur. Connection Request parola denemesi yapılmaz.

## Doğrulama ve kapsam

```sh
python3 -m unittest discover -s tests -v
```

Kontroller; girdi sınırları, kayıt bozulması, başarı kanıtı, geri alma sırasında durdurmayı engelleme, salt okunur sonuç ve çıktı süzmesini kapsar. Yeni panel gerçek router'da yeniden denenene kadar önceki betiklerin canlı başarısıyla yeni panelin doğrulaması ayrı tutulur.

Canlı doğrulama, daha önce root erişimi bulunan laboratuvar cihazında yapıldı. Bu sonuç, aynı akışın stok cihazda ilk root erişimini sağlayacağını veya farklı firmware sürümlerinde çalışacağını garanti etmez.


Frontend durum testleri için `node --test tests/test_access_state.cjs` kullanılır. Uygulamayı çalıştırmak için Node gerekmez.
