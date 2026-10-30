# Windows kurulumu

v1.15, Windows üzerinde **deneysel Npcap + WSL 2 köprüsü** içerir. USB Ethernet ve dahili kablolu Ethernet aynı yöntemle listelenir. Kart Windows'ta kalır; USB/IP aktarımı gerekmez. Bu sürüm gerçek Windows bilgisayar/router üzerinde henüz uçtan uca doğrulanmadı. Mac'teki sentetik testler, Windows sürücüsü veya VLAN uyumluluğunun kanıtı değildir.

## Gerekenler

- Windows 10/11, x64 veya ARM64; 64 bit Python 3.9 veya üzeri.
- WSL 2 üzerinde kurulumu tamamlanmış Ubuntu/Debian. Otomatik Linux paket hazırlığı bu dağıtımlar içindir.
- Güncel Npcap. VLAN desteği için en az 1.88 kullanın; sürücü paketle birlikte dağıtılmaz.
- Router WAN portuna bağlı, VLAN etiketli Ethernet paketlerini alıp gönderebilen USB veya dahili Ethernet kartı.

Python: [resmi indirme sayfası](https://www.python.org/downloads/windows/).
Npcap: [resmi indirme sayfası](https://npcap.com/#download).
Scapy, Windows'ta Npcap gerektirir; [kurulum yönergesi](https://scapy.readthedocs.io/en/stable/installation.html#windows).

WSL 2 yoksa Windows terminalinde:

```powershell
wsl --install -d Ubuntu
wsl --update
```

Gerekli Windows yeniden başlatmasını tamamlayın, Ubuntu'yu bir kez açıp kullanıcı kurulumunu bitirin. `wsl --list --verbose` çıktısında dağıtımın sürümü 2 olmalıdır. Bu işlemler uygulama tarafından otomatik başlatılmaz.

## İlk çalıştırma

1. ZIP paketini tamamen çıkarın. `Baslat.cmd` dosyasını arşiv içinden çalıştırmayın.
2. Npcap'i resmi yükleyiciyle kurun. Güncel Scapy belgesi WinPcap uyumluluk modunu kapalı bırakmayı önerir.
3. İnternet erişimi varken **Kurulum.cmd** dosyasını açın. Windows için `.venv-win` hazırlanır. WSL tarafına Python, Scapy, PPP, iproute2, OpenSSL ve çekirdek modülleri kurulur/yüklenir. Bu adım router ayarlarını değiştirmez.
4. **Kontrol.cmd** ile Npcap, WSL bağımlılıkları ve fiziksel Ethernet listesini kontrol edin. Bu kontrol paket dinlemez veya ağ testi başlatmaz. Kartın kablo bağlı değilken pasif görünmesi normaldir.
5. Router WAN portunu Ethernet kartına bağlayın. **Baslat.cmd** dosyasını sağ tıklayıp yönetici olarak çalıştırın.
6. Panel `http://127.0.0.1:8890` adresinde açılır. Kartı Windows'taki adıyla seçin. Önce **WAN cihazını keşfet**, sonra **Salt okunur keşif** ve **Standart log aktarımı testi** çalıştırın.

Birden fazla WSL dağıtımı varsa başlatıcı seçim ister. Belirli dağıtım veya farklı panel portu için terminalden:

```bat
Baslat.cmd --distro Ubuntu --port 8891
```

Kartları uygulama başlamadan önce takın. Sonradan yeni kart eklediyseniz panel oturumunu kapatıp yeniden açın.

## Nasıl çalışır?

Windows başlatıcısı fiziksel kablolu kartları `Get-NetAdapter -Physical` ile listeler. USB ve dahili Ethernet için aynı Npcap yolu kullanılır. Wi-Fi ve WSL'nin sanal NAT adaptörü hedef listesine alınmaz.

Her kart için WSL'de geçici, IP adresi olmayan bir TAP karşılığı oluşturulur. Panelde keşif/test başlatılınca yalnızca seçilen Windows kartı dinlenir. Windows ve WSL arasında yalnızca PPPoE Ethernet paketleri, `wsl.exe` sürecinin ikili giriş/çıkış kanalı üzerinden taşınır. Paket köprüsü için ek TCP/UDP portu veya Windows Ethernet köprüsü açılmaz.

PPP/IP, DNS/NTP ve ACS işlemleri mevcut Linux motorunda yürür. Windows'taki fiziksel kartın IP adresi, yönlendirmesi, VLAN sürücü ayarı ve güvenlik duvarı uygulama tarafından değiştirilmez. Yeni TAP bağlantıları kapanışta silinir. SSH ile doğrulama için bilgisayarın ayrıca router'ın LAN/Wi-Fi ağına bağlı olması gerekir.

Windows başlatıcısı Ubuntu'yu root olarak çalıştırır. Npcap paket erişimi için başlatıcı yönetici olarak açılır. Npcap kurulumu, lisans onayı ve Windows özelliklerini etkinleştirme işlemleri kullanıcıya aittir; uygulama bunları sessizce yapmaz.

## Kayıtlar, güncelleme ve kapanış

WSL çalışma kopyası `/var/lib/acs-lab-studio` altındadır. Oturum kayıtları `.runs`, geri alma kayıtları `.state` içindedir. Windows klasörünün NTFS izinlerine güvenilmediği için özel kayıtlar Linux dosya sisteminde tutulur. Raporu panelden indirebilirsiniz.

Yeni ZIP sürümüne geçerken mevcut oturumu kapatın, yeni paketi çıkarın ve **Kurulum.cmd** dosyasını tekrar çalıştırın. Kod güncellenir; WSL'deki `.runs` ve `.state` korunur. Kaynak klasördeki eski oturumlar veya parolalar WSL'ye kopyalanmaz.

Çıkmadan önce panelde işlemi bitirin, ardından terminalde Ctrl+C kullanın. Yazma/geri alma sürüyorsa normal kapanış reddedilir. Terminal zorla kapanır veya fiziksel bağlantı kesilirse otomatik geri alma garanti edilemez; sonraki oturumda bekleyen kaydı kontrol edin. Araç başka WSL dağıtımlarını kapatmaz veya ilgisiz PPP süreçlerini sonlandırmaz.

## Uyumluluk ve kalan doğrulama

WSL'de `/dev/net/tun`, `/dev/ppp` veya `ppp_async` eksikse hazırlık durur. Önce `wsl --update` uygulayın; WSL'nin gerek gördüğü yeniden başlatma adımlarını tamamlayın. Stok WSL çekirdeğinde gereken modüller bulunmuyorsa ortam desteklenmiş sayılmaz. USB Ethernet sürücüsünün Linux'ta bulunması gerekmez; fiziksel sürücü Windows'ta çalışır.

Npcap'in yeni sürümleri VLAN etiketlerini alma/gönderme desteği sunar, ancak kartın ve sürücüsünün ilgili VLAN'a izin vermesi gerekir. VLAN görünmüyorsa veya PPPoE kurulmazsa kart/sürücü uyumluluğu ayrıca kontrol edilmelidir; araç bunu gizleyerek başarı göstermez. Otomatik kayıt defteri veya sürücü ayarı değişikliği yapılmaz.

Kalan canlı test sırası: USB kartta PADI → PPP/IP → ACS salt okunur sonuç → log aktarımı; ardından dahili kartta aynı adımlar. Bunlardan sonra yazma/geri alma ve seçilen ayarlar doğrulanmalıdır. Windows sürümü bu testler bitene kadar deneysel kalır.

Kaynaklar: [Microsoft WSL kurulum ve komutları](https://learn.microsoft.com/en-us/windows/wsl/basic-commands), [Windows'tan WSL uygulamalarına localhost erişimi](https://learn.microsoft.com/en-us/windows/wsl/networking), [Npcap VLAN değişiklikleri](https://npcap.com/changelog), [Microsoft WSL çekirdek yapılandırması](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.6.y/arch/x86/configs/config-wsl).
