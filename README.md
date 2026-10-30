# ACS Lab Studio

**Vantiva EGA225CTRN3 / GENT-R** için yerel PPPoE ve TR-069 (ACS) test ve yapılandırma aracı. Bilgisayarın Ethernet bağlantısı üzerinden çalışır. Güncel sürüm: **v1.15**.

## Başlamadan önce

**İşlem yapmadan önce router yapılandırmanızın ve önemli verilerinizin yedeğini alın.** Geri yükleme yöntemini bildiğinizden emin olun. Studio, router'ın tam yedeğini otomatik almaz.

Yalnızca sahibi olduğunuz veya yönetmeye yetkili olduğunuz cihazlarda, izole bir test ortamında kullanın. Operatörün WAN/ONT bağlantısını test sırasında ayırın. Kullanımdan doğabilecek erişim kaybı, veri kaybı, hizmet kesintisi ve diğer sonuçların tüm sorumluluğu kullanıcıya aittir. Yazılım herhangi bir garanti verilmeden sunulur.

## Cihaz ve platform durumu

- **Marka / model:** Vantiva EGA225CTRN3.
- **Donanım:** GENT-R.
- **Denenen firmware:** Mushu 23.1.a, `23.1.a.0698-1521021`; web arayüzü `EGA225CTRN-R2-RC4`.
- Diğer model ve firmware sürümleri için uyumluluk doğrulanmamıştır. Aynı modelin stok durumunda ilk root erişimi sağlayacağı garanti edilmez.

| Platform | Durum | Başlatma |
| --- | --- | --- |
| macOS | Laboratuvar cihazında denendi | `Baslat.command` |
| Linux | Deneysel, gerçek donanım doğrulaması bekliyor | `sh Baslat.sh` |
| Windows | Deneysel, Npcap + WSL 2 gerekiyor | `Baslat.cmd` |

USB veya dahili Ethernet seçilebilir. Linux ve Windows'ta kart/sürücü uyumluluğu ayrıca sınanmalıdır.

## Neler yapar?

- WAN MAC adresini ve görünen VLAN etiketini keşfeder. Varsayılan VLAN **35**'tir.
- Salt okunur keşif, sistem günlüğü aktarımı ve yazma/geri alma testleri sunar.
- Mevcut web admin hesabına engineer rolü verir.
- engineer ve superuser CLI hesaplarının LAN SSH izinlerini, kalıcılığını ve parolasını düzenler.
- Uyumlu firmware'de Linux root parolasını ACS üzerinden değiştirmeyi dener. Bu işlem THENC anahtarı veya WPS düğmesi gerektirmez.

**Web admin rolü, CLI hesabı ve Linux root hesabı ayrı işlemlerdir.** CLI hesap izni veya root parolası değiştirmek SSH hizmetini kendiliğinden açmaz. Root SSH için hizmet ve root giriş izinleri ayrıca açık olmalıdır. Parola değişikliğini yeni bir SSH bağlantısıyla doğrulayın; o zamana kadar mevcut yönetim oturumunu açık tutun.

## Kurulum ve kullanım

macOS ve Linux için Python 3.9+, Scapy, pppd ve OpenSSL gerekir. Linux'ta ayrıca iproute2 ve çekirdek PPP desteği gerekir. Başlatıcı ağ işlemleri için yönetici yetkisi ister.

```sh
python3 -m venv .venv
.venv/bin/python3 -m pip install -r requirements.txt
```

Linux sistem paketleri ve ayrıntılar: [Teknik kılavuz](GUIDE.md). Windows'ta önce [Windows kurulumunu](WINDOWS.md) tamamlayın; `Kurulum.cmd`, `Kontrol.cmd` ve yönetici olarak `Baslat.cmd` sırasını izleyin.

1. Bilgisayarın Ethernet bağlantısını Vantiva'nın **WAN / Internet** portuna takın.
2. Sisteminizin başlatıcısını açın. Panel: **http://127.0.0.1:8890**.
3. Adaptörü seçip kontrol edin. **WAN cihazını keşfet** ile bulunan cihazı seçin.
4. Önce **Salt okunur keşif**, ardından **Standart log aktarımı testi** çalıştırın.
5. Sonucu kontrol edip istediğiniz ayarları seçin. Her değişiklikten sonra cihaz üzerindeki etkisini doğrulayın.

SSH veya web yönetimi için ayrıca router'ın LAN ya da Wi-Fi ağına bağlı olun. Yönetim IP adresi panelden değiştirilebilir; `192.168.1.131` kullanmak zorunlu değildir. Keşifte paket gelmiyorsa WAN kablosunu çıkarıp tekrar takın.

## Kayıtlar ve kurtarma

Oturumlar `.runs/`, kurtarma kayıtları `.state/` içinde tutulur; hassas cihaz bilgileri içerebilir. Bu klasörleri paylaşmayın ve bekleyen geri alma kaydı varken silmeyin. Yazma/geri alma sürerken programı zorla kapatmayın. Kesinti sonrası paneldeki kurtarma adımlarını izleyin.

Ayrıntılı kurulum, işlem sınırları ve kurtarma: [GUIDE.md](GUIDE.md). Windows desteği: [WINDOWS.md](WINDOWS.md). Sürüm geçmişi: [CHANGELOG.md](CHANGELOG.md).
