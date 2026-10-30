# Sürüm geçmişi

## v1.17.2

- Stok cihazda parola kabul edilmesine rağmen root oturumunun hemen kapanmasına yol açan restricted shell kısıtı ele alındı. Root kartındaki LAN SSH seçeneği artık yalnızca root hesabının terminal shell'ini de /bin/ash yapar.
- Yalnızca parola değiştirme seçeneği ve diğer CLI hesaplarının shell ayarları korunur.
- Shell değişikliği, tekrar uygulama ve hata durumu geçici passwd dosyasında sınandı. Sıfırlanmış laboratuvar cihazında macOS üzerinden yeni root parolasıyla SSH terminal girişi doğrulandı. Linux ve Windows desteği deneysel kalır.

## v1.17.1

- Root + LAN SSH dosyasında STS ayrıştırıcısının reddettiği iç içe servis yolları kaldırıldı. LAN ayarları ve servis işlemleri ayrı yerel STS satırlarıyla oluşturulur.
- Root aktarımının hata kodu ve açıklaması panelde ve işlem günlüğünde görünür hale getirildi.
- Dosyanın gönderildiği bilgisi, HTTP gövdesi tamamen yazıldıktan sonra kaydedilir.
- v1.17 dosyasının reddi ve düzeltmenin kabulü, gerçek firmware ayrıştırıcısıyla Lua 5.1 üzerinde yerelde yeniden üretildi; UCI ve servisler taklit edildi.

## v1.17

- LAN yönetim IP adresinin manuel olduğu açıklandı; varsayılan değer 192.168.1.1 yapıldı.
- İlerleme aşamaları çalışma moduna göre gösterilir. Başarılı log aktarımı eksik bir 4/7 özeti yerine tamamlandı olarak gösterilir.
- Root parola kartına isteğe bağlı LAN SSH hizmeti ve root parola girişi açma seçeneği eklendi. Seçilmezse SSH ayarları değişmez.
- SSH açma isteği ile doğrulanmış hizmet durumu ayrı gösterilir. Yeni seçeneğin canlı cihaz doğrulaması bekliyor.

## v1.16.1

- Her çalışma modunun bitiş koşulu ayrı tanımlandı ve doğrulandı.
- Root parola aktarımı doğrudan tamamlandığında ek TransferComplete bildirimi beklenmez.
- Başlangıç koşulları uygun olmayan yazma testi, yazma yapmadan başarısız sonuçla kapanır.
- Süre ayarının yalnızca bekleme üst sınırı olduğu arayüzde açıklandı.

## v1.16

- İşlem tamamlandığında ağ oturumu son RPC yanıtından sonra otomatik kapanır; paket trafiğinin durması beklenmez.
- Kapanışta PAP geri alma adımı, dinleyici veya alt süreç hatası olsa da çalışır.
- Çevrimdışı ağ kurtarma düğmesi, ortak PAP kilidi ve güvenli tekrar kurtarma eklendi.
- Panel ağ kapanışını gösterir; sonraki test temizlik tamamlandıktan sonra açılır.
- Sayfa yenilendiğinde oturum ayarları geri gösterilir; süre sayacı kapanışta durur.
- İlgisiz HTTP/DNS/NTP trafiği dışlanır; TLS el sıkışması sunucunun kapanışını engellemez.
- Kesintisiz trafik, arka arkaya test, kesinti ve temizleme hatası için regresyon testleri eklendi.

## v1.15

- Windows için deneysel Npcap + WSL 2 paket köprüsü ve kurulum başlatıcıları eklendi.
- USB ve dahili Ethernet kartları aynı panelden seçilebilir.
- Platform etiketi Windows'u kapsayacak şekilde güncellendi.
- README kısaltıldı; kurulum ve işlem ayrıntıları GUIDE.md, sürüm geçmişi bu dosyaya taşındı.
- Hedef cihaz, platform doğrulaması, yedekleme ve kullanıcı sorumluluğu açıkça belirtildi.
- İşlem sonrası aynı operatör altyapısında kullanım için CWMP kapatma notu ve arayüz ekran görüntüleri eklendi.

## v1.14.1

- Açılır menü okları çerçeve içine alındı, açıklamalar kısaltıldı ve arayüzdeki uzun çizgiler kaldırıldı.
- LAN SSH ayarı ve root parola izni için durum göstergeleri eklendi.
- Web rolü, CLI hesap izni ve Linux root parolası arasındaki ayrım netleştirildi.

## v1.14

- Deneysel yerel Linux desteği eklendi.
- Adaptör keşfi, PPP işlemleri, dinleyici adresleri ve geçici IP yönetimi platforma göre düzenlendi.
- Mevcut oturum ve kurtarma kayıtlarının korunması sağlandı.

## v1.11

- STS indirme ve geri alma testi eklendi.
- engineer hesabının kalıcılık ayarı için 1 → 0 → 1 doğrulaması ve kurtarma kaydı eklendi.

## v1.10

- Standart sistem günlüğü aktarımı testi eklendi.
- Dosya alımı, boyut sınırı ve aktarım sonucunun birlikte doğrulanması sağlandı.

## v1.9

- Salt okunur keşfe desteklenen RPC yöntemleri, web kullanıcı rolleri, günlük metadata ve SSH hesap ayarları eklendi.

## v1.8

- Mevcut admin kullanıcısının engineer web rolüne geçirilmesi eklendi.
- Kullanıcı keşfi, yazılabilirlik kontrolü ve değişiklik sonrası tekrar okuma eklendi.

## v1.7

- Önceki oturumun başarı bilgisini gösteren üst kart kaldırıldı.

## v1.6

- Bağlantı ve kullanım adımları ile WAN kablosunu yeniden takma açıklaması eklendi.

## v1.5

- Salt okunur keşif varsayılan mod yapıldı.
- Keşfi durdur düğmesi ve yazı boyutları düzenlendi.

## v1.4

- engineer ve superuser hesap açıklamaları, kalıcılık açıklaması ve işlem sonrası bağlantı adımları eklendi.
- Kontrast, dar ekran düzeni ve klavye odağı iyileştirildi.

## Diğer geçmiş iyileştirmeler

- Linux root parolası için ayrı STS aktarım modu eklendi; sonuç SSH ile doğrulamaya bırakıldı.
- Salt okunur keşfin otomatik tamamlanması ve oturum ilerleme göstergesi eklendi.
- İşlem seçenekleri ilgili çalışma modunun içine taşındı.

Bu son maddelerin ilk eklendiği sürüm numaraları önceki kayıtlarda belirtilmediği için ayrı listelenmiştir.
