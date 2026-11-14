# Puyad Kalkanı Light Agent

Uzak sunucuları Puyad Kalkanı paneline bağlayan küçük ajan. Sadece Python standart kütüphanesini kullanıyor. Hedef makineye `pip` ile paket kurmak ya da venv açmak gerekmiyor. `python3`, `curl` ve `openssl` olması yeterli. `openssl` yalnızca ajanın sertifikasını üretmek için gerekiyor, çünkü standart kütüphane sertifika üretemiyor.

Ajanın kendine ait bir kural listesi yok. Panelden tarama başlatıldığında kurallar istekle birlikte gönderiliyor, ajan bunları yerelde çalıştırıp sonucu geri dönüyor. Düzeltme istekleri de aynı şekilde geliyor. Bunun dışında belirli aralıklarla ana makineye heartbeat gönderiyor, panel sunucuyu bu heartbeat'lere bakarak çevrimiçi gösteriyor.

## Kurulum

Varsayılan giriş: admin / puyad2026. Panelde ADMIN → Parola Değiştir'den değiştirebilirsiniz.

Ajan dosyaları ana makinedeki backend tarafından HTTPS ile sunuluyor. Ajan da yalnızca HTTPS dinliyor. Controller ile ajan birbirinin kendinden imzalı sertifikasını parmak iziyle sabitliyor.

1. Panelde **Sunucu Yönetimi → Ajan Kurulum Komutu** bölümüne ajanın ana makineye ulaştığı adresi yaz (örn. `192.168.1.10:8000`) ve **Komutu Oluştur**'a bas.
2. Uzak makinede boş bir klasör aç ve komutu orada çalıştır:

   ```bash
   mkdir puyad-agent && cd puyad-agent
   curl -sSf -k --pinnedpubkey 'sha256//...' https://192.168.1.10:8000/api/agent/update.sh -o update.sh && bash update.sh
   ```

   `--pinnedpubkey` controller'ın açık anahtarını kontrol ediyor ve eşleşmezse hiçbir şey indirmeden duruyor (`curl: (90)`). Betik `agent.py`, `collector.py` ve `security.py` dosyalarını aynı pinle indiriyor. `config.json` yoksa örnekten oluşturuyor ve `controller` ile `controller_fingerprint` alanlarını dolduruyor.
3. `config.json` içindeki `secret` alanına ajan anahtarını yaz. Anahtar panelde **Sunucu Yönetimi → Ajan İletişim Anahtarı** bölümünde duruyor ve ana makinedeki `AGENT_SHARED_SECRET` ile aynı olmalı.
4. Ajanı `python3 agent.py start` ile başlat. İlk açılışta `agent.crt` ve `agent.key` üretiliyor (anahtar `0600`) ve ajan parmak izi ekrana basılıyor. `python3 agent.py status` aynı izi yeniden gösteriyor.
5. Ajan ilk heartbeat'te sertifikasını panele gönderiyor ve sunucu **Onay bekliyor** olarak görünüyor. Kartta görünen parmak izini `status` çıktısıyla karşılaştır, aynıysa **Onayla**'ya bas. Panel onaydan önce ajana tarama ya da düzeltme göndermiyor. Sunucu heartbeat'le kendiliğinden ekleniyor. Elle **Sunucu Ekle** ile eklediysen kayıt aynı IP ve port üzerinden eşleşiyor.

Güncelleme için aynı komutu ajan klasöründe yeniden çalıştır. `config.json` varsa korunuyor, ajan yeniden başlatılıyor.

Ajan başlarken şu durumlarda açık bir hatayla duruyor ve HTTP'ye geri dönmüyor:

- `openssl` yok: `sudo apt install openssl` ile kur.
- `controller` `https://` ile başlamıyor ya da `controller_fingerprint` boş veya geçersiz: kurulum komutunu panelden alıp yeniden çalıştır.

`controller` boşsa ajan heartbeat göndermeden HTTPS dinlemeye devam ediyor. Bu durumda panel ajanın sertifikasını öğrenemiyor, ajan kullanılamıyor.

## Eski sürümden geçiş

Eski ajanlar düz HTTP konuşuyordu. Yeni controller HTTP kabul etmiyor, geçiş için bir ara ayar da yok. Ana makine güncellendikten sonra her ajanda şu sırayı izle:

1. `openssl version` ve `curl --version` ile ikisinin kurulu olduğunu doğrula.
2. Panelden kurulum komutunu al. Adres ajanın bugün kullandığı `IP:8000` olmalı, panelin nginx adresi değil.
3. Ajanın mevcut klasörüne geç (`agent.py`'nin olduğu yer) ve komutu çalıştır. `secret`, `agent_id`, `port` ve diğer alanlar korunuyor. `controller` `https://` adresine çevriliyor ve `controller_fingerprint` ekleniyor.
4. Betik ajanı yeniden başlatıyor ve sonda `status` çıktısında ajan parmak izini gösteriyor.
5. Panelde sunucu kartında **Onay bekliyor** görünüyor. Parmak izini 4. adımdaki çıktıyla karşılaştırıp **Onayla**'ya bas.
6. **Şimdi Tara** ile bağlantıyı doğrula.

Ajanı `--controller` ile komut satırından başlatıyorsan adresi `https://` ile ver ve `--controller-fingerprint` ekle. Değeri kurulum komutunun yanında gösterilen controller parmak izinden al.

## Komutlar

```bash
python3 agent.py start     # arka planda başlatır, PID'i agent.pid'e yazar
python3 agent.py status    # süreç ayakta mı, /api/health yanıt veriyor mu, ajan parmak izi
python3 agent.py stop
python3 agent.py restart
python3 agent.py run       # ön planda çalışır, hata ayıklarken işe yarıyor
```

Komut verilmezse `run` çalışıyor. `-d` / `--daemon` ise `run` yerine `start` anlamına geliyor.

## Ayarlar

Ajan ayarları şu sırayla okuyor: `agent.py` ile aynı klasördeki `config.json` (ya da `--config` ile verilen dosya), sonra ortam değişkenleri, en son komut satırı parametreleri. Komut satırında verilenler yalnızca o çalıştırma için geçerli, hiçbir yere kaydedilmiyor. `update.sh` ajanı parametresiz başlattığı için kalıcı ayarları `config.json` içinde tut.

| `config.json` | Parametre | Ortam değişkeni | Varsayılan |
|---|---|---|---|
| `controller` | `--controller` | `PUYAD_CONTROLLER_URL` | boş (heartbeat gönderilmez), `https://` olmalı |
| `controller_fingerprint` | `--controller-fingerprint` | — | boş, `update.sh` yazar |
| `cert_file` | `--cert-file` | — | `agent.crt` |
| `key_file` | `--key-file` | — | `agent.key` |
| `secret` | `--secret` | `PUYAD_AGENT_SECRET` | boş |
| `token` | `--token` | `PUYAD_AGENT_TOKEN` | boş |
| `port` | `--port` | `PUYAD_AGENT_PORT` | `8000` |
| `host` | `--host` | — | `0.0.0.0` |
| `interval` | `--interval` | — | `60` sn (en az 5) |
| `pid_file` | `--pid-file` | — | `agent.pid` |
| `log_file` | `--log-file` | — | `agent.log` |
| `agent_id` | — | — | ilk açılışta üretilir |

`secret` HMAC imzalı isteklerde kullanılıyor, panel ajanla bu şekilde konuşuyor. `token` ise isteğe bağlı bir Bearer token. Ajana elle istek atmak istersen işe yarıyor.

`agent_id` ajanın sabit kimliği. `config.json`'da yoksa ajan ilk açılışta rastgele bir değer üretip dosyaya yazıyor (dosya `0600` izinle yeniden yazılıyor). Elle vermek istersen 8–64 karakter, yalnızca harf, rakam, `-` ve `_` olmalı. Kimliği değiştirme: panel bu değeri heartbeat'ten öğrenip saklıyor, değişirse bir sonraki heartbeat'e kadar panelin istekleri reddedilir.

İmza isteğin gövdesini ve hedef ajanın `agent_id`'sini kapsıyor (`v3` şeması), bir ajana gönderilmiş imzalı istek başka bir ajana tekrar oynatılamıyor. Panel bir ajanın kimliğini ilk heartbeat'te öğreniyor. O zamana kadar o sunucuda tarama ve düzeltme çalışmıyor, sunucu çevrimdışı görünüyor. Bu yüzden ajanı `controller` adresiyle çalıştır.

Eski şemayı (`v2`) kullanan ajanlar yeni panelle konuşamıyor, panel de onlara dosya gönderemiyor. Paneli güncelledikten sonra her makinede `update.sh` komutunu bir kez çalıştır. Yeni ajan ilk açılışta `agent_id`'sini üretir ve ilk heartbeat'le panele bildirir.

## Sorun giderme

Port çakışması, 409 hatası, sertifika ya da anahtar değişikliği için ana [README'deki Sorun giderme](../README.md#sorun-giderme) bölümüne bak.

## Bilinen eksikler

- Tüm ajanlar aynı `secret`'ı paylaşıyor. `agent_id` replay'i engelliyor ama sırrı ele geçiren biri her ajan için imza üretebilir ve ilk heartbeat'te kendi sertifikasını "onay bekliyor" olarak kaydedebilir. Panelde onaylamadan önce parmak izini karşılaştır.

Ajanla ilgili sorun ya da öneri için: puyadkalkani@gmail.com
