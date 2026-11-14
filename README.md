# Puyad Kalkanı

Puyad Kalkanı, Debian tabanlı Linux sunucuları tek bir web panelinden denetlemek için yazdığım bir araç. CIS kurallarına göre sistemi tarıyor, kurulu paketlerdeki bilinen CVE'leri buluyor ve uygun olmayan ayarları düzeltebiliyor. Düzeltmeden önce yedek aldığı için yanlış giden bir değişiklik geri alınabiliyor. Uzaktaki makineler, yalnızca standart Python ile çalışan küçük bir ajan üzerinden panele bağlanıyor.

Backend FastAPI ve SQLite ile, arayüz React (Create React App) ile yazıldı.

## Neler var

Panelin sol menüsündeki her sayfa ayrı bir özelliğe karşılık geliyor:

- CIS denetimi: `backend/rules.json` içinde 51 kural var (SSH, parola politikası, servisler, dosya izinleri, kernel parametreleri). Uymayan kurallar panelden düzeltilebiliyor, istenmeyenler yok sayılabiliyor.
- Snapshot ve geri alma: düzeltmeden önce ilgili yapılandırma dosyalarının kopyası alınıyor.
- Zafiyet analizi: `dpkg` paketleri CVE'lere karşı kontrol ediliyor, açığı olan paketler tek tek ya da toplu güncellenebiliyor.
- Honeypot: seçilen portlarda sahte servisler açıyor ve bağlanmaya çalışanları kaydediyor.
- Canlı log, ağ haritası (açık portlar ve bağlantılar, harita üzerinde), adli bilişim kanıt toplama, zamanlanmış tarama, PDF rapor.
- Telegram bildirimleri: honeypot tetiklendiğinde ve brute-force denemesi algılandığında mesaj gönderiyor.

Taramaların, düzeltmelerin ve honeypot'un çoğu root yetkisi istiyor. CVE analizi Debian, Ubuntu ve sürümü bunlara eşlenebilen türevlerde (Linux Mint, LMDE, Pop!_OS, Raspberry Pi OS gibi) çalışıyor; Kali gibi kendi deposu olan rolling dağıtımlar ile RPM, pacman ve apk tabanlı sistemler desteklenmiyor.

## Kurulum

Python 3.12 (CI) ve 3.13 (geliştirme) ile, Node.js 22 ile test ediliyor. Komutlar depo kök dizininden çalıştırılıyor:

```bash
git clone https://github.com/nejdett/Puyad-Kalkani.git
cd Puyad-Kalkani

python3 -m venv backend/venv
backend/venv/bin/pip install -r backend/requirements.txt
cp config.json.example config.json
```

`config.json` içindeki gizli alanlar (`AGENT_SHARED_SECRET`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`) bilerek boş geliyor. Ajan anahtarını `python3 -c "import secrets; print(secrets.token_hex(32))"` ile üretip yaz ya da panelden oluştur. Bu dosyayı oluşturmayı atlama: dosya yoksa backend ajan anahtarını her okumada yeniden rastgele üretiyor, bu da ajanların bağlantısını bozuyor. Dosyadaki her anahtar `PUYAD_` önekiyle ortam değişkeni olarak da verilebiliyor (örneğin `PUYAD_TELEGRAM_BOT_TOKEN`). Dolu bir ortam değişkeni `config.json`'daki değeri ezer, boş olan yok sayılır. Sırları dosyada değil ortamda tutmak istersen `cp .env.example .env` ile değerleri `.env`'e yaz ve backend'i `--env-file ../.env` ile başlat. `.env` git'e girmiyor. Ortamdan verilen bir değer panelden değiştirilemez, çünkü panel `config.json`'a yazıyor. Kullanılabilen anahtarlar:

- `AGENT_SHARED_SECRET`: ajanlarla HMAC doğrulaması için ortak anahtar
- `PUYAD_SECRET_KEY` (yalnızca ortam değişkeni): oturum token'larını imzalayan anahtar, verilmezse `backend/.secret_key` içinde üretiliyor
- `PUYAD_TLS_CERT`, `PUYAD_TLS_KEY` (yalnızca ortam değişkeni): controller'ın hazır sertifikası ve anahtarı. Verilmezse `backend/tls/` altında kendinden imzalı bir sertifika üretiliyor
- `TELEGRAM_ENABLED`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`
- `RATE_LIMIT_*`: giriş, genel API, ağır işlemler, dışa aktarma ve Telegram için istek sınırları

Backend'i başlatmak için:

```bash
cd backend
sudo venv/bin/python serve.py --host 0.0.0.0 --port 8000
```

`serve.py` backend'i yalnızca HTTPS ile açıyor, düz HTTP dinlemiyor. İlk açılışta `openssl` ile `backend/tls/controller.crt` ve `controller.key` dosyalarını üretiyor (10 yıllık, kendinden imzalı). Sonraki açılışlarda aynı sertifikayı kullanıyor ve parmak izini ekrana yazıyor. `openssl` (1.1.1 ya da üstü) kurulu değilse backend açık bir hatayla duruyor, bu durumda `sudo apt install openssl` ile kur ya da `PUYAD_TLS_CERT` ve `PUYAD_TLS_KEY` ile hazır sertifika ver. `.env` kullanıyorsan `serve.py --env-file ../.env` ile başlat. `uvicorn main:app` ile doğrudan başlatmak artık desteklenmiyor: ajanlar HTTPS bekliyor, kurulum komutu da sertifika olmadan üretilemiyor.

Arayüz için ayrı bir terminalde:

```bash
cd frontend
cp .env.example .env
npm install
npm start
```

Panel `http://localhost:3000` adresinde açılıyor. Geliştirme sunucusu bilerek yalnızca `127.0.0.1`'e bağlanıyor ve `/api` isteklerini `https://localhost:8000`'e aktarıyor. Bu yerel proxy sertifikayı doğrulamıyor, yalnızca geliştirme için. Backend ise ajanların erişebilmesi için `0.0.0.0` üzerinde dinliyor. Yani API ağdan erişilebilir durumda, gerekiyorsa 8000 portunu güvenlik duvarıyla sınırla.

İlk çalıştırmada `backend/credentials.json` oluşturuluyor. Varsayılan giriş: admin / puyad2026. Panelde ADMIN → Parola Değiştir'den değiştirebilirsiniz.

## Production kurulumu

`npm start` yalnızca geliştirme için. Sunucuda `cd frontend && npm run build` ile derle, `build/` klasörünü nginx sunsun:

```nginx
server {
    listen 80;
    server_name panel.example.com;
    root /opt/Puyad-Kalkani/frontend/build;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;
    # Fontlar Google'dan, harita karoları OpenStreetMap'ten geliyor
    add_header Content-Security-Policy "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' https://*.tile.openstreetmap.org; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'" always;

    location / {
        try_files $uri /index.html;
    }

    location /api/ {
        proxy_pass https://127.0.0.1:8000;
        # Backend kendinden imzalı — yalnızca bu sertifikaya güven
        proxy_ssl_trusted_certificate /opt/Puyad-Kalkani/backend/tls/controller.crt;
        proxy_ssl_verify on;
        proxy_ssl_name puyad-controller;
        proxy_ssl_server_name on;
        proxy_set_header Host $host;
        # İstemcinin yazdığı X-Forwarded-For ezilir, backend en sağdaki değeri kullanıyor
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_buffering off;
    }
}
```

nginx backend ile aynı makinede olmalı, backend `X-Forwarded-For`'a yalnızca `127.0.0.1`'den güveniyor. Backend HTTPS konuştuğu için `proxy_pass` `https://` ile başlıyor. nginx backend sertifikasını `proxy_ssl_trusted_certificate` ile doğruluyor, sertifikadaki ad da `puyad-controller`. `PUYAD_TLS_CERT` ile kendi sertifikanı verdiysen yolu ve `proxy_ssl_name`'i ona göre değiştir. Controller sertifikası yenilenirse nginx'i de `sudo systemctl reload nginx` ile yeniden yükle. Panelin tarayıcıya sunduğu TLS ayrı bir iş, onun için `sudo certbot --nginx -d panel.example.com` yeterli. Ajanlar nginx'e değil, doğrudan backend'in 8000 portuna bağlanıyor. Kurulum komutundaki adres de bu yüzden `panel.example.com` değil, backend'in `IP:8000` adresi olmalı. CSP'de `'unsafe-inline'` gerekmiyor, React ve Leaflet stilleri DOM üzerinden basıyor. `location` bloklarına kendi `add_header`'ını eklersen nginx üst bloktaki başlıkları devralmaz, onları da oraya kopyala.

## Uzak sunucu bağlama

Controller ile ajanlar arasındaki trafik HTTPS. İki taraf da kendinden imzalı sertifika kullanıyor ve karşı tarafın sertifikasını parmak iziyle sabitliyor. Uzak makinede `python3`, `curl` ve `openssl` olmalı. Depoyu klonlamak gerekmiyor, dosyalar backend'den iniyor.

1. Panelde **Sunucu Yönetimi → Ajan Kurulum Komutu** bölümüne ajanların ana makineye ulaştığı adresi yaz (örn. `192.168.1.10:8000`) ve **Komutu Oluştur**'a bas. Komut şuna benziyor:

   ```bash
   curl -sSf -k --pinnedpubkey 'sha256//...' https://192.168.1.10:8000/api/agent/update.sh -o update.sh && bash update.sh
   ```

   `-k` sertifika zincirini atlıyor, çünkü sertifika kendinden imzalı. `--pinnedpubkey` ise controller'ın açık anahtarını kontrol ediyor ve eşleşmezse hiçbir şey indirmeden duruyor. Güven panelden geliyor: komutu panelin kendisinden kopyala, e-posta ya da sohbet üzerinden gelen bir komuta güvenme.
2. Uzak makinede boş bir klasör aç (`mkdir puyad-agent && cd puyad-agent`) ve komutu orada çalıştır. Betik ajan dosyalarını aynı pinle indiriyor ve `config.json`'u oluşturuyor. `controller` alanına `https://` adresini, `controller_fingerprint` alanına controller'ın parmak izini yazıyor.
3. `config.json`'daki `secret` alanına ajan anahtarını yaz. Anahtar **Sunucu Yönetimi → Ajan İletişim Anahtarı** bölümünde duruyor. Sonra ajanı `python3 agent.py start` ile başlat. Ajan ilk açılışta kendi sertifikasını (`agent.crt`, `agent.key`) üretiyor ve parmak izini ekrana yazıyor.
4. Ajan ilk heartbeat'te sertifikasını gönderiyor ve sunucu panelde **Onay bekliyor** olarak görünüyor. Kartta görünen parmak izini uzak makinedeki `python3 agent.py status` çıktısıyla karşılaştır. Aynıysa **Onayla**'ya bas. Onaydan önce panel bu ajana tarama ya da düzeltme göndermiyor.

Aynı komut sonraki güncellemeler için de kullanılıyor. `config.json` varsa betik yalnızca dosyaları ve controller adresini, parmak izini güncelliyor, ajanı yeniden başlatıyor. Ajanın diğer komutları ve parametreleri [light_agent/README.md](light_agent/README.md) içinde.

### Sertifika değişirse

Controller ya da ajan sertifikası değişince ne yapılacağı [Sorun giderme](#sorun-giderme) bölümünde.

## HTTPS'e geçiş (sahadaki ajanlar)

Eski sürümde controller ile ajanlar düz HTTP konuşuyordu. Yeni sürümde HTTP tamamen kapalı ve geçiş için bir ara ayar yok. Controller HTTPS'e geçtiği andan itibaren eski ajanların heartbeat'leri ulaşmıyor. Her ajanda kurulum komutu çalışana kadar o sunucular panelde çevrimdışı görünüyor. Bu süreyi kısa tutmak için şu sırayı izle:

1. Ana makinede `openssl version` 1.1.1 ya da üstü olmalı.
2. Uzak makinelerde `openssl` ve `curl` kurulu olmalı, eksikse önce kur. Ajan `openssl` olmadan sertifika üretemiyor ve başlamıyor.
3. Controller'da kodu çek, `config.json`'dan `AGENT_USE_TLS` ve `AGENT_VERIFY_TLS` satırlarını sil (artık okunmuyor) ve backend'i durdur.
4. Controller'ı `sudo venv/bin/python serve.py --host 0.0.0.0 --port 8000` ile başlat. Sertifika üretiliyor ve parmak izi ekrana basılıyor. systemd servisi kullanıyorsan `ExecStart` satırını da `serve.py`'ye çevir.
5. nginx varsa `location /api/` bloğunu yukarıdaki örneğe göre `https://` ve `proxy_ssl_*` satırlarıyla güncelle, `sudo nginx -t && sudo systemctl reload nginx`.
6. Panelde **Ajan Kurulum Komutu** bölümünden, ajanların kullandığı `IP:8000` adresiyle kurulum komutunu al.
7. Komutu her ajanda, ajanın mevcut klasöründe (`agent.py`'nin olduğu yer) çalıştır. Mevcut `config.json` korunuyor: `secret`, `agent_id` ve `port` aynı kalıyor, yalnızca `controller` `https://` adresiyle değişiyor ve `controller_fingerprint` ekleniyor. Betik ajanı yeniden başlatıyor ve sonda ajan parmak izini yazdırıyor.
8. Sunucu kartında **Onay bekliyor** göründüğünde parmak izini 7. adımdaki çıktıyla karşılaştırıp **Onayla**'ya bas. Kayıt aynı IP ve port üzerinden eşleştiği için tarama geçmişi korunuyor.
9. **Tümünü Kontrol Et** ile sunucuların çevrimiçi göründüğünü doğrula, bir sunucuda **Şimdi Tara** çalıştır.

Bir ajan 7. adımdan sonra başlamazsa çıktıdaki `[Hata]` satırına bak. En sık nedenler `openssl` eksikliği, `controller` adresinin `https://` ile başlamaması ya da `controller_fingerprint` alanının boş olması. Komutu yeniden çalıştırmak üçünü de düzeltiyor, `openssl` hariç.

## Parola değiştirme

Giriş yaptıktan sonra kenar çubuğunda **ADMIN → Parola Değiştir** sayfasını aç. Yeni parola en az 8 karakter olmalı. Parola değişince açık oturumların hepsi kapanıyor, yeni parolayla tekrar giriş yapılıyor.

## Testler

pytest ve mypy `requirements.txt` içinde değil, ayrıca kurulması gerekiyor:

```bash
backend/venv/bin/pip install pytest mypy types-requests
backend/venv/bin/python -m pytest
```

Frontend testleri:

```bash
cd frontend
CI=true npm test -- --watchAll=false
```

CI (`.github/workflows/ci.yml`) bunlara ek olarak 22 backend dosyasında `mypy --strict` ve `npm run build` çalıştırıyor.

## Sorun giderme

- **8000 portu meşgul:** Backend ile ajanın varsayılan portu aynı. İkisi aynı makinedeyse ajanı `--port` ile (ya da `config.json`'daki `port` ile) farklı bir portta başlat.
- **Ajan logunda 409:** Ajan sertifikası değişmiş (`agent.crt` silinmiş), panel yeni sertifikayı reddediyor. Panelde o sunucunun kartında **Sıfırla**'ya bas, sonraki heartbeat'ten sonra parmak izini karşılaştırıp onayla.
- **Controller sertifikası değişti** (`backend/tls/` silindi ya da `PUYAD_TLS_CERT` değişti): Ajanlar eski parmak izine güvendiği için bağlanmayı reddediyor. Panelden yeni kurulum komutunu alıp her ajanda yeniden çalıştır. nginx kullanıyorsan onu da yeniden yükle.
- **Ajan anahtarı yenilendi:** Bağlı ajanlar yeni anahtarı kendiliğinden almıyor. Her ajanın `config.json` dosyasındaki `secret` alanını elle güncelleyip ajanı yeniden başlat.

## Bilinen eksikler

- Panel tek kullanıcılı. Ayrı hesap ya da rol yok, çıkış yapınca o kullanıcının tüm oturumları kapanıyor.
- Backend tek uvicorn süreciyle çalışacak şekilde yazıldı. Rate limit sayaçları bellekte tutuluyor, birden fazla worker ile çalıştırılırsa her süreç kendi sayacını tutar.
- Tüm ajanlar aynı ortak sırrı paylaşıyor. Sırrı ele geçiren biri herhangi bir ajan adına istek imzalayabilir, ilk heartbeat'te kendi sertifikasını "onay bekliyor" olarak da kaydedebilir. Sertifikayı onaylamadan önce parmak izini ajandaki `status` çıktısıyla karşılaştır.

Soru, hata bildirimi ya da öneri için puyadkalkani@gmail.com adresine yazabilirsin.

MIT lisansı ile dağıtılıyor, ayrıntılar [LICENSE](LICENSE) dosyasında.
