  # Linux Sunucu Kurulum ve Yapılandırma Dokümantasyonu

## İçindekiler
1. [Ortamlar](#1-ortamlar)
2. [VirtualBox ve Ağ Ayarları](#2-virtualbox-ve-ağ-ayarları)
3. [Netplan ile Statik IP Ataması](#3-netplan-ile-statik-ip-ataması)
4. [OpenSSH Server Kurulumu](#4-openssh-server-kurulumu)
5. [SSH Anahtar Oluşturma ve Yapılandırma](#5-ssh-anahtar-oluşturma-ve-yapılandırma)
6. [Güvenlik Duvarı Yapılandırması (UFW)](#7-güvenlik-duvarı-yapılandırması-ufw)
7. [Veritabanı Sunucusu Kurulumu (MariaDB)](#8-veritabanı-sunucusu-kurulumu-mariadb)
8. [Web Sunucusu Kurulumu (Apache)](#9-web-sunucusu-kurulumu-apache)
9. [2025ozgur.com Web Sitesi Kurulumu](#10-2025ozgurcom-web-sitesi-kurulumu)
10. [WordPress Kurulumu (bugday.org)](#11-wordpress-kurulumu-bugdayorg)


---

## 1. Ortamlar

### Sistem Mimarisi

**Host Sistem:**
- İşletim Sistemi: Windows
- Sanallaştırma: VirtualBox

**Sanal Makineler:**
- **VM1 (Web Sunucu)**: Ubuntu Server 24.04 LTS — IP: 192.168.1.50
- **VM2 (Veritabanı Sunucu)**: Ubuntu Server 24.04 LTS — IP: 192.168.1.51

**Kullanıcı:**
- Kullanıcı adı: `dila` (root dışında normal kullanıcı)
- SSH erişimi: Ssh key ile kimlik doğrulama

## 2. VirtualBox ve Ağ Ayarları

### 2.1 Sanal Makine Oluşturma

**Adım 1: Ubuntu Server ISO**

Ubuntu 24.04 LTS Server ISO:
```
https://ubuntu.com/download/server
```

**Adım 2: VirtualBox'ta Yeni VM Oluşturma**

1. VirtualBox'ı açın
2. **New** (Yeni) butonuna tıklayın
3. VM ayarları:
   - **Name**: ubuntu-web (veya Ubuntu-DB)
   - **Type**: Linux
   - **Version**: Ubuntu (64-bit)
   - **Memory**: 2048 MB (Web için), 2048 MB (DB için)
   - **Hard Disk**: Create a virtual hard disk now
   - **Hard disk size**: 25 GB (Web için), 25 GB (DB için)
4. **Create** tıklayın

**Adım 3: VM Ayarlarını Düzenle**

VM'i sağ tıklayın → **Settings**:

1. **System** → **Processor**: 1 CPU
2. **Storage** → Controller: Ubuntu ISO'yu seçin
3. **Network** → Adapter 1:
   - **Attached to**: Bridged Adapter (internet erişiminde hata almamak ve VM'ler yerel ağda gerçek bir cihaz rolünde olmaları için)
   - **Name**: Host'unuzun aktif ağ adaptörü

### 2.2 Server Kurulumları

**Ubuntu Server Kurulum Adımları:**
1. VM'i başlatın
2. Profile setup:
   - Your name: `Dila`
   - Your server's name: `ubuntu-web` (veritabanı serverı için isimlendirme: `ubuntu-db`)
   - Username: `dila`
   - Password: Güçlü bir parola belirleyin
3. SSH Setup: **Install OpenSSH server** işaretleyin
4. Featured Server Snaps: **Hiçbir şey seçmeyin** (minimal kurulum için)
5. Kurulum tamamlanınca **Reboot** edin
---

## 3. Netplan ile Statik IP Ataması

Ubuntuda ağ yapılandırması için **Netplan** kullanılıyor. Netplan yapılandırma dosyasını düzenleyerek static ip tanımlandı.

### 3.1 Mevcut Ağ Yapılandırmasını Kontrol Etme

Her iki VM'de de:

```bash
# Mevcut IP adresini göster
ip a
```

### 3.2 Web Sunucusu için Statik IP (192.168.1.50)

**Adım 1: SSH ile Web VM'ine bağlan**

```bash
# Geçici DHCP IP'si ile bağlan (ip a komutuyla öğrendik)
ssh dila@<DHCP_IP>
```

**Adım 2: Netplan yapılandırma dosyasını düzenle**

```bash
# Mevcut yapılandırma dosyasını düzenle
sudo nano /etc/netplan/50-cloud-init.yaml
```

**Adım 3: Dosya içeriğini şu şekilde değiştir:**

```yaml
network:
  version: 2
  ethernets:
    enp0s3:  # Ağ arayüzü adı (ip a ile kontrol edin)
      dhcp4: no
      addresses:
        - 192.168.1.50/24
      routes:
        - to: default
          via: 192.168.1.1  # Gateway adresinizi kontrol edin
      nameservers:
        addresses:
          - 8.8.8.8
          - 1.1.1.1
```
**Bilgilendirme**
 
 Neden `gateway4` yerine `routes` kullanıyoruz?
- `gateway4` deprecated (artık kullanılmıyor)
- Ubuntu 24.04'te `routes` ile `to: default` kullanımı öneriliyor
- Bu sayede deprecation uyarısı almıyoruz

**Adım 4: Yapılandırmayı uygula ve kontrol et**

```bash
# kalıcı olarak uygula
sudo netplan apply

# kontrol et
ip a 
```

**Adım 5: Bağlantıyı test et**

```bash
# İnternet bağlantısını test et
ping -c 4 8.8.8.8
```

### 3.3 Veritabanı Sunucusu için Statik IP (192.168.1.51)

**Aynı işlemleri DB VM'i için tekrarla, sadece IP adresini değiştir:**

```bash
# DB VM'ine bağlan
ssh dila@<DB_DHCP_IP>

# Netplan yapılandırmasını düzenle
sudo nano /etc/netplan/50-cloud-init.yaml
```

**DB VM için yapılandırma:**

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 192.168.1.51/24  # Sadece bu satır farklı
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 1.1.1.1
```

Uygula:

```bash
sudo netplan apply
ip a show enp0s3
ping -c 4 8.8.8.8
```

---

## 4. OpenSSH Server Kurulumu

### 4.1 OpenSSH Server Kurulumu
Ubuntu Server kurulumunda SSH'ı işaretlediyseniz zaten kurulu olması lazım. 

**Her iki VM'de de:**

```bash
# SSH servisini kontrol et
sudo systemctl status ssh
```

Eğer kurulu değilse:

```bash
# Güncelle
sudo apt update

# Kur
sudo apt install -y openssh-server

# Servisi başlat ve etkinleştir
sudo systemctl enable --now ssh

# Durumu kontrol et
sudo systemctl status ssh
```
---

## 5. SSH Key Oluşturma ve Yapılandırma
### 5.1 Host'ta (Windows) SSH key Oluşturma

**Windows PowerShell'de:**

```powershell
# SSH key oluştur
ssh-keygen
```

**Oluşturulan dosyalar:**
- `C:\Users\YourName\.ssh\id_rsa` → Private key 
- `C:\Users\YourName\.ssh\id_rsa.pub` → Public key 

**Public key:**

```powershell
cat C:\Users\YourName\.ssh\id_rsa.pub
```

Çıktı:
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... yourname@hostname
```

### 5.2 Public Key'i Sunuculara Kopyalama

**Adım 1: Public key'i kopyala**

PowerShell'de:

```powershell
# Public key'i kopyala (içeriğini seç ve kopyala)
cat C:\Users\YourName\.ssh\id_rsa.pub
```

**Adım 2: Web VM'ine parola ile bağlan**

```powershell
ssh dila@192.168.1.50
```

**Adım 3: VM'de authorized_keys dosyası oluştur**

```bash
# .ssh dizinini oluştur
mkdir -p ~/.ssh

# authorized_keys dosyasını oluştur ve düzenle
nano ~/.ssh/authorized_keys
```

Public key'i dosyaya kaydedin

**Adım 4: Yetkileri ayarla**

```bash
# Dosya sahibi r-w-x
chmod 700 ~/.ssh

# Dosya sahibi r-w
chmod 600 ~/.ssh/authorized_keys
```

**Adım 5: DB VM'i için tekrarla**

```powershell
ssh dila@192.168.1.51
```

Aynı işlemler yapılacak.

### 5.3 SSH Yapılandırma Dosyasını Düzenleme

**Her iki VM'de de:**

```bash
# SSH yapılandırma dosyasını düzenle
sudo nano /etc/ssh/ssh_config
```

**Aşağıdaki satırları bulun ve değiştirin:**

```
# Parola ile girişi kapat
PasswordAuthentication no

# Root kullanıcısı ile girişi kapat
PermitRootLogin no

# Public key ile girişi aç (genelde zaten açıktır)
PubkeyAuthentication yes

# Boş parolalara izin verme
PermitEmptyPasswords no

```
### 5.4 SSH Servisini Yeniden Başlatma

```bash
# SSH servisini yeniden başlat
sudo systemctl restart ssh

# Servisi kontrol et
sudo systemctl status ssh
```
### 5.5 Anahtar Tabanlı Girişi Test Etme

**Host'tan (Windows PowerShell) test:**

```powershell
# Web'e bağlan (parola sormadan girmeli)
ssh dila@192.168.1.50

# DB'ye bağlan (parola sormadan girmeli)
ssh dila@192.168.1.51
```
---
## 6. Güvenlik Duvarı Yapılandırması (UFW)
### 6.1 Web Sunucusu Güvenlik Duvarı Yapılandırması

**Web VM'ine bağlan:**

```bash
ssh dila@192.168.1.50
```

**Adım 1: UFW'yi kur**

```bash
sudo apt update

# UFW'yi kur
sudo apt install ufw -y
```

**Adım 2: Varsayılan politikaları ayarla**

```bash
# Gelen trafiği varsayılan olarak reddet
sudo ufw default deny incoming

# Giden trafiğe varsayılan olarak izin ver
sudo ufw default allow outgoing
```


**Adım 3: Gerekli portları aç**

```bash
# SSH erişimine limitli izin ver (Aynı IP'den 30 saniyede 6'dan fazla bağlantı denemesi engellenir)
sudo ufw limit 22/tcp

# HTTP trafiğine izin ver
sudo ufw allow 80/tcp

```

**Adım 4: Güvenlik duvarını etkinleştir**

```bash
sudo ufw enable
```

**Adım 5: Durumu kontrol et**

```bash
sudo ufw status verbose
```

### 6.2 Veritabanı Sunucusu Güvenlik Duvarı Yapılandırması

**DB VM'ine bağlan:**

```bash
ssh dila@192.168.1.51
```

**Adım 1: UFW'yi kur**

```bash
sudo apt update
sudo apt install ufw -y
```

**Adım 2: Varsayılan politikaları ayarla**

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

**Adım 3: Gerekli portları aç**

```bash
sudo ufw limit 22/tcp

# MySQL/MariaDB portunu sadece web sunucusundan izin ver
sudo ufw allow from 192.168.1.50 to any port 3306 proto tcp
```

**Adım 4: Güvenlik duvarını etkinleştir**

```bash
sudo ufw enable
sudo ufw status verbose
```
---

## 7. Veritabanı Sunucusu Kurulumu (MariaDB)

### 7.1 MariaDB Kurulumu

**DB VM'ine bağlan:**

```bash
ssh dila@192.168.1.51
```

**Adım 1: MariaDB Server'ı kur**

```bash
sudo apt update
sudo apt install mariadb-server -y
```

**Adım 2: Servisi kontrol et**

```bash
sudo systemctl status mariadb

sudo systemctl enable mariadb
```
### 7.2 MariaDB Güvenlik Yapılandırması

```bash
# Güvenlik scriptini çalıştır
sudo mysql_secure_installation
```

**Sorular ve cevaplar:**

```
Enter current password for root: [ENTER - henüz parola yok]

Switch to unix_socket authentication [Y/n]: n
Change the root password? [Y/n]: y
New password: 
Re-enter new password:
Remove anonymous users? [Y/n]: y
Disallow root login remotely? [Y/n]: y
Remove test database and access to it? [Y/n]: y
Reload privilege tables now? [Y/n]: y
```

### 7.3 MariaDB'ye Giriş Yapma

```bash
sudo mysql -u root -p
```

**MariaDB komut satırını göreceksiniz:**
```
MariaDB [(none)]>
```

### 7.4 WordPress için Veritabanı Oluşturma

**MariaDB komut satırında:**

```sql
CREATE DATABASE wordpress_db;

-- Veritabanının oluştuğunu kontrol et
SHOW DATABASES;
```


### 7.5 WordPress için Kullanıcı Oluşturma

```sql
-- Web sunucusundan (192.168.1.50) erişebilecek kullanıcı oluştur
CREATE USER 'wp_user'@'192.168.1.50' IDENTIFIED BY '12345';

-- Kullanıcıya wordpress_db üzerinde tam yetki ver
GRANT ALL PRIVILEGES ON wordpress_db.* TO 'wp_user'@'192.168.1.50';

-- Değişiklikleri uygula
FLUSH PRIVILEGES;
```
**Kullanıcıyı ve yetkilerini kontrol et:**

```sql
-- Kullanıcıları listele
SELECT User, Host FROM mysql.user WHERE User='wp_user';
SHOW GRANTS FOR 'wp_user'@'192.168.1.50';
```

### 7.6 MariaDB'yi Uzak Bağlantılara Açma

Varsayılan olarak MariaDB sadece localhost'tan bağlantı kabul eder. Uzak bağlantıları etkinleştirmeliyiz.

```bash
sudo nano /etc/mysql/mariadb.conf.d/50-server.cnf
```

**Şu satırı:**

```ini
bind-address = 127.0.0.1
```

**Şu şekilde değiştirin:**

```ini
bind-address = 0.0.0.0
```

**MariaDB'yi yeniden başlat:**

```bash
sudo systemctl restart mariadb

# Servisin çalıştığını kontrol et
sudo systemctl status mariadb
```

### 7.7 Web Sunucusundan Bağlantı Testi

**Web VM'ine geç:**

```bash
ssh dila@192.168.1.50
```

**DB sunucusuna bağlan:**

```bash
mysql -h 192.168.1.51 -u wp_user -p
```
---

## 8. Web Sunucusu Kurulumu (Apache)

### 8.1 Apache ve PHP Kurulumu

**Web VM'ine bağlan:**

```bash
ssh dila@192.168.1.50
```

**Adım 1: Sistem paketlerini güncelle**

```bash
sudo apt update
sudo apt upgrade -y
```

**Adım 2: Apache ve PHP paketlerini kur**

```bash
# Apache, PHP ve WordPress için gerekli PHP eklentiler ile
sudo apt install -y apache2 php8.3 libapache2-mod-php8.3 \
  php8.3-mysql php8.3-curl php8.3-mbstring \
  php8.3-xml  php8.3-zip php8.3-intl
```

**Adım 3: Servisleri başlat ve etkinleştir**

```bash
sudo systemctl start apache2

sudo systemctl enable apache2

sudo systemctl status apache2
```

**Adım 4: Apache kurulumunu test et**

Tarayıcınızda şu adrese gidin:

```
http://192.168.1.50
```

**Apache2 Ubuntu Default Page** görmelisiniz. Bu sayfa Apache'nin çalıştığını gösterir.

### 8.2 Apache Modüllerini Etkinleştirme

WordPress için gerekli Apache modüllerini etkinleştirelim.

```bash
# mod_rewrite: SEO-uyumlu URL'ler için
sudo a2enmod rewrite

# Apache'yi yeniden başlat
sudo systemctl restart apache2
```

**mod_rewrite**
- WordPress permalink yapısı için zorunlu
- SEO-uyumlu URL'ler (bugday.org/yazilar/baslik)
- REST API çalışması için gerekli
- .htaccess dosyasının işlevselliği

### 8.3 Web Siteleri için Dizin Yapısı Oluşturma

```bash
# Her alan adı için ayrı dizin oluştur
sudo mkdir -p /var/www/bugday
sudo mkdir -p /var/www/2025ozgur

# Dizinlerin sahipliğini www-data kullanıcısına ver
sudo chown -R www-data:www-data /var/www/bugday
sudo chown -R www-data:www-data /var/www/2025ozgur

# Dizin yetkilerini ayarla
sudo chmod -R 755 /var/www/bugday
sudo chmod -R 755 /var/www/2025ozgur
```

---

## 9. 2025ozgur.com Web Sitesi Kurulumu

### 9.1 Site İçeriği Oluşturma

**Web VM'de:**
```bash
cat << 'EOF' | sudo tee /var/www/2025ozgur/index.html > /dev/null
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>2025 Özgür</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            line-height: 1.6;
        }
        h1 {
            color: #333;
        }
        p {
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <h1>Veri Gizliliği Taahhüdü</h1>
EOF

# 100 satır ekle
for i in {1..100}; do
    echo "    <p>$i. Kullanıcılarımın kişisel verilerini toplamayacağım.</p>" | sudo tee -a /var/www/2025ozgur/index.html > /dev/null
done

# HTML'i kapat
echo "</body></html>" | sudo tee -a /var/www/2025ozgur/index.html > /dev/null
```

### 9.2 Yönetim Sayfası için Parola Koruması

**Adım 1: htpasswd aracını kur**

```bash
sudo apt install apache2-utils -y
```

**Adım 2: Parola dosyası oluştur**

```bash
# .htpasswd dosyası oluştur
sudo htpasswd -c /etc/apache2/.htpasswd ad.soyad
```

**Parola oluştur:**
```
New password: 
...
```

**Adım 3: Yönetim dizini oluştur**

```bash
sudo mkdir -p /var/www/2025ozgur/yonetim
sudo chown -R www-data:www-data /var/www/2025ozgur/yonetim
```

### 9.3 Apache Virtual Host Yapılandırması

```bash
# Virtual Host dosyası oluştur
sudo nano /etc/apache2/sites-available/2025ozgur.com.conf
```

**Dosya içeriği:**

```apache
<VirtualHost *:80>
    ServerName 2025ozgur.com
    ServerAlias www.2025ozgur.com
    DocumentRoot /var/www/2025ozgur

    <Directory /var/www/2025ozgur>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # Yönetim dizini için parola koruması
    <Directory /var/www/2025ozgur/yonetim>
        AuthType Basic
        AuthName "Yönetim Paneli"
        AuthUserFile /etc/apache2/.htpasswd
        Require valid-user
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/2025ozgur-error.log
    CustomLog ${APACHE_LOG_DIR}/2025ozgur-access.log combined
</VirtualHost>
```

**Adım 4: Siteyi etkinleştir**

```bash
sudo a2ensite 2025ozgur.com.conf
sudo systemctl reload apache2
```

### 9.4 Hosts Dosyasına Ekleme 
**Windows'ta `C:\Windows\System32\drivers\etc\hosts` dosyasını düzenle:**

PowerShell'i **yönetici olarak** çalıştır:

```powershell
notepad C:\Windows\System32\drivers\etc\hosts
```

Ekle:

```
192.168.1.50 2025ozgur.com www.2025ozgur.com
```

DNS cache'i temizle:

```powershell
ipconfig /flushdns
```

### 9.5 Test Etme

**Ana sayfa:**
```
http://2025ozgur.com
http://www.2025ozgur.com
```

100 satırlık taahhüdü gör.

**Yönetim sayfası:**
```
http://2025ozgur.com/yonetim
```

Kullanıcı adı ve parola soracak
---

## 10. WordPress Kurulumu (bugday.org)

### 10.1 WordPress İndirme

**Web VM'de:**

```bash
# Geçici dizine git
cd /tmp

# WordPress'in son sürümünü indir
wget https://wordpress.org/latest.tar.gz

# İçeriği çıkar
tar -xzvf latest.tar.gz

# İçeriğini kontrol et
ls -la wordpress/
```

### 10.2 WordPress Dosyalarını Kopyalama

```bash
# WordPress dosyalarını hedef dizine kopyala
sudo cp -r wordpress/* /var/www/bugday/

# Sahipliği www-data'ya ver
sudo chown -R www-data:www-data /var/www/bugday

# Dizinler için 755, dosyalar için 644 yetkileri
sudo find /var/www/bugday -type d -exec chmod 755 {} \;
sudo find /var/www/bugday -type f -exec chmod 644 {} \;

# Temizlik
rm -rf wordpress latest.tar.gz
```
### 10.3 WordPress Yapılandırma Dosyası Oluşturma

```bash
cd /var/www/bugday
sudo nano wp-config.php
```

**Veritabanı bilgilerini değiştir:**
```php
define( 'DB_NAME', 'wordpress_db' );
define( 'DB_USER', 'wp_user' );
define( 'DB_PASSWORD', '12345' );
define( 'DB_HOST', '192.168.1.51' );
define( 'DB_CHARSET', 'utf8' );
define( 'DB_COLLATE', '' );
```

**wp-config.php güvenliği:**

```bash
sudo chmod 640 /var/www/bugday/wp-config.php
```

### 10.4 bugday.org için Apache Virtual Host

```bash
sudo nano /etc/apache2/sites-available/bugday.org.conf
```

**Dosya içeriği:**

```apache
<VirtualHost *:80>
    ServerName bugday.org
    ServerAlias www.bugday.org  xn--buday-l1a.org www. xn--buday-l1a.org
    DocumentRoot /var/www/bugday

    <Directory /var/www/bugday>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/bugday.org-error.log
    CustomLog ${APACHE_LOG_DIR}/bugday.org-access.log combined
</VirtualHost>
```
- `buğday.org` → ` xn--buday-l1a.org` (Punycode)


**Kaydet, etkinleştir:**

```bash
sudo a2ensite bugday.org.conf
sudo apache2ctl configtest
sudo systemctl reload apache2
```

### 10.5 Hosts Dosyasına bugday.org Ekleme

**Windows hosts dosyasına ekle:**

```
192.168.1.50 bugday.org www.bugday.org
192.168.1.50  xn--buday-l1a.org www. xn--buday-l1a.org
```

DNS cache temizle:

```powershell
ipconfig /flushdns
```

### 11.6 WordPress Kurulum Sihirbazı

Tarayıcıda:
```
http://bugday.org adresine git kurulumu tamamla
```

### 10.7 Permalink Ayarı (SEO-Uyumlu URL)

WordPress yönetim panelinde:

1. **Ayarlar** → **Kalıcı Bağlantılar**
2. **Yazı adı** seçeneğini seçin: `/%year%/%monthnum%/%day%/%postname%/`
3. **Değişiklikleri Kaydet**


### 10.8 Yeni Yazı Oluşturma ve Dosya Yükleme

WordPress yönetim panelinde:

1. **Yazılar** → **Yeni Ekle**
2. **Başlık**: "Benim Yeni Yazım"
3. **İçerik**:
4. **Dosya yüklemek için**:
   - Blok ekle **(+)** butonuna tıklayın
   - **Resim** veya **Dosya** bloğunu seçin
5. **Yayımla** butonuna tıklayın

### 10.9 Yazınızı Görüntüleme

Yazı yayımlandıktan sonra **"Yazıyı Görüntüle"** linkine tıklayın.

URL şöyle olacak:
```
http://www.bugday.org/2025/10/05/bubenimyazim/
```

Bu SEO-uyumlu URL yapısı

### 10.10 buğday.org ile Test

Aynı WordPress'e `buğday.org` ile de erişebilmelisiniz:

```
http://buğday.org
http:// xn--buday-l1a.org
```

Her iki domain de aynı WordPress sitesini gösterecek.

---
