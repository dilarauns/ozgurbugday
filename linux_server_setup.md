  # Linux Sunucu Kurulum ve Yapılandırma Dokümantasyonu

## İçindekiler
1. [Ortam ve Amaç](#1-ortam-ve-amaç)
2. [VirtualBox ve Ağ Ayarları](#2-virtualbox-ve-ağ-ayarları)
3. [Netplan ile Statik IP Ataması](#3-netplan-ile-statik-ip-ataması)
4. [OpenSSH Server Kurulumu](#4-openssh-server-kurulumu)
5. [SSH Anahtar Oluşturma ve Yapılandırma](#5-ssh-anahtar-oluşturma-ve-yapılandırma)
6. [SSH Güvenlik Yapılandırması](#6-ssh-güvenlik-yapılandırması)
7. [Güvenlik Duvarı Yapılandırması (UFW)](#7-güvenlik-duvarı-yapılandırması-ufw)
8. [Veritabanı Sunucusu Kurulumu (MariaDB)](#8-veritabanı-sunucusu-kurulumu-mariadb)
9. [Web Sunucusu Kurulumu (Apache)](#9-web-sunucusu-kurulumu-apache)
10. [2025ozgur.com Web Sitesi Kurulumu](#10-2025ozgurcom-web-sitesi-kurulumu)
11. [WordPress Kurulumu (bugday.org)](#11-wordpress-kurulumu-bugdayorg)
12. [Test ve Doğrulama](#12-test-ve-doğrulama)

---

## 1. Ortam ve Amaç

### Sistem Mimarisi

**Host Sistem:**
- İşletim Sistemi: Windows
- Sanallaştırma: VirtualBox

**Sanal Makineler:**
- **VM1 (Web Sunucu)**: Ubuntu Server 24.04 LTS — IP: 192.168.1.50
- **VM2 (Veritabanı Sunucu)**: Ubuntu Server 24.04 LTS — IP: 192.168.1.51

**Kullanıcı:**
- Kullanıcı adı: `dila` (root dışında normal kullanıcı)
- SSH erişimi: Anahtar tabanlı kimlik doğrulama

**Amaç:**
- VM'ler minimal paketlerle kurulacak (GUI yok)
- Statik IP adresleri atanacak
- SSH anahtar tabanlı erişim sağlanacak
- Web servisi ve veritabanı servisi ayrı VM'lerde çalışacak
- Güvenlik duvarı yapılandırılacak


## 2. VirtualBox ve Ağ Ayarları

### 2.1 Sanal Makine Oluşturma

**Adım 1: Ubuntu Server ISO**

Ubuntu 24.04 LTS Server ISO'sunu resmi siteden:
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
   - **Attached to**: Bridged Adapter
   - **Name**: Host'unuzun aktif ağ adaptörü

### 2.2 Minimal Kurulum

**Ubuntu Server Kurulum Adımları:**
1. VM'i başlatın
2. Profile setup:
   - Your name: `Dila`
   - Your server's name: `ubuntu-web` (veya `ubuntu-db`)
   - Username: `dila`
   - Password: Güçlü bir parola belirleyin
3. SSH Setup: **Install OpenSSH server** işaretleyin
4. Featured Server Snaps: **Hiçbir şey seçmeyin** (minimal kurulum için)
5. Kurulum tamamlanınca **Reboot** edin

**Önemli:** Kurulum sırasında sadece **OpenSSH server** seçeneğini işaretleyin, başka hiçbir paket/snap kurulmasın.

### 2.3 Neden Bridged Adapter?

**Bridged Adapter Kullanma Nedenleri:**
- VM'ler yerel ağda gerçek bir cihaz gibi davranır
- Sabit IP atayabiliriz
- Host bilgisayardan doğrudan SSH bağlantısı yapılabilir
- VM'ler birbirleriyle doğrudan haberleşebilir
- İnternet erişimi sorunsuz çalışır

**NAT ile Sorunlar:**
- VM'lere dışarıdan doğrudan erişim yok
- Port yönlendirme (port forwarding) gerekir
- Sabit IP atama karmaşık
- VM'ler arası iletişimde sorunlar yaşanabilir

**Kontrol (VirtualBox UI):**
1. VM → Settings → Network
2. Adapter 1 → Attached to: **Bridged Adapter**
3. Name: Host ağ adaptörü

---

## 3. Netplan ile Statik IP Ataması

### 3.1 Netplan Nedir ve Neden Kullanıyoruz?

Ağ yapılandırması için **Netplan** kullanılıyor. Netplan, YAML formatında basit yapılandırma dosyaları kullanır.

### 3.2 Mevcut Ağ Yapılandırmasını Kontrol Etme

Her iki VM'de de:

```bash
# Mevcut IP adresini göster
ip a

# Ağ arayüz adını öğren (genelde enp0s3)
ip link show

# Varsayılan gateway'i öğren
ip route show default

# Mevcut netplan yapılandırmasını göster
cat /etc/netplan/*.yaml
```

### 3.3 Web Sunucusu için Statik IP (192.168.1.50)

**Adım 1: SSH ile Web VM'ine bağlan**

```bash
# Geçici DHCP IP'si ile bağlan (ip a komutuyla öğrenin)
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

**Önemli Notlar:**
- `enp0s3`: Ağ arayüz adınız farklı olabilir (`ip a` ile kontrol edin)
- `192.168.1.1`: Gateway adresiniz farklı olabilir (`ip route` ile kontrol edin)
- `/24`: Subnet mask (255.255.255.0)

**Neden `gateway4` yerine `routes` kullanıyoruz?**
- `gateway4` deprecated (artık kullanılmıyor)
- Ubuntu 24.04'te `routes` ile `to: default` kullanımı öneriliyor
- Bu sayede deprecation uyarısı almıyoruz

**Adım 4: Yapılandırmayı test et ve uygula**

```bash
# Yapılandırmayı test et (10 saniye dener, sorun varsa geri alır)
sudo netplan try

# "Do you want to keep these settings?" sorusuna y (yes) cevabı ver

# Sorun yoksa kalıcı olarak uygula
sudo netplan apply

# IP adresini kontrol et
ip a show enp0s3
```

**Beklenen çıktı:**
```
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 192.168.1.50/24 brd 192.168.1.255 scope global enp0s3
```

**Adım 5: Bağlantıyı test et**

```bash
# İnternet bağlantısını test et
ping -c 4 8.8.8.8

# DNS çözümlemeyi test et
ping -c 4 google.com
```

### 3.4 Veritabanı Sunucusu için Statik IP (192.168.1.51)

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

Test et ve uygula:

```bash
sudo netplan try
sudo netplan apply
ip a show enp0s3
ping -c 4 8.8.8.8
```

### 3.5 VM'ler Arası İletişimi Test Etme

**Web VM'den DB VM'e ping at:**

```bash
# Web VM'de
ping -c 4 192.168.1.51
```

**DB VM'den Web VM'e ping at:**

```bash
# DB VM'de
ping -c 4 192.168.1.50
```

Her iki yönde de ping başarılı olmalı.

---

## 4. OpenSSH Server Kurulumu

### 4.1 SSH Nedir ve Neden Gerekli?

**SSH (Secure Shell):**
- Uzaktan güvenli sunucu yönetimi için kullanılır
- Tüm iletişim şifrelenir
- Parola veya anahtar tabanlı kimlik doğrulama
- Dosya transferi (SCP, SFTP) için kullanılabilir

### 4.2 OpenSSH Server Kurulumu

Ubuntu Server kurulumunda SSH'ı işaretlediyseniz zaten kurulu. Kontrol edelim:

**Her iki VM'de de:**

```bash
# SSH servisinin çalıştığını kontrol et
sudo systemctl status ssh
```

Eğer kurulu değilse:

```bash
# Paket listesini güncelle
sudo apt update

# OpenSSH Server kur
sudo apt install -y openssh-server

# Servisi başlat ve etkinleştir
sudo systemctl enable --now ssh

# Durumu kontrol et
sudo systemctl status ssh
```

**Beklenen çıktı:**
```
● ssh.service - OpenBSD Secure Shell server
     Loaded: loaded (/lib/systemd/system/ssh.service; enabled)
     Active: active (running)
```

### 4.3 SSH Portunu Kontrol Etme

```bash
# SSH'ın hangi portta dinlediğini kontrol et
sudo ss -tlnp | grep ssh
```

**Çıktı:**
```
LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=xxx,fd=3))
```

Port 22'de dinliyor olmalı.

---

## 5. SSH Anahtar Oluşturma ve Yapılandırma

### 5.1 SSH Anahtar Tabanlı Kimlik Doğrulama Nedir?

**Parola vs Anahtar:**

| Özellik | Parola | SSH Anahtarı |
|---------|--------|--------------|
| Güvenlik | Zayıf (brute force) | Çok güçlü (2048+ bit) |
| Kolaylık | Her seferinde yazma | Otomatik giriş |
| Yönetim | Zorlu | Kolay |
| İptal | Zor | Kolay (key sil) |

**Neden anahtar tabanlı kimlik doğrulama?**
- Brute force saldırılarına karşı koruma
- 2048 bit RSA anahtarı ~11 karakterlik parolaya eşdeğer
- Otomatik giriş (parola yazmaya gerek yok)
- Tek anahtar ile birden fazla sunucuya erişim
- Anahtarı kaybederseniz iptal edebilirsiniz

### 5.2 Host'ta (Windows) SSH Anahtar Çifti Oluşturma

**Windows PowerShell'de:**

```powershell
# SSH anahtar çifti oluştur
ssh-keygen
```

**İnteraktif sorular:**

```
Generating public/private rsa key pair.
Enter file in which to save the key (C:\Users\YourName/.ssh/id_rsa): [ENTER]
Enter passphrase (empty for no passphrase): [İsteğe bağlı parola]
Enter same passphrase again: [Tekrar]
```

**Passphrase kullanmalı mıyım?**
- **Evet**: Daha güvenli, biri anahtarınızı çalarsa yine de kullanamaz
- **Hayır**: Daha pratik, otomasyon için gerekli

**Oluşturulan dosyalar:**
- `C:\Users\YourName\.ssh\id_rsa` → Private key (GİZLİ)
- `C:\Users\YourName\.ssh\id_rsa.pub` → Public key (paylaşılabilir)

**Public key'i görüntüle:**

```powershell
cat C:\Users\YourName\.ssh\id_rsa.pub
```

Çıktı:
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... yourname@hostname
```

### 5.3 Public Key'i Sunuculara Kopyalama

**Yöntem 1: Manuel Kopyalama (Kullandığımız yöntem)**

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

Public key'inizi yapıştırın (sağ tık veya Ctrl+Shift+V)

Kaydedin: `Ctrl+O`, `Enter`, `Ctrl+X`

**Adım 4: Yetkileri ayarla**

```bash
# .ssh dizini yetkileri
chmod 700 ~/.ssh

# authorized_keys dosyası yetkileri
chmod 600 ~/.ssh/authorized_keys
```

**Neden bu yetkiler?**
- `700` (.ssh): Sadece sahibi okuyabilir, yazabilir, girebilir
- `600` (authorized_keys): Sadece sahibi okuyabilir ve yazabilir
- SSH güvenlik nedeniyle başka yetkileri kabul etmez

**Adım 5: DB VM'i için tekrarla**

```powershell
ssh dila@192.168.1.51
```

Aynı işlemleri yapın.

**Yöntem 2: ssh-copy-id (Linux/Mac veya Windows WSL)**

Eğer Linux/Mac kullanıyorsanız veya Windows'ta WSL varsa:

```bash
# Web VM için
ssh-copy-id dila@192.168.1.50

# DB VM için
ssh-copy-id dila@192.168.1.51
```

Bu komut otomatik olarak public key'i kopyalar ve yetkileri ayarlar.

### 5.4 Anahtar Tabanlı Girişi Test Etme

**Host'tan (Windows PowerShell) test:**

```powershell
# Web VM'ine bağlan (parola sormadan girmeli)
ssh dila@192.168.1.50

# DB VM'ine bağlan
ssh dila@192.168.1.51
```

Başarılı olursa artık parola sormadan giriş yapabiliyorsunuz!

---

## 6. SSH Güvenlik Yapılandırması

### 6.1 Neden SSH Güvenliğini Artırmalıyız?

**Güvenlik Riskleri:**
- Brute force parola denemeleri
- Root kullanıcısı hedef alınması
- Zayıf parolalar
- Otomatik botlar sürekli SSH portlarını tarar

**Alacağımız Önlemler:**
- Parola ile girişi kapatma
- Root girişini engelleme
- Giriş deneme sayısını sınırlama

### 6.2 SSH Yapılandırma Dosyasını Düzenleme

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

**Önemli Uyarı:** SSH yapılandırmasını değiştirdikten sonra **mevcut oturumunuzu KAPATMAYIN!** Yeni bir terminal açıp önce test edin.

**Kaydedin:** `Ctrl+O`, `Enter`, `Ctrl+X`

### 6.3 SSH Servisini Yeniden Başlatma

```bash
# SSH yapılandırmasını test et
sudo ssh -t

# Hata yoksa "No error" der veya sessiz kalır

# SSH servisini yeniden başlat
sudo systemctl restart ssh

# Servisi kontrol et
sudo systemctl status ssh
```

### 6.4 Yeni Terminal ile Test Etme

**Mevcut SSH oturumunu KAPATMAYIN!**

**Yeni PowerShell penceresi açın ve test edin:**

```powershell
# Anahtar ile giriş çalışıyor mu?
ssh dila@192.168.1.50

# Başarılı mı? Evet ise güvendesiniz.
```

**Parola ile girişi test etme:**

```powershell
# Parola ile giriş denemesi (reddedilmeli)
ssh -o PreferredAuthentications=password dila@192.168.1.50
```

**Beklenen çıktı:**
```
Permission denied (publickey).
```

Bu çıktı doğru! Parola ile giriş artık engellenmiş.

### 6.5 SSH Config Dosyası Oluşturma (Kolaylık İçin)

Host bilgisayarınızda (Windows):

```powershell
# SSH config dosyası oluştur
notepad C:\Users\YourName\.ssh\config
```

**Dosya içeriği:**

```
Host webserver
    HostName 192.168.1.50
    User dila
    IdentityFile C:\Users\YourName\.ssh\id_rsa

Host dbserver
    HostName 192.168.1.51
    User dila
    IdentityFile C:\Users\YourName\.ssh\id_rsa
```

Kaydedin.

**Artık şu şekilde bağlanabilirsiniz:**

```powershell
ssh webserver
ssh dbserver
```

---

## 7. Güvenlik Duvarı Yapılandırması (UFW)

### 7.1 UFW Nedir ve Neden Kullanıyoruz?

**Güvenlik Duvarı Neden Gerekli?**
- İstenmeyen dış erişimleri engeller
- Sadece gerekli portları açık tutar
- Saldırı yüzeyini azaltır
- "Default deny" (varsayılan reddet) politikası güvenlik sağlar

### 7.2 Web Sunucusu Güvenlik Duvarı Yapılandırması

**Web VM'ine bağlan:**

```bash
ssh dila@192.168.1.50
```

**Adım 1: UFW'yi kur**

```bash
# Paket listesini güncelle
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
# SSH erişimine limitli izin ver (brute force koruması)
sudo ufw limit 22/tcp

# HTTP trafiğine izin ver
sudo ufw allow 80/tcp

```

**`limit` ne demek?**
- Aynı IP'den 30 saniyede 6'dan fazla bağlantı denemesi engellenir
- Brute force saldırılarına karşı koruma
- SSH için özellikle önemli

**Adım 4: Güvenlik duvarını etkinleştir**

```bash
# UFW'yi etkinleştir
sudo ufw enable

# Uyarı gelecek: "Command may disrupt existing ssh connections"
# y (yes) deyin, sorun yok çünkü SSH portunu açtık
```

**Adım 5: Durumu kontrol et**

```bash
# Verbose çıktı ile durum göster
sudo ufw status verbose
```

**Beklenen çıktı:**

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     LIMIT IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
22/tcp (v6)                LIMIT IN    Anywhere (v6)
80/tcp (v6)                ALLOW IN    Anywhere (v6)
```

**UFW otomatik olarak IPv6 kurallarını da ekler.**

**Adım 6: UFW'nin otomatik başladığını kontrol et**

```bash
# UFW servisinin otomatik başladığını kontrol et
sudo systemctl is-enabled ufw
```

**Çıktı:** `enabled` olmalı

### 7.3 Veritabanı Sunucusu Güvenlik Duvarı Yapılandırması

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
# SSH erişimine limitli izin ver
sudo ufw limit 22/tcp

# MySQL/MariaDB portunu SADECE web sunucusundan izin ver
sudo ufw allow from 192.168.1.50 to any port 3306 proto tcp
```

**Kritik Güvenlik Notu:**
- `from 192.168.1.50`: Sadece web sunucusundan erişim
- Veritabanı portunu tüm dünyaya açmak büyük güvenlik riski
- IP bazlı filtreleme ek güvenlik katmanı

**Adım 4: Güvenlik duvarını etkinleştir**

```bash
sudo ufw enable
sudo ufw status verbose
```

**Beklenen çıktı:**

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     LIMIT IN    Anywhere
3306/tcp                   ALLOW IN    192.168.1.50
22/tcp (v6)                LIMIT IN    Anywhere (v6)
```

### 7.4 Güvenlik Duvarı Test Etme

**Web VM'den DB VM'e MySQL bağlantısı test et:**

```bash
# Web VM'de (henüz MySQL client kurulu değilse kur)
sudo apt install mariadb-client -y

# DB'ye bağlanmayı dene
mysql -h 192.168.1.51 -u root -p
```

Bağlantı başarılı olmalı (veritabanı yapılandırmasına göre).

**Host'tan DB'ye bağlanmayı deneyin (reddedilmeli):**

```bash
# Host'tan (bu başarısız olmalı çünkü güvenlik duvarı engeller)
# PowerShell'de (eğer MySQL client kuruluysa)
mysql -h 192.168.1.51 -u root -p
```

**Beklenen sonuç:** Connection refused veya timeout hatası. Bu doğru! Sadece web sunucusu veritabanına erişebilir.

---

## 8. Veritabanı Sunucusu Kurulumu (MariaDB)

### 8.1 MariaDB Nedir ve Neden Kullanıyoruz?

**MariaDB:**
- MySQL'in açık kaynak fork'u
- MySQL ile %100 uyumlu
- Daha hızlı geliştirme döngüsü
- Tamamen açık kaynak
- WordPress ile mükemmel uyum

**Neden ayrı sunucuda?**
- Güvenlik: Veritabanı izole
- Performans: Kaynaklar paylaşılmaz
- Yönetim: Bağımsız yönetim ve yedekleme
- Ölçeklenebilirlik: Her servis bağımsız büyüyebilir

### 8.2 MariaDB Kurulumu

**DB VM'ine bağlan:**

```bash
ssh dila@192.168.1.51
```

**Adım 1: Paket listesini güncelle**

```bash
sudo apt update
```

**Adım 2: MariaDB Server'ı kur**

```bash
sudo apt install mariadb-server -y
```

**Adım 3: Servisin çalıştığını kontrol et**

```bash
# Servis durumunu kontrol et
sudo systemctl status mariadb

# Otomatik başlatmayı etkinleştir (genelde zaten etkin)
sudo systemctl enable mariadb
```

**Beklenen çıktı:**
```
● mariadb.service - MariaDB database server
     Loaded: loaded
     Active: active (running)
```

### 8.3 MariaDB Güvenlik Yapılandırması

```bash
# Güvenlik scriptini çalıştır
sudo mysql_secure_installation
```

**İnteraktif sorular ve cevaplar:**

```
Enter current password for root: [ENTER - henüz parola yok]

Switch to unix_socket authentication [Y/n]: n
(unix_socket zaten aktif, gerek yok)

Change the root password? [Y/n]: y
New password: [GÜÇLÜ BİR PAROLA GİRİN]
Re-enter new password: [TEKRAR GİRİN]

Remove anonymous users? [Y/n]: y
(Anonim kullanıcıları kaldır - güvenlik için önemli)

Disallow root login remotely? [Y/n]: y
(Root'un uzaktan girişini engelle - kritik güvenlik)

Remove test database and access to it? [Y/n]: y
(Test veritabanını sil - gereksiz)

Reload privilege tables now? [Y/n]: y
(Yetki tablolarını yeniden yükle)
```

**Bu adımların güvenlik önemi:**
- **Root parolası**: Yetkisiz erişimi engeller
- **Anonim kullanıcı silme**: Güvenlik açığı
- **Root uzaktan giriş engelleme**: Root sadece localhost'tan erişebilir
- **Test DB silme**: Gereksiz veritabanı güvenlik riski

### 8.4 MariaDB'ye Giriş Yapma

```bash
# Root olarak MariaDB'ye gir
sudo mysql -u root -p
```

Root parolanızı girin.

**MariaDB komut satırını göreceksiniz:**
```
MariaDB [(none)]>
```

### 8.5 WordPress için Veritabanı Oluşturma

**MariaDB komut satırında:**

```sql
-- WordPress için veritabanı oluştur
CREATE DATABASE wordpress_db;

-- Veritabanının oluştuğunu kontrol et
SHOW DATABASES;
```


### 8.6 WordPress için Kullanıcı Oluşturma

```sql
-- Web sunucusundan (192.168.1.50) erişebilecek kullanıcı oluştur
CREATE USER 'wp_user'@'192.168.1.50' IDENTIFIED BY '12345';

-- Kullanıcıya wordpress_db üzerinde tam yetki ver
GRANT ALL PRIVILEGES ON wordpress_db.* TO 'wp_user'@'192.168.1.50';

-- Değişiklikleri uygula
FLUSH PRIVILEGES;
```

**Kritik Güvenlik Notu:**
- `'wp_user'@'192.168.1.50'`: Kullanıcı sadece bu IP'den bağlanabilir
- `'wp_user'@'%'` gibi wildcard kullanmayın (tüm IP'lerden erişim olur)
- Her web sunucusu için ayrı kullanıcı oluşturun

**Kullanıcıyı ve yetkilerini kontrol et:**

```sql
-- Kullanıcıları listele
SELECT User, Host FROM mysql.user WHERE User='wp_user';

-- Beklenen çıktı:
-- +---------+--------------+
-- | User    | Host         |
-- +---------+--------------+
-- | wp_user | 192.168.1.50 |
-- +---------+--------------+

-- Yetkileri göster
SHOW GRANTS FOR 'wp_user'@'192.168.1.50';
```

**MariaDB'den çık:**

```sql
EXIT;
```

### 8.7 MariaDB'yi Uzak Bağlantılara Açma

Varsayılan olarak MariaDB sadece localhost'tan bağlantı kabul eder. Uzak bağlantıları etkinleştirmeliyiz.

```bash
# MariaDB yapılandırmasını düzenle
sudo nano /etc/mysql/mariadb.conf.d/50-server.cnf
```

**Şu satırı bulun:**

```ini
bind-address = 127.0.0.1
```

**Şu şekilde değiştirin:**

```ini
bind-address = 0.0.0.0
```

**veya daha güvenli (sadece DB sunucusunun IP'si):**

```ini
bind-address = 192.168.1.51
```

**bind-address seçenekleri:**
- `127.0.0.1`: Sadece localhost (varsayılan, uzak bağlantı yok)
- `0.0.0.0`: Tüm ağ arayüzlerinden (her yerden)
- `192.168.1.51`: Sadece bu IP'den

**Kaydedin:** `Ctrl+O`, `Enter`, `Ctrl+X`

**MariaDB'yi yeniden başlat:**

```bash
sudo systemctl restart mariadb

# Servisin çalıştığını kontrol et
sudo systemctl status mariadb
```

### 8.8 Web Sunucusundan Bağlantı Testi

**Web VM'ine geç:**

```bash
ssh dila@192.168.1.50
```

**DB sunucusuna bağlan:**

```bash
mysql -h 192.168.1.51 -u wp_user -p
```

Parolayı girin: `12345`

**Başarılı bağlantı:**

```sql
-- Veritabanlarını listele
SHOW DATABASES;

-- wordpress_db'yi seç
USE wordpress_db;

-- Hangi veritabanında olduğumuzu kontrol et
SELECT DATABASE();

-- Çıkış
EXIT;
```

Başarılı oldu mu? Harika! Veritabanı hazır.

---

## 9. Web Sunucusu Kurulumu (Apache)

### 9.1 Apache Nedir ve Neden Kullanıyoruz?

**Apache HTTP Server:**
- Dünyanın en popüler web sunucusu
- Güçlü modüler yapı
- .htaccess desteği (WordPress için önemli)
- Geniş dokümantasyon ve topluluk desteği
- WordPress tarafından önerilen sunucu

### 9.2 Apache ve PHP Kurulumu

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
# Apache, PHP ve WordPress için gerekli PHP eklentilerini kur
sudo apt install -y apache2 php8.3 libapache2-mod-php8.3 \
  php8.3-mysql php8.3-curl php8.3-gd php8.3-mbstring \
  php8.3-xml php8.3-xmlrpc php8.3-zip php8.3-intl
```

**Kurduğumuz paketlerin açıklaması:**

| Paket | Açıklama | WordPress'te Kullanımı |
|-------|----------|----------------------|
| `apache2` | Web sunucusu | Ana sunucu |
| `php8.3` | PHP yorumlayıcısı | WordPress'in çalışması için |
| `libapache2-mod-php8.3` | Apache-PHP entegrasyonu | Apache ile PHP çalıştırma |
| `php8.3-mysql` | MySQL/MariaDB bağlantısı | Veritabanı işlemleri |
| `php8.3-curl` | HTTP istekleri | API çağrıları, güncelleme kontrolü |
| `php8.3-gd` | Resim işleme | Küçük resim (thumbnail) oluşturma |
| `php8.3-mbstring` | Multi-byte string | Türkçe karakter desteği |
| `php8.3-xml` | XML işleme | RSS, import/export |
| `php8.3-xmlrpc` | XML-RPC protokolü | Bazı eklentiler için |
| `php8.3-zip` | ZIP dosya işleme | Tema/eklenti kurulumu |
| `php8.3-intl` | Uluslararasılaştırma | Çoklu dil desteği |

**Adım 3: Servisleri başlat ve etkinleştir**

```bash
# Apache'yi başlat
sudo systemctl start apache2

# Sistem açılışında otomatik başlaması için etkinleştir
sudo systemctl enable apache2

# Servis durumunu kontrol et
sudo systemctl status apache2
```

**Beklenen çıktı:**
```
● apache2.service - The Apache HTTP Server
     Loaded: loaded
     Active: active (running)
```

**Adım 4: Apache kurulumunu test et**

Tarayıcınızda şu adrese gidin:

```
http://192.168.1.50
```

**Apache2 Ubuntu Default Page** görmelisiniz. Bu sayfa Apache'nin çalıştığını gösterir.

### 9.3 Apache Modüllerini Etkinleştirme

WordPress için gerekli Apache modüllerini etkinleştirelim.

```bash
# mod_rewrite: SEO-uyumlu URL'ler için (kritik!)
sudo a2enmod rewrite

# Apache'yi yeniden başlat
sudo systemctl restart apache2
```

**mod_rewrite neden kritik?**
- WordPress permalink yapısı için zorunlu
- SEO-uyumlu URL'ler (bugday.org/yazilar/baslik)
- REST API çalışması için gerekli
- .htaccess dosyasının işlevselliği

**mod_rewrite olmadan:**
```
❌ bugday.org/benim-yazim/ → 404 Hatası
❌ REST API çalışmaz
❌ WordPress admin paneli sorun yaşar
```

**mod_rewrite ile:**
```
✅ bugday.org/benim-yazim/ → Çalışır
✅ REST API çalışır
✅ Tüm WordPress özellikleri aktif
```


### 9.4 Web Siteleri için Dizin Yapısı Oluşturma

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

**www-data kullanıcısı nedir?**
- Apache bu kullanıcı ile çalışır
- Web dosyalarının sahibi olmalı
- WordPress'in dosya oluşturabilmesi için gerekli
- Güvenlik için root kullanılmaz

**755 yetkileri:**
- **Sahip (www-data)**: okuma + yazma + çalıştırma (7)
- **Grup**: okuma + çalıştırma (5)
- **Diğerleri**: okuma + çalıştırma (5)

### 9.5 Apache Varsayılan Sitesini Devre Dışı Bırakma

```bash
# Varsayılan siteyi devre dışı bırak
sudo a2dissite 000-default.conf

# Apache'yi yeniden yükle
sudo systemctl reload apache2
```

**Neden varsayılan siteyi kaldırıyoruz?**
- Kendi sitelerimizi kullanacağız
- Port 80 çakışmasını önler
- Gereksiz bilgi sızıntısını engeller

---

## 10. 2025ozgur.com Web Sitesi Kurulumu

### 10.1 Site İçeriği Oluşturma

**Web VM'de:**

```bash
# 100 satırlık içerik oluştur
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

# Yetkileri düzelt
sudo chown www-data:www-data /var/www/2025ozgur/index.html
sudo chmod 644 /var/www/2025ozgur/index.html
```

### 10.2 Yönetim Sayfası için Parola Koruması

**Adım 1: htpasswd aracını kur**

```bash
sudo apt install apache2-utils -y
```

**Adım 2: Parola dosyası oluştur**

```bash
# .htpasswd dosyası oluştur
sudo htpasswd -c /etc/apache2/.htpasswd ad.soyad
```

**Parola soracak:**
```
New password: parola
Re-type new password: parola
```

**Neden /etc/apache2/.htpasswd?**
- Web root dışında (güvenlik)
- Tarayıcıdan erişilemez
- Apache kolayca bulur

**Parolayı kontrol et:**

```bash
cat /etc/apache2/.htpasswd
```

Çıktı:
```
ad.soyad:$apr1$xxx...
```

**Adım 3: Yönetim dizini oluştur**

```bash
sudo mkdir -p /var/www/2025ozgur/yonetim
sudo chown -R www-data:www-data /var/www/2025ozgur/yonetim
```

### 10.3 Apache Virtual Host Yapılandırması

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

**Yapılandırma açıklaması:**
- `ServerName`: Ana domain
- `ServerAlias`: www ile de erişilebilir
- `AllowOverride All`: .htaccess kullanımına izin
- `AuthType Basic`: Temel HTTP kimlik doğrulama
- `Require valid-user`: .htpasswd'deki herhangi bir geçerli kullanıcı

**Kaydedin:** `Ctrl+O`, `Enter`, `Ctrl+X`

**Adım 4: Siteyi etkinleştir**

```bash
# Siteyi etkinleştir
sudo a2ensite 2025ozgur.com.conf

# Yapılandırmayı test et
sudo apache2ctl configtest

# Apache'yi yeniden yükle
sudo systemctl reload apache2
```

### 10.4 Hosts Dosyasına Ekleme (Test için)

**Windows'ta `C:\Windows\System32\drivers\etc\hosts` dosyasını düzenle:**

PowerShell'i **yönetici olarak** çalıştır:

```powershell
notepad C:\Windows\System32\drivers\etc\hosts
```

Ekle:

```
192.168.1.50 2025ozgur.com www.2025ozgur.com
```

Kaydet ve DNS cache'i temizle:

```powershell
ipconfig /flushdns
```

### 10.5 Test Etme

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

Kullanıcı adı ve parola soracak:
- **Kullanıcı adı**: ad.soyad
- **Parola**: parola

---

## 11. WordPress Kurulumu (bugday.org)

### 11.1 WordPress İndirme

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

### 11.2 WordPress Dosyalarını Kopyalama

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

**Dosya yetkileri neden bu şekilde?**
- **Dizinler (755)**: Listele, oku, gir
- **Dosyalar (644)**: Oku, www-data yazabilir
- **Güvenlik**: Gereksiz yazma/çalıştırma yok

### 11.3 WordPress Yapılandırma Dosyası Oluşturma

```bash
cd /var/www/bugday

# Örnek yapılandırmayı kopyala
sudo cp wp-config-sample.php wp-config.php

# Yapılandırmayı düzenle
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

### 11.4 bugday.org için Apache Virtual Host

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

**Punycode açıklaması:**
- `buğday.org` → ` xn--buday-l1a.org` (Punycode)
- Tarayıcılar otomatik Punycode'a çevirir
- Apache'de her iki versiyonu da ekleyin

**Kaydet, etkinleştir:**

```bash
sudo a2ensite bugday.org.conf
sudo apache2ctl configtest
sudo systemctl reload apache2
```

### 11.5 Hosts Dosyasına bugday.org Ekleme

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
http://bugday.org
```

**Kurulum adımları:**

1. Dil seçimi: **Türkçe** veya **English**
2. **Hadi Başlayalım!** (Let's go!)
3. Site bilgileri:
   - **Site Başlığı**: Bugday Blog
   - **Kullanıcı Adı**: admin (veya başka)
   - **Parola**: Güçlü bir parola
   - **E-posta**: Geçerli e-posta
   - **Arama motorlarının siteyi indekslemesine izin ver**: ✓
4. **WordPress'i Kur**

Kurulum tamamlandı!

### 11.7 WordPress'e Giriş

```
http://bugday.org/wp-admin
```

Kullanıcı adı ve parola ile giriş yapın.

### 11.8 Permalink Ayarı (SEO-Uyumlu URL)

WordPress yönetim panelinde:

1. **Ayarlar** → **Kalıcı Bağlantılar**
2. **Yazı adı** seçeneğini seçin: `/%postname%/`
3. **Değişiklikleri Kaydet**

**Hata alırsanız:** "Yanıt geçerli bir JSON yanıtı değil"

Bu mod_rewrite sorunu. Çözüm:

```bash
# Web VM'de
sudo a2enmod rewrite
sudo systemctl restart apache2
```

WordPress'te permalink ayarlarını tekrar kaydedin.

### 11.9 .htaccess Dosyası Oluşturma

WordPress otomatik oluşturmalı, ama yoksa manuel oluşturun:

```bash
sudo nano /var/www/bugday/.htaccess
```

**İçerik:**

```apache
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
```

**Yetkileri düzelt:**

```bash
sudo chown www-data:www-data /var/www/bugday/.htaccess
sudo chmod 644 /var/www/bugday/.htaccess
```

### 11.10 Yeni Yazı Oluşturma ve Dosya Yükleme

WordPress yönetim panelinde:

1. **Yazılar** → **Yeni Ekle**
2. **Başlık**: "Benim Yeni Yazım"
3. **İçerik**: İstediğiniz içeriği yazın
4. **Dosya yüklemek için**:
   - Blok ekle **(+)** butonuna tıklayın
   - **Resim** veya **Dosya** bloğunu seçin
   - Bilgisayarınızdan bir dosya yükleyin (resim, PDF, vb.)
5. **Yayımla** butonuna tıklayın

### 11.11 Yazınızı Görüntüleme

Yazı yayımlandıktan sonra **"Yazıyı Görüntüle"** linkine tıklayın.

URL şöyle olacak:
```
http://bugday.org/benim-yeni-yazim/
```

Bu SEO-uyumlu URL yapısıdır!

### 11.12 buğday.org ile Test

Aynı WordPress'e `buğday.org` ile de erişebilmelisiniz:

```
http://buğday.org
http:// xn--buday-l1a.org
```

Her iki domain de aynı WordPress sitesini gösterecek.

---

## 12. Test ve Doğrulama

### 12.1 Sistem Geneli Testler

**Tüm servislerin çalıştığını kontrol et:**

```bash
# Web VM'de
sudo systemctl status apache2
sudo systemctl status ufw

# DB VM'de
sudo systemctl status mariadb
sudo systemctl status ufw
```

**Ağ bağlantılarını test et:**

```bash
# Web VM'den DB VM'e
ping -c 4 192.168.1.51

# DB VM'den Web VM'e
ping -c 4 192.168.1.50
```

### 12.2 Güvenlik Duvarı Testleri

**Web VM'de:**

```bash
sudo ufw status verbose
```

Beklenen:
- SSH (22): LIMIT
- HTTP (80): ALLOW

**DB VM'de:**

```bash
sudo ufw status verbose
```

Beklenen:
- SSH (22): LIMIT
- MySQL (3306): ALLOW from 192.168.1.50 only

### 12.3 SSH Güvenlik Testleri

**Parola ile giriş denemesi (başarısız olmalı):**

```powershell
# Host'tan
ssh -o PreferredAuthentications=password dila@192.168.1.50
```

Beklenen: `Permission denied (publickey)`

**Anahtar ile giriş (başarılı olmalı):**

```powershell
ssh dila@192.168.1.50
```

Parola sormadan giriş yapmalı.

### 12.4 Veritabanı Bağlantı Testleri

**Web VM'den DB'ye bağlantı:**

```bash
mysql -h 192.168.1.51 -u wp_user -p
```

Başarılı olmalı.

**Host'tan DB'ye bağlantı (başarısız olmalı):**

```bash
# PowerShell'de (eğer MySQL client varsa)
mysql -h 192.168.1.51 -u wp_user -p
```

Beklenen: Connection refused veya timeout (güvenlik duvarı engelledi)

### 12.5 Web Siteleri Testleri

**2025ozgur.com ana sayfa:**

```
http://2025ozgur.com
http://www.2025ozgur.com
```

✅ 100 satırlık taahhüt görünmeli

**2025ozgur.com yönetim sayfası:**

```
http://2025ozgur.com/yonetim
```

✅ Kullanıcı adı/parola sorup giriş yapmalı
- Kullanıcı: ad.soyad
- Parola: parola

**bugday.org WordPress:**

```
http://bugday.org
http://www.bugday.org
http://buğday.org
http:// xn--buday-l1a.org
```

✅ WordPress sitesi açılmalı

**WordPress admin paneli:**

```
http://bugday.org/wp-admin
```

✅ Giriş sayfası açılmalı

**SEO-uyumlu URL testi:**

Bir yazı URL'si:
```
http://bugday.org/benim-yeni-yazim/
```

✅ Yazı görünmeli (404 değil)

### 12.6 WordPress REST API Testi

```bash
# Web VM'de
curl http://bugday.org/wp-json/wp/v2/posts
```

✅ JSON formatında yazılar listesi dönmeli

Eğer 404 alırsanız, mod_rewrite veya .htaccess sorunu var.

### 12.7 Dosya Yükleme Testi

WordPress'te:

1. **Medya** → **Yeni Ekle**
2. Büyük bir resim yükleyin (2-5 MB)
3. Başarılı olmalı (64M limite kadar)

### 12.8 Yeniden Başlatma Testi

**Tüm servislerin otomatik başladığını test et:**

```bash
# Her iki VM'i de yeniden başlat
sudo reboot
```

VM'ler yeniden başladıktan sonra:

1. SSH ile bağlanabilir misiniz?
2. Web siteleri açılıyor mu?
3. WordPress çalışıyor mu?
4. Veritabanı bağlantısı sağlanıyor mu?

Hepsi **EVET** olmalı!

---

## Ek Notlar ve İpuçları

### Önemli Dosya Konumları

**Web VM:**
- Apache yapılandırma: `/etc/apache2/`
- Virtual Hosts: `/etc/apache2/sites-available/`
- Web dosyaları: `/var/www/`
- PHP yapılandırma: `/etc/php/8.3/apache2/php.ini`
- Apache logları: `/var/log/apache2/`

**DB VM:**
- MariaDB yapılandırma: `/etc/mysql/`
- MariaDB logları: `/var/log/mysql/`

**Her iki VM:**
- SSH yapılandırma: `/etc/ssh/sshd_config`
- Netplan yapılandırma: `/etc/netplan/`
- UFW yapılandırma: `/etc/ufw/`

### Faydalı Komutlar

**Servis yönetimi:**
```bash
sudo systemctl start/stop/restart/status servis_adi
sudo systemctl enable/disable servis_adi
```

**Log görüntüleme:**
```bash
# Apache hata logları
sudo tail -f /var/log/apache2/error.log

# Apache erişim logları
sudo tail -f /var/log/apache2/access.log

# Sistem logları
sudo journalctl -xe
```

**Disk kullanımı:**
```bash
df -h
du -sh /var/www/*
```

**Ağ bağlantıları:**
```bash
# Açık portlar
sudo ss -tlnp

# Firewall durumu
sudo ufw status verbose

# Ağ trafiği
sudo iftop
```

### Yapılan İşlemlerin Özeti

| Kategori | Yapılan İşlem | Neden Önemli |
|----------|---------------|--------------|
| Ağ | Statik IP atama | Güvenilir iletişim |
| Güvenlik | SSH anahtar tabanlı giriş | Brute force koruması |
| Güvenlik | Parola girişini kapatma | Güçlü kimlik doğrulama |
| Güvenlik | UFW yapılandırması | Gereksiz portları kapatma |
| Güvenlik | DB portunu IP ile filtreleme | Veritabanı izolasyonu |
| Web | Apache + PHP kurulumu | WordPress çalışması |
| Web | mod_rewrite etkinleştirme | SEO-uyumlu URL'ler |
| Web | Virtual Host yapılandırması | Çoklu site desteği |
| Veritabanı | MariaDB kurulumu | WordPress verisi |
| Veritabanı | Uzak bağlantı yapılandırması | Ayrı sunucu mimarisi |
| WordPress | Kurulum ve yapılandırma | Blog/site yönetimi |
| WordPress | Permalink ayarları | SEO optimizasyonu |

**Bu sistem production ortamına yakın bir yapıdadır ve gerçek dünya senaryolarında kullanılabilir.**