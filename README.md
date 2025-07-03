# RADIUS MFA Sunucusu

## Hakkında

Bu Node.js tabanlı uygulama, RADIUS protokolü üzerinden çift aşamalı kimlik doğrulama (MFA) sağlayan bir sunucudur. Kullanıcı ilk aşamada LDAP ile doğrulanır. Ardından, e-posta adresine 6 haneli bir kod gönderilir. Bu kod doğru şekilde girildiğinde erişim sağlanır.

## Geliştiriciler

- **Başar Sönmez**  
  📧 [basar@ecesoft.com.tr](mailto:basar@ecesoft.com.tr)  
  📱 +90 505 337 6198

- **Ali Yıldırım**  
  📧 [neoxp.pro@gmail.com](mailto:neoxp.pro@gmail.com)  
  📱 +90 534 574 0000

## Özellikler

- PAP destekli RADIUS sunucusu
- LDAP ile ilk aşama kullanıcı doğrulama
- E-posta ile ikinci aşama 6 haneli kod gönderimi (2FA)
- Her bağlantı için benzersiz `sessionId` (UUID) oluşturulup log'lara eklenmesi
- Başarılı 2FA girişlerinde `Access-Accept`, hatalı girişlerde `Access-Reject`
- `User-Password` dışındaki tüm RADIUS attribute'larını log'lama
- Kullanıcının LDAP üzerinden e-posta ve cep telefonu bilgilerini çekme
- JSON tabanlı konfigürasyon dosyası
- Günlük debug ve kod log'ları
- Kod log dosyasının günlük otomatik yedeklenmesi (`cron` desteği)

## Kurulum

```bash
npm install radius ldapjs nodemailer node-cron uuid
```

## Çalıştırma

```bash
node radiusservermfa.js
```

## Yapılandırma Dosyası (`radiusservermfa.json`)

Aşağıda örnek bir konfigürasyon yer almaktadır:

```json
{
  "radius": {
    "port": 1812,
    "secret": "ecesoft_secret"
  },
  "ldap": {
    "url": "ldap://192.168.1.10",
    "baseDN": "dc=ecesoft,dc=com,dc=tr",
    "domain": "ecesoft.com.tr"
  },
  "smtp": {
    "host": "smtp.ecesoft.com.tr",
    "port": 587,
    "secure": false,
    "auth": {
      "user": "noreply@ecesoft.com.tr",
      "pass": "sifre"
    },
    "tls": {
      "rejectUnauthorized": false
    },
    "from": "noreply@ecesoft.com.tr",
    "subject": "Güvenlik Kodunuz",
    "message": "Girişinizi tamamlamak için MFA kodunuz:"
  },
  "code": {
    "maxAgeMs": 300000
  },
  "files": {
    "debugLog": "radiusservermfa_debug.txt",
    "codeLog": "radiusservermfa_codes.txt",
    "codeBackupPrefix": "radiusservermfa_"
  },
  "backup": {
    "cronTime": "0 0 * * *"
  }
}
```

## Log Dosyaları

- `radiusservermfa_debug.txt`: Tüm bağlantılar, işlem adımları, hatalar ve `sessionId` bazlı takip bilgileri.
- `radiusservermfa_codes.txt`: Kod gönderimi yapılan kullanıcı, IP, e-posta ve kod bilgileri.
- `radiusservermfa_YYYY-MM-DD.txt`: Her gün oluşturulan kod log dosyasının yedeği (cron ile).

## Kullanım Akışı

1. Kullanıcı, PAP destekli bir istemci üzerinden RADIUS sunucusuna bağlanır.
2. LDAP ile ilk doğrulama yapılır.
3. LDAP üzerinden e-posta bilgisi alınırsa kullanıcıya 6 haneli MFA kodu gönderilir.
4. Kullanıcı aynı kullanıcı adı ile bu sefer MFA kodunu şifre yerine girer.
5. Kod geçerliyse `Access-Accept`, geçersizse `Access-Reject` yanıtı verilir.

## Destek

Destek talepleriniz için geliştiriciler ile doğrudan iletişime geçebilirsiniz.

---

© 2025 Ecesoft Teknoloji
