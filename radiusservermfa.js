// ===================================================
//  RADIUS MFA Sunucusu
//  Geliştiriciler: Başar Sönmez & Ali Yıldırım
//  İletişim: basar@ecesoft.com.tr | +90 505 337 6198
// ===================================================

const radius = require('radius');
const ldap = require('ldapjs');
const dgram = require('dgram');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');
const cron = require('node-cron');
const { v4: uuidv4 } = require('uuid');  // UUID paketi

// Ayarları JSON'dan yükle
let config;
try {
  const configPath = path.join(__dirname, 'radiusservermfa.json');
  console.log('Konfigürasyon dosyası yükleniyor:', configPath);
  config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
  console.log('Konfigürasyon dosyası başarıyla yüklendi.');
} catch (err) {
  console.error('Konfigürasyon dosyası okunamadı veya hatalı:', err.message);
  process.exit(1);
}

const logFile = config?.files?.debugLog ? path.join(__dirname, config.files.debugLog) : null;
const codeFile = config?.files?.codeLog ? path.join(__dirname, config.files.codeLog) : null;

if (!logFile || !codeFile) {
  console.error('logFile veya codeFile tanımlı değil. Lütfen JSON ayarlarını kontrol edin.');
  process.exit(1);
}

const userCodeMap = new Map();

// Yeni debug fonksiyonu, sessionId ile log başına ekleniyor
function debugLogWithId(sessionId, ...args) {
  const line = `[${new Date().toISOString()}] [${sessionId}] ${args.join(' ')}\n`;
  fs.appendFileSync(logFile, line);
  console.log(`[${sessionId}]`, ...args);
}

debugLogWithId('SYSTEM', 'Uygulama başlatıldı.');
console.log('Uygulama başlatıldı.');

const smtpTransport = nodemailer.createTransport({
  host: config.smtp.host,
  port: config.smtp.port,
  secure: config.smtp.secure,
  auth: config.smtp.auth,
  tls: config.smtp.tls
});
console.log('SMTP transport oluşturuldu.');

function generateSixDigitCode() {
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  console.log('6 haneli kod oluşturuldu:', code);
  return code;
}

function logCodeToFile(username, ip, email, mobile, code, clientIP) {
  const line = `[${new Date().toISOString()}] ${username} | IP: ${ip} | Email: ${email || 'yok'} | Mobile: ${mobile || 'yok'} | Kod: ${code} | Client IP: ${clientIP}\n`;
  fs.appendFileSync(codeFile, line);
  console.log(`Kod dosyaya kaydedildi: ${username} | Kod: ${code} | Client IP: ${clientIP}`);
}

async function sendVerificationEmail(sessionId, toEmail, code, ip, username, mobile, clientIP) {
  const mailOptions = {
    from: config.smtp.from,
    to: toEmail,
    subject: config.smtp.subject,
    text: `${config.smtp.message} ${code}`
  };

  console.log(`[${sessionId}] E-posta gönderiliyor: ${toEmail} → Kod: ${code}`);
  await smtpTransport.sendMail(mailOptions);
  console.log(`[${sessionId}] E-posta gönderildi: ${toEmail}`);
  logCodeToFile(username, ip, toEmail, mobile, code, clientIP);
  userCodeMap.set(username, { code, timestamp: Date.now() });
  debugLogWithId(sessionId, `E-posta gönderildi: ${toEmail} → Kod: ${code}`);
}

const server = dgram.createSocket('udp4');
console.log('UDP sunucusu oluşturuldu.');

server.on('message', async (msg, rinfo) => {
  const sessionId = uuidv4(); // Her bağlantı için benzersiz sessionId
  console.log(`[${sessionId}] Yeni bağlantı alındı: ${rinfo.address}:${rinfo.port}`);
  debugLogWithId(sessionId, 'Yeni bağlantı alındı:', rinfo.address);

  try {
    console.log(`[${sessionId}] RADIUS paketi çözülüyor.`);
    const packet = radius.decode({ packet: msg, secret: config.radius.secret });
    if (packet.code !== 'Access-Request') {
      console.log(`[${sessionId}] Geçersiz paket kodu: ${packet.code}. İşlem sonlandırılıyor.`);
      return;
    }

    const username = packet.attributes['User-Name'];
    const password = packet.attributes['User-Password'];
    const clientIP = packet.attributes['Framed-IP-Address'] || packet.attributes['Calling-Station-Id'] || rinfo.address;
    const userDN = `${username}@${config.ldap.domain}`;
    console.log(`[${sessionId}] Kullanıcı: ${username}, Client IP: ${clientIP}`);

    // Kullanıcı adı veya şifre eksikse uyarı ver
    if (!username || !password) {
      console.warn(`[${sessionId}] Uyarı: Kullanıcı adı veya şifre eksik. username: ${username} password: ${password}`);
      debugLogWithId(sessionId, 'Uyarı: Kullanıcı adı veya şifre eksik. username:' + username + ' password:' + password);
      return;
    }

    // User-Password hariç diğer attribute'ları debugLog'a yaz
    console.log(`[${sessionId}] RADIUS Attributes:`);
    debugLogWithId(sessionId, `------------------------------------------------------------`);
    Object.entries(packet.attributes).forEach(([k, v]) => {
      if (k !== 'User-Password') {
        console.log(`[${sessionId}] Attr: ${k} = ${v}`);
        debugLogWithId(sessionId, `Attr: ${k} = ${v}`);
      }
    });

    const is2faStep = userCodeMap.has(username) && password.length === 6 && /^\d+$/.test(password);
    console.log(`[${sessionId}] 2FA adımı: ${is2faStep}`);

    if (is2faStep) {
      const record = userCodeMap.get(username);
      const isExpired = !record || Date.now() - record.timestamp > config.code.maxAgeMs;
      console.log(`[${sessionId}] Kod süresi kontrolü: Süresi dolmuş mu? ${isExpired}`);

      if (isExpired) {
        userCodeMap.delete(username);
        const response = radius.encode_response({
          packet,
          code: 'Access-Reject',
          secret: config.radius.secret,
          attributes: [['Reply-Message', '2FA kodu süresi dolmuş.']]
        });
        server.send(response, 0, response.length, rinfo.port, rinfo.address);
        console.log(`[${sessionId}] ${username} → Kod süresi dolmuş → Access-Reject`);
        debugLogWithId(sessionId, `${username} → Kod süresi dolmuş.`);
        return;
      }

      if (record.code === password) {
        userCodeMap.delete(username);
        const response = radius.encode_response({
          packet,
          code: 'Access-Accept',
          secret: config.radius.secret
        });
        server.send(response, 0, response.length, rinfo.port, rinfo.address);
        console.log(`[${sessionId}] ${username} → Kod doğru → Access-Accept`);
        debugLogWithId(sessionId, `${username} → Kod doğru → Access-Accept`);
      } else {
        const response = radius.encode_response({
          packet,
          code: 'Access-Reject',
          secret: config.radius.secret,
          attributes: [['Reply-Message', '2FA kodu geçersiz.']]
        });
        server.send(response, 0, response.length, rinfo.port, rinfo.address);
        console.log(`[${sessionId}] ${username} → Kod yanlış → Access-Reject`);
        debugLogWithId(sessionId, `${username} → Kod yanlış → Access-Reject`);
      }
      return;
    }

    console.log(`[${sessionId}] LDAP istemcisi oluşturuluyor.`);
    const client = ldap.createClient({ url: config.ldap.url });

    client.bind(userDN, password, (err) => {
      if (err) {
        console.error(`[${sessionId}] ${username} → LDAP bağlanamadı: ${err.message}`);
        debugLogWithId(sessionId, `${username} → LDAP bağlanamadı: ${err.message}`);
        client.unbind();
        return;
      }
      console.log(`[${sessionId}] ${username} → LDAP bağlantısı başarılı.`);

      const opts = {
        filter: `(sAMAccountName=${username})`,
        scope: 'sub',
        attributes: ['mobile', 'mail']
      };
      console.log(`[${sessionId}] LDAP araması başlatılıyor: ${username}`);

      client.search(config.ldap.baseDN, opts, (err, res) => {
        if (err) {
          console.error(`[${sessionId}] ${username} → LDAP arama hatası: ${err.message}`);
          debugLogWithId(sessionId, `${username} → LDAP arama hatası: ${err.message}`);
          client.unbind();
          return;
        }

        res.on('searchEntry', async (entry) => {
          const mobileAttr = entry.attributes.find(attr => attr.type === 'mobile');
          const emailAttr = entry.attributes.find(attr => attr.type === 'mail');

          const rawMobile = mobileAttr?.values?.[0] || '';
          const cleanedMobile = rawMobile.replace(/[^\d+]/g, '').trim();
          const email = emailAttr?.values?.[0] || '';
          console.log(`[${sessionId}] ${username} → LDAP araması: Email: ${email}, Mobile: ${cleanedMobile}`);

          debugLogWithId(sessionId, `${username} doğrulandı. Email: ${email}, IP: ${rinfo.address}`);

          const code = generateSixDigitCode();

          if (email) {
            console.log(`[${sessionId}] ${username} → 2FA kodu gönderiliyor: ${email}`);
            await sendVerificationEmail(sessionId, email, code, rinfo.address, username, cleanedMobile, clientIP);

            const response = radius.encode_response({
              packet,
              code: 'Access-Challenge',
              secret: config.radius.secret,
              attributes: [['Reply-Message', `2FA kodu ${email} adresinize gonderildi.`]]
            });

            server.send(response, 0, response.length, rinfo.port, rinfo.address);
            console.log(`[${sessionId}] ${username} → Access-Challenge gönderildi.`);
            debugLogWithId(sessionId, `${username} → Access-Challenge gönderildi.`);
          } else {
            console.log(`[${sessionId}] ${username} → E-posta adresi yok, kod gönderilmedi.`);
            debugLogWithId(sessionId, `${username} → E-posta adresi yok, kod gönderilmedi.`);
          }
        });

        res.on('end', () => {
          console.log(`[${sessionId}] LDAP bağlantısı kapatılıyor.`);
          client.unbind();
        });
        res.on('error', (err) => {
          console.error(`[${sessionId}] ${username} → LDAP arama hatası: ${err.message}`);
          debugLogWithId(sessionId, `${username} → LDAP arama hatası: ${err.message}`);
          client.unbind();
        });
      });
    });

  } catch (err) {
    console.error(`[${sessionId}] RADIUS hata: ${err.message}`);
    debugLogWithId(sessionId, `RADIUS hata: ${err.message}`);
  }
});

server.on('listening', () => {
  const { address, port } = server.address();
  console.log(`RADIUS sunucusu başlatıldı: ${address}:${port}`);
  debugLogWithId('SYSTEM', `RADIUS sunucusu başlatıldı: ${address}:${port}`);
});

server.bind(config.radius.port);
console.log(`RADIUS sunucusu ${config.radius.port} portunda dinlemeye başladı.`);

cron.schedule(config.backup.cronTime, () => {
  console.log('Yedekleme işlemi başlatılıyor.');
  try {
    if (fs.existsSync(codeFile)) {
      const today = new Date().toISOString().slice(0, 10);
      const backup = path.join(__dirname, `${config.files.codeBackupPrefix}${today}.txt`);
      fs.copyFileSync(codeFile, backup);
      fs.truncateSync(codeFile, 0);
      console.log(`Kod dosyası yedeklendi: ${backup}`);
      debugLogWithId('SYSTEM', `Kod dosyası yedeklendi → ${backup}`);
    } else {
      console.log('Yedeklenecek kod dosyası bulunamadı.');
    }
  } catch (err) {
    console.error(`Yedekleme hatası: ${err.message}`);
    debugLogWithId('SYSTEM', `Yedekleme hatası: ${err.message}`);
  }
});