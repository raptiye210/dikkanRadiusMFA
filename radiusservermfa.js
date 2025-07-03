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
  config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
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
}

debugLogWithId('SYSTEM', 'Uygulama başlatıldı.');

const smtpTransport = nodemailer.createTransport({
  host: config.smtp.host,
  port: config.smtp.port,
  secure: config.smtp.secure,
  auth: config.smtp.auth,
  tls: config.smtp.tls
});

function generateSixDigitCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function logCodeToFile(username, ip, email, mobile, code, clientIP) {
  const line = `[${new Date().toISOString()}] ${username} | IP: ${ip} | Email: ${email || 'yok'} | Mobile: ${mobile || 'yok'} | Kod: ${code} | Client IP: ${clientIP}\n`;
  fs.appendFileSync(codeFile, line);
}

async function sendVerificationEmail(sessionId, toEmail, code, ip, username, mobile, clientIP) {
  const mailOptions = {
    from: config.smtp.from,
    to: toEmail,
    subject: config.smtp.subject,
    text: `${config.smtp.message} ${code}`
  };

  await smtpTransport.sendMail(mailOptions);
  logCodeToFile(username, ip, toEmail, mobile, code, clientIP);
  userCodeMap.set(username, { code, timestamp: Date.now() });
  debugLogWithId(sessionId, `E-posta gönderildi: ${toEmail} → Kod: ${code}`);
}

const server = dgram.createSocket('udp4');

server.on('message', async (msg, rinfo) => {
  const sessionId = uuidv4(); // Her bağlantı için benzersiz sessionId
  debugLogWithId(sessionId, 'Yeni bağlantı alındı:', rinfo.address);

  try {
    const packet = radius.decode({ packet: msg, secret: config.radius.secret });
    if (packet.code !== 'Access-Request') return;

    const username = packet.attributes['User-Name'];
    const password = packet.attributes['User-Password'];
    const clientIP = packet.attributes['Framed-IP-Address'] || packet.attributes['Calling-Station-Id'] || rinfo.address;
    const userDN = `${username}@${config.ldap.domain}`;

    // Kullanıcı adı veya şifre eksikse uyarı ver
    if (!username || !password) {
      debugLogWithId(sessionId, 'Uyarı: Kullanıcı adı veya şifre eksik. username:' + username + ' password:' + password);
      console.warn(`[${sessionId}] Uyarı: Kullanıcı adı veya şifre eksik. username:` + username + ' password:' + password);
      return;
    }

    // User-Password hariç diğer attribute'ları debugLog'a yaz
    debugLogWithId(sessionId, `------------------------------------------------------------`);
    Object.entries(packet.attributes).forEach(([k, v]) => {
      if (k !== 'User-Password') {
        debugLogWithId(sessionId, `Attr: ${k} = ${v}`);
      }
    });

    const is2faStep = userCodeMap.has(username) && password.length === 6 && /^\d+$/.test(password);

    if (is2faStep) {
      const record = userCodeMap.get(username);
      const isExpired = !record || Date.now() - record.timestamp > config.code.maxAgeMs;

      if (isExpired) {
        userCodeMap.delete(username);
        const response = radius.encode_response({
          packet,
          code: 'Access-Reject',
          secret: config.radius.secret,
          attributes: [['Reply-Message', '2FA kodu süresi dolmuş.']]
        });
        server.send(response, 0, response.length, rinfo.port, rinfo.address);
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
        debugLogWithId(sessionId, `${username} → Kod doğru → Access-Accept`);
      } else {
        const response = radius.encode_response({
          packet,
          code: 'Access-Reject',
          secret: config.radius.secret,
          attributes: [['Reply-Message', '2FA kodu geçersiz.']]
        });
        server.send(response, 0, response.length, rinfo.port, rinfo.address);
        debugLogWithId(sessionId, `${username} → Kod yanlış → Access-Reject`);
      }
      return;
    }

    const client = ldap.createClient({ url: config.ldap.url });

    client.bind(userDN, password, (err) => {
      if (err) {
        debugLogWithId(sessionId, `${username} → LDAP bağlanamadı: ${err.message}`);
        client.unbind();
        return;
      }

      const opts = {
        filter: `(sAMAccountName=${username})`,
        scope: 'sub',
        attributes: ['mobile', 'mail']
      };

      client.search(config.ldap.baseDN, opts, (err, res) => {
        if (err) {
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

          debugLogWithId(sessionId, `${username} doğrulandı. Email: ${email}, IP: ${rinfo.address}`);

          const code = generateSixDigitCode();

          if (email) {
            await sendVerificationEmail(sessionId, email, code, rinfo.address, username, cleanedMobile, clientIP);

            const response = radius.encode_response({
              packet,
              code: 'Access-Challenge',
              secret: config.radius.secret,
              attributes: [['Reply-Message', `2FA kodu ${email} adresinize gonderildi.`]]
            });

            server.send(response, 0, response.length, rinfo.port, rinfo.address);
            debugLogWithId(sessionId, `${username} → Access-Challenge gönderildi.`);
          } else {
            debugLogWithId(sessionId, `${username} → E-posta adresi yok, kod gönderilmedi.`);
          }
        });

        res.on('end', () => client.unbind());
        res.on('error', (err) => {
          debugLogWithId(sessionId, `${username} → LDAP arama hatası: ${err.message}`);
          client.unbind();
        });
      });
    });

  } catch (err) {
    debugLogWithId(sessionId, `RADIUS hata: ${err.message}`);
  }
});

server.on('listening', () => {
  const { address, port } = server.address();
  debugLogWithId('SYSTEM', `RADIUS sunucusu başlatıldı: ${address}:${port}`);
});

server.bind(config.radius.port);

cron.schedule(config.backup.cronTime, () => {
  try {
    if (fs.existsSync(codeFile)) {
      const today = new Date().toISOString().slice(0, 10);
      const backup = path.join(__dirname, `${config.files.codeBackupPrefix}${today}.txt`);
      fs.copyFileSync(codeFile, backup);
      fs.truncateSync(codeFile, 0);
      debugLogWithId('SYSTEM', `Kod dosyası yedeklendi → ${backup}`);
    }
  } catch (err) {
    debugLogWithId('SYSTEM', `Yedekleme hatası: ${err.message}`);
  }
});
