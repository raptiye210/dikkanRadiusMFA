# Node.js 22 tabanlı resmi bir imaj kullanıyoruz
FROM node:latest

# Çalışma dizinini ayarlıyoruz
WORKDIR /home/basar/RadiusMFA

# package.json ve package-lock.json (varsa) kopyalıyoruz
COPY package*.json ./

# Bağımlılıkları yüklüyoruz
RUN npm install

# Uygulama dosyalarını kopyalıyoruz
COPY . .

# Uygulamanın çalışacağı portu belirtiyoruz
EXPOSE 1812/udp

# Uygulamayı başlatma komutu
CMD ["npm", "start"]