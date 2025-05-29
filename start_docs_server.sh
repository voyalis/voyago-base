#!/bin/bash
# start_docs_server.sh: VoyaGo Omega X dokümantasyon geliştirme sunucusunu başlatır.

VENV_DIR=".venv_docs"
PORT="8001" # Çakışmaları önlemek için farklı bir port

echo "VoyaGo Omega X Dokümantasyon Sunucusu Başlatılıyor..."
echo "----------------------------------------------------"

# 1. Sanal ortamın varlığını kontrol et
if [ ! -d "$VENV_DIR" ]; then
    echo "❌ HATA: '$VENV_DIR' sanal ortamı bulunamadı."
    echo "Lütfen önce './setup_docs_env.sh' script'ini çalıştırarak ortamı kurun."
    exit 1
fi

# 2. Sanal ortamı bu script içinde geçici olarak aktifleştir
# (Bu, script bittiğinde dış kabuğu etkilemez, ama script içindeki komutlar
# sanal ortamın Python ve pip'ini kullanır)
source "$VENV_DIR/bin/activate"
if [ $? -ne 0 ]; then
    echo "❌ HATA: Sanal ortam ($VENV_DIR) aktifleştirilemedi."
    exit 1
fi
echo "✅ Sanal ortam '$VENV_DIR' aktif."

# 3. mkdocs serve komutunu çalıştır
echo "📘 MkDocs sunucusu http://127.0.0.1:$PORT adresinde başlatılıyor..."
echo "   Durdurmak için Ctrl+C tuşlarına basın."
echo "----------------------------------------------------"

mkdocs serve -a "127.0.0.1:$PORT"

# Kullanıcı Ctrl+C ile sunucuyu durdurduktan sonra script buraya gelir.
echo "----------------------------------------------------"
echo "ℹ️ Dokümantasyon sunucusu durduruldu."
# Sanal ortamdan çıkış (bu script için gerekli değil çünkü script bitiyor)
# deactivate # Bu komut burada çalışırsa, sadece bu script'in alt kabuğunu etkiler.

exit 0