#!/bin/bash -eu
#
# Copyright 2020 Google LLC (Lisansı koruyabiliriz veya kendi lisansımızı ekleyebiliriz)
# ... (Lisans detayları) ...

# Go bin dizininin PATH'te olduğundan emin oluyoruz. 
# Eğer değilse, aşağıdaki satırı yorumdan çıkarıp kendi Go bin yolunuzla güncelleyebilirsiniz.
# export PATH=$PATH:$(go env GOPATH)/bin 
# VEYA doğrudan pluginlerin tam yolunu kullanabiliriz.

# Proto dosyamızın bulunduğu dizin (bu script'e göreceli)
PROTO_DIR="./proto"

# Üretilecek Go dosyalarının konulacağı dizin (bu script'e göreceli)
# Bu klasörün önceden oluşturulmuş olması iyi olur (mkdir genproto yapmıştık)
OUT_DIR="./genproto"

# Eğer OUT_DIR yoksa oluştur (isteğe bağlı, biz manuel oluşturduk)
# mkdir -p ${OUT_DIR}

echo "Generating Go files from ${PROTO_DIR}/auth.proto to ${OUT_DIR}..."

# protoc komutu
# ~/go/bin/protoc-gen-go ve ~/go/bin/protoc-gen-go-grpc pluginlerinin PATH'te olduğunu varsayıyoruz.
# Değilse, --plugin=protoc-gen-go=~/go/bin/protoc-gen-go gibi tam yollarını belirtmemiz gerekebilir.
# Şimdilik PATH'te olduğunu varsayalım.
protoc \
    --proto_path=${PROTO_DIR} \
    --go_out=${OUT_DIR} \
    --go_opt=paths=source_relative \
    --go-grpc_out=${OUT_DIR} \
    --go-grpc_opt=paths=source_relative \
    ${PROTO_DIR}/auth.proto

echo "Protobuf Go files generated successfully in ${OUT_DIR}."