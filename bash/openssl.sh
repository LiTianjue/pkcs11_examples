#!/bin/bash
my_dir=$(dirname $0)
# vars.sh sets MY_KEY_ID variable
source ${my_dir}/vars.sh
echo 'openssl <<EOF
engine -t dynamic -pre SO_PATH:/usr/lib64/openssl/engines/engine_pkcs11.so -pre ID:pkcs11 -pre LIST_ADD:1 -pre LOAD -pre MODULE_PATH:/opt/cspid/libcspid.so -pre VERBOSE
rsa -in slot_1-label_'${MY_KEY_ID}' -inform engine -engine pkcs11 -pubout -passin pass:a
s_client -connect localhost.localdomain:443 -cert /home/steve/.testca/a.pem -certform PEM -CApath /home/steve/.testca -engine pkcs11 -key slot_1-label_'${MY_KEY_ID}' -keyform engine -pass pass:a
EOF' > ${my_dir}/tmpopenssl.sh
bash ${my_dir}/tmpopenssl.sh
echo
#rm ${my_dir}/tmpopenssl.sh
