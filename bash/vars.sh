MY_PKCS11_LIB=/opt/cspid/libcspid.so
export MY_PKCS11_LIB
MY_PIN=a
export $MY_PIN
if [ -f $MY_PKCS11_LIB ]
then
	MY_TOKEN_CONTENT=$(pkcs11-tool --module "${MY_PKCS11_LIB}" --list-token-slots | grep ^Slot)
	echo $MY_TOKEN_CONTENT
	MY_CONTENT=$(pkcs11-tool --module "$MY_PKCS11_LIB" --login --list-objects --pin "$MY_PIN" 2>/dev/null)
	MY_KEY_ID=$(pkcs11-tool --module "$MY_PKCS11_LIB" --login --list-objects --pin "$MY_PIN" 2>/dev/null \
	| sed '0,/^Private Key Object/d' | head -n 2 | tail -n 1 \
	| awk '{print $2}')
	export MY_KEY_ID
fi
