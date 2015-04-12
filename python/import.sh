#!/bin/bash
password=password
pin=a
echo $pin > a.txt
echo >> a.txt
echo Yes > y.txt
echo >> y.txt
rm -f ./cert8.db ./key3.db ./secmod.db
rm -rf ~/.cspid
cspid_cli --initialize -p "$pin"
cspid_cli --import -f ~/.testca/a.p12 -p "$pin" --p12pin "$password" -y < y.txt
certutil -N -d . --empty-password
modutil -add cspid -libfile /opt/cspid/libcspid.so -dbdir . -force
for crl in $(ls ~/.testca | grep ^.*\.crl\.pem$)
do
	echo $crl
	crl_base=$(echo $crl | sed 's/\.pem$//')
	openssl crl -in ~/.testca/$crl -inform PEM -out ~/.testca/$crl_base -outform DER
	crlutil -I -d . -i ~/.testca/${crl_base}
done
certutil -L -d . -h all < a.txt
