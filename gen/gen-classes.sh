while IFS= read -r line
do 
  ks=$(echo $line | cut -d'-' -f2)
  mode=$(echo $line | cut -d'-' -f3)
  while IFS= read -r line
  do
    pad=$line
    pad_c=$(echo $pad | tr "." _ | tr "-" _)
    path=${PWD}/src/java/com/canonical/openssl/cipher/AES${ks}with${mode}padding${pad_c}.java
    cp ${PWD}/gen/template.java ${path}
    sed -i 's/__PADC__/'$pad_c'/g' ${path}
    sed -i 's/__KS__/'$ks'/g' ${path} 
    sed -i 's/__MODE__/'$mode'/g' ${path} 
    sed -i 's/__PAD__/'$pad'/g' ${path} 
  done <${PWD}/gen/padding.txt
done <${PWD}/gen/name-key-size-mode.txt
