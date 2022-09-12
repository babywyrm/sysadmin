# chkrootkit & rkhunter:
# www.fduran.com

http://www.chkrootkit.org/download/
http://sourceforge.net/projects/rkhunter/
cd /usr/local/src/
wget ftp://ftp.pangeia.com.br/pub/seg/pac/chkrootkit.tar.gz
tar zxvf chkrootkit.tar.gz
cd chkrootkit-0.49/
./chkrootkit

cd ..
wget http://sourceforge.net/projects/rkhunter/files/rkhunter/1.3.8/rkhunter-1.3.8.tar.gz/download
tar zxvf rkhunter-1.3.8.tar.gz
cd rkhunter-1.3.8
./installer.sh --install
rkhunter --check

#################################
##
##
