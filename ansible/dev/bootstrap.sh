sudo apt-get -y install python-pip git python-dev
mkdir ~/src
cd ~/src
git clone https://gist.github.com/7273812.git setup
cd setup
sudo pip install --upgrade ansible
