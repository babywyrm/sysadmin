# Install Wine with Mono & Gecko in Ubuntu 20.04
**Warning: Do not try those command in your main PC, I test in a virtual Machine**

**Note: Most of commands are from the `Dockerfile` in Reference section. If you want to test wine, just run their docker container**

## 1. Setup PPA

```bash
sudo dpkg --add-architecture i386
wget -qO - https://dl.winehq.org/wine-builds/winehq.key | sudo apt-key add -
# for Ubuntu 20.04
sudo apt-add-repository 'deb https://dl.winehq.org/wine-builds/ubuntu/ focal main'
```

## 2. Install Wine on Ubuntu
```bash
sudo apt-get update
sudo apt-get -y install winehq-stable=7.0.0.0~focal-1
# if ask paudio (or similar) different from ...., I choose to use Default [N]
```

## 3. Check Wine Version
```bash
wine --version
# It will prompt `wine-7.0`
```

## 4. Install Mono
```bash
sudo mkdir /opt/wine-stable/share/wine/mono
sudo wget -O - https://dl.winehq.org/wine/wine-mono/7.0.0/wine-mono-7.0.0-x86.tar.xz | sudo tar -xJv -C /opt/wine-stable/share/wine/mono
```

## 5. Download Gecko
```bash
sudo mkdir /opt/wine-stable/share/wine/gecko
sudo wget -O /opt/wine-stable/share/wine/gecko/wine-gecko-2.47.1-x86.msi https://dl.winehq.org/wine/wine-gecko/2.47.1/wine-gecko-2.47.1-x86.msi
sudo wget -O /opt/wine-stable/share/wine/gecko/wine-gecko-2.47.1-x86_64.msi https://dl.winehq.org/wine/wine-gecko/2.47.1/wine-gecko-2.47.1-x86_64.msi
```

After above steps, you should find wine-mono & wine-gecko as following screenshots:
![Where to find wine-mono](https://user-images.githubusercontent.com/5998887/215333623-72daf85f-487d-42f7-9354-19a04c8a7cc8.png)
![Where to find wine-gecko](https://user-images.githubusercontent.com/5998887/215333696-fddc1753-ea59-45f4-914a-a6afbe66603d.png)


## 6. Set WINE env config in bashrc
note: do not run any windows program before this setup
Run following lines will add WINE env config in your .bashrc file

``` bash
# Wine Setup
echo "export WINEPREFIX=~/prefix32" >> ~/.bashrc
echo "export WINEARCH=win32" >> ~/.bashrc
```

## 7. Run explore.exe to setup wine folder automatically.
Use following command in bash terminal, and it will take a while for setup.
``` bash
wine /opt/wine-stable/lib/wine/i386-windows/explorer.exe
# or
/opt/wine-stable/bin/wine /opt/wine-stable/lib/wine/i386-windows/explorer.exe
```
Here is screenshot of Windows explorer
![Windows explorer](https://user-images.githubusercontent.com/5998887/215333856-23f5af37-8ce1-497a-baf0-35adfaf1b1e8.png)


If setup successfully, go to `My Computer -> Control Panel -> Add/Remove Programs`.
Then, there should have `Wine Mono Windows Support` and `Wine Gecko`.  
Here are some screenshots:
* After double clicks `My Computer`
![After double clicks My Computer](https://user-images.githubusercontent.com/5998887/215334393-f71e9de6-f75d-4511-bbe9-c42a41684b7a.png)

* After double clicks `Control Panel`
![After double clicks Control Panel](https://user-images.githubusercontent.com/5998887/215334465-bcb07e8b-0b0d-451d-90d9-2a8694481fb8.png)


## 8. Manually install Mono and Gecko
After you double click `Add/Remove Programs`, nothing happenned or prompt some error message (such as `no suitable program to open Add/Remove Programs`). You may need to install Mono and Gecko, I used following steps.

### 8.1 Open `control.exe` in system32
* Go to `My Computer -> C: -> Windows -> system32`, find `control.exe` and double clicks it
![Screenshot from 2022-07-15 00-40-30](https://user-images.githubusercontent.com/5998887/215335790-95a1a869-e8e7-449d-ab66-82e6cb9043bf.png)

* Double click `Add/Remove Programs`
![Screenshot from 2022-07-15 00-40-42](https://user-images.githubusercontent.com/5998887/215335836-912b454a-fc5b-42ab-942f-415a63a4c1c9.png)

If there is no any program on the list (in the middle of `Add/Remove Programs` window), need to install manually.

### 8.2 Install wine-gecko
* Click `Install` button on the `Add/Remove Programs` window, then, It will show up `file dialog`. Find the `wine-gecko-x86.msi` file which download in previous step, and select & open it.
![Screenshot from 2022-07-15 00-41-14](https://user-images.githubusercontent.com/5998887/215336564-8a2c3221-5680-453e-8819-3bf779c3ed3a.png)
Then, `wine-gecko` should show up on the `Add/Remove Programs` window.
![Screenshot from 2022-07-15 00-41-57](https://user-images.githubusercontent.com/5998887/215336718-268be923-c9ff-464d-8689-d0484a1fe6a2.png)

### 8.3 Install wine-mono
* Click `Install` button on the `Add/Remove Programs` window, then, It will show up `file dialog`. Find the `winemono-support.msi` file which download in previous step, and select & open it.
![Screenshot from 2022-07-15 00-42-32](https://user-images.githubusercontent.com/5998887/215337220-e12f6973-634a-43ff-a6b7-8732cccf5dc9.png)
Then, `Wine Mono Windows Support` should show up on the `Add/Remove Programs` window.
![Screenshot from 2022-07-15 01-05-08](https://user-images.githubusercontent.com/5998887/215337313-2aafcb7c-0247-4a8c-b825-6e104f8d7263.png)

## Test some Windows programs with Wine
Here are some screenshots:

Run PuTTY
![Screenshot from 2022-07-15 00-54-53](https://user-images.githubusercontent.com/5998887/215337461-273aeb17-d8da-4f0b-8008-e5a23791db6b.png)

Run Bult-in Windows programs (such as `Task Manager`, `Notepad`, and `cmd.exe`), you can find them in `system32` folder
![Screenshot from 2022-07-15 00-39-17](https://user-images.githubusercontent.com/5998887/215337580-0dba36fb-c2f4-4ff8-9fdd-d27b9afbf950.png)


# Reference:
https://github.com/solarkennedy/wine-x11-novnc-docker/blob/master/Dockerfile  
https://tecadmin.net/install-wine-on-ubuntu/   
