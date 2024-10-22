https://github.blog/changelog/2023-10-02-github-actions-apple-silicon-m1-macos-runners-are-now-available-in-public-beta/

https://github.blog/changelog/2024-01-30-github-actions-introducing-the-new-m1-macos-runner-available-to-open-source/



https://github.com/hkratz/gha-runner-osx-arm64/pull/2
https://github.com/dotnet/runtime/issues/64103
```
export COMPlus_ReadyToRun=0
git clone https://github.com/hkratz/gha-runner-osx-arm64.git -b macos-arm64
cd gha-runner-osx-arm64/src/
./dev.sh layout
cd ../_layout/
./config.sh --url  {repo-url} --token AA... # use your repo URL and your runner registration token
```




https://gist.github.com/tadhgboyle/a0c859b7d7c0a258593dc00cdc5006cc




    install homebrew if you have not already
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

    install qemu
        brew install qemu

    extract the .ova file
        tar -xvf /path/to/ova

    convert the .ova file to a .qcow2 file
        qemu-img convert -O qcow2 /path/to/vdmk /path/to/output/qcow2
        make sure you have the .qcow2 extension in the output path
        there is no output until the processing is complete. it might take up to 5 minutes

    download utm

    make a new virtual machine in utm
        click the + icon on the top menu and then "start from scratch"
        go to the "drives" tab and click "import drive", then select the .qcow2 we just made
        in some cases you might have to disable uefi booting
            click on "system", then "advanced settings", and then unselect "uefi booting"
        by default, preformance is awful. to fix this you should give at least 6gb of RAM, 6 cores and enable mulicore mode
        click "save"

    start the virtual machine and enjoy x86_64 emulation on your m1 mac!

