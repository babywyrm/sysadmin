```
stage("Generate Software Bill of Materials (sbom) with Syft"){
    steps{
        sh '''
            curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
            syft app:${BUILD_NUMBER} --scope all-layers -o json > sbom-${BUILD_NUMBER}.json
            syft app:${BUILD_NUMBER} --scope all-layers -o table > sbom-${BUILD_NUMBER}.txt
        '''
    }
}
```

Our supply chain is under attack. This has hard-hitting and long-lasting ramifications on commerce that could seriously impact businesses across the country (and the globe). Because of this, the U.S. Whitehouse launched a cybersecurity initiative to help guide developers and businesses. You can read the cybersecurity executive order in its entirety, so you’re familiar with everything it details. The gist, however, is that it’s become absolutely necessary for companies to be able to secure their supply chains.

To do that is no simple matter because there are so many moving parts involved. This is especially true in the cloud native world, where containers and Kubernetes are moving targets for insecurity.

But it all starts with one place… container images. If you’re not using trustworthy images, your entire stack could be compromised. But here’s the thing, those images are created by everyone, from individuals to large enterprise corporations. And sure, you can use various tools to scan those images for vulnerabilities, but it’s become quite clear that one particular piece of the puzzle is now in demand. That piece is a Software Bill Of Materials (SBOM).
What Is an SBOM?

Simply put, an SBOM is a full listing of every package and dependency that goes into making a container image. Okay, that could be challenging. Why? Because how many packages and dependencies go into creating a Linux container image? Take, for instance, Pop!_OS (which is my daily driver). If I issue the command:

dpkg --list |wc --lines

I am told there are 3,008 packages installed. That’s a lot. To make this more complicated, you can’t easily run that command on a container image. Sure, you could deploy a container based on the image, access the container, and then issue the command. But only if the dpkg and wc commands are included with that base image, you might see the output.

You don’t want to have to do that for every image you create. Given how incredibly busy developers are, that’s a big ask. So what do you do? Fortunately, there are tools available that make creating a Software Bill of Materials quite easy.

One such tool is called syft, from Anchore. With syft you can have it pull down images and extract a full SBOM very quickly. Once you have that SBOM you can present it to those who need the list, so they can verify everything included in the image meets company requirements and/or security policies.

What’s better, syft doesn’t just list the name of the included package, it also adds the version number. That means every single package installed can be verified for security.

That’s important.

And because syft supports most package formats (including APK, DEB, RPM, Ruby Bundles, Python Wheel/Egg/requirements.txt, JavaScript NPM/Yarn, Java JAR/EAR/WAR, Jenkins plugins JPI/HPI, Go modules), it should work on most container images.

So how do you use syft? Let me show you. I’ll be demonstrating on Ubuntu Server 20.04, but the tool can be used on any platform that supports Docker.
Installing Syft

The first thing to do is install git. For that, log into your server and issue the command:

sudo apt-get install git -y

Once git is installed, you’ll then clone the syft repository with the command:

git clone https://github.com/anchore/syft.git

You should now see a new directory, name syft. Change into that directory with:

cd syft

Create the executable binary with the command:

./install.sh

Next, you need to move the syft binary to a directory in your $PATH. Do this with the command:

sudo cp bin/syft /usr/local/bin

Make sure the installation is complete by issuing the command:

syft -h

You should see the help information listed.
How to Generate an SBOM with syft

Now the fun begins. Let’s say you want to build a cloud native application based on the official AlmaLinux image. Do that you’ll use syft to not only generate the SBOM but to pull down the image (although you can generate an SBOM with an image that has already been pulled). Let’s run syft against AlmaLinux with the command:

syft almalinux

Once syft pulls down the image, it will load it and extract the contents. With the contents extracted, syft will list out every package and dependency found in the image (Figure 1).

 
Figure 1: Syft has reported the SBOM for the AlmaLinux image.

Figure 1: Syft has reported the SBOM for the AlmaLinux image.

That’s all fine and dandy, but what do you do when you need to send that list to someone on your team? Easy. Since this is Linux, you can send the output of the command to a file like so:

syft almalinux > almalinux_sbom

The output of the command will be sent to the file almalinux_sbom, which you can now print out or email to someone else. Want to count the number of packages in the container? Issue the command:

less almalinux_sbom | wc --lines

You should see around 162 packages installed.

And that, my friends, is all there is to generating a Software Bill of Materials for a container image. This might not be the most impressive trick you’ll pull out of your developer toolbox, but it’s one you might find you’ll be required to do in the near future. Once you have that SBOM in hand, you can check every single package for vulnerabilities to make sure you’re building with a solid and secure foundation.
