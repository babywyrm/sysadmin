rpm-spec-reference.sh
# do not rely on specific architecture
BuildArch: noarch

# suppress automatic detection of requirements
AutoReqProv: no
rpmbuild-reference.sh
### INSTALLATION ###

# install
rpm -i ${packagename}.rpm

# install with progress
rpm -ivh ${packagename}.rpm

# install in full-on debug mode
rpm -ivvvh ${packagename}.rpm

# install without running scripts
rpm -i ${packagename}.rpm --noscripts

# install even if this version is already installed
rpm -i ${packagename}.rpm --force

### UNINSTALLATION ###

# uninstall
rpm -e ${packagename}

# uninstall without running scripts
rpm -e ${packagename} --noscripts


# what package provides this file?
rpm -qf `which gem`
# rubygems-1.3.7-1.el6.noarch

# what packages depend on this package?
rpm -q --whatrequires rubygems

# rubygem-bundler-1.0.21-0.noarch

# uninstall even if there are dependencies
rpm -e ${packagename} --nodeps

# uninstall all rpms containing "foo" in name
rpm -e `rpm -qa | grep foo`

### UPGRADE ###

# upgrade
rpm -U ${packagename}.rpm

# install without running scripts
rpm -U ${packagename}.rpm --noscripts

# update even if this version is already installed
rpm -U ${packagename}.rpm --force

### ANALYSIS OF UNINSTALLED RPM FILES ###

# print properties
rpm -qipv ${packagename}.rpm

# print filelist
rpm -qlpv ${packagename}.rpm

# print required dependencies
rpm -qpR ${packagename}.rpm

### ANALYSIS OF INSTALLED RPM FILES

# list all installed rpms containing "foo" in name
rpm -qa | grep foo

# print installed files of installed package
rpm -ql ${packagename}
