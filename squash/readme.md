
##
#
https://gist.github.com/smoser/a8d69727ceca99f81f4b
#
##

```
We’ve located the adversary’s location and must now secure access to their Optical Network Terminal to disable their internet connection. Fortunately,
we’ve obtained a copy of the device’s firmware, which is suspected to contain hardcoded credentials. Can you extract the password from it?

As you uzip the file you will see 3 more files


now fwu_ver contains some version details of the frimware i guess

3.0.5

and hw_ver contains some data i didnt undstood its most probably the firmware name X1

and the rootfs is a squash file

Squashfs is a compressed read-only file system for Linux. Squashfs compresses files, inodes and directories

so we can use squashfs utility here to be specific unsquashfs which will extract all the content of rootfs file

sudo unsquashfs rootfs
```


Revisions 12
Clone this repository at &lt;script src=&quot;https://gist.github.com/smoser/a8d69727ceca99f81f4b.js&quot;&gt;&lt;/script&gt;
squashfs image test
README.md
overview

This repo contains some work that has been done with the goal of combining the maas ephemeral image and the lxd image as seen on http://cloud-images.ubuntu.com. The result would be less data to download for the end user.

To accomplish this, the following work items would need to be done:

    cloud-images build to produce a squashfs image as lxd-root.squash
    maas-images code changed to re-distribute the lxd-root.squash image along side the kernel and initramfs. Alternatively, the cloud-image build process could produce these artifacts and maas-images simply mirror them also.
    maas code change to consume lxd-root.squash
    maas code change to either:
        instruct curtin to install via 'cp:///' rather than 'http:///'
        convert lxd-root.squash into .tar.gz for installation (some of this code is started as squash2tar.py below).
    cloud-initramfs-dynconf change to not assume /etc/resolvconf -> /run/network/dyn-netconf
    lxd support of squashfs as import type

Pros

    removal of the maas specific 'maas ephemeral image'
    any maas installation already has the lxd image and lxd installations have part of the maas needs (missing kernel/initramfs)
    squashfs compression means less network read over iscsi in boot, reducing a bottleneck on iscsi server.

Cons

    squashfs image cannot be quickly and easily modified/patched. This is admittedly primarily dev use only.
    lxd-squash would not contain a kernel installed, which means all installations would need dpkg installation of kernel, where currently only hwe kernels on LTS releases do.

tools / usage

This describes how to test the boot of a squashfs root image, including build of image and boot in kvm.

This file is part of a gist at https://gist.github.com/smoser/a8d69727ceca99f81f4b
setup

run prepare-images to get images downloaded.

./prepare-images wily
./prepare-images trusty vivid # to use hwe-v kernel

booting and testing

to boot an image in qemu-system-x86_64 , do:

./boot-test <image> <kernel> <initrd> 2>&1 | tee my.log

That does a boot of using external kernel and initrd and via cloud-localds seed will do a 'cp / /mnt'.

Essentially this does a boot and then a full read of the filesystem.
hacks bugs issues

    need /lib/modules in lxd image bug 1501843
    need squashfs modules in 'most' bug 1501834
    why apparmor=0 cmdline

Example sizes and such

$ ls -l root.img root.img.gz root-squash-gzip root-squash-xz
-r--r--r-- 1 ubuntu ubuntu 1.0G Sep 28 19:34 root.img
-rw-rw-r-- 1 ubuntu ubuntu 182M Sep 28 20:57 root.img.gz
-rw-r--r-- 1 ubuntu ubuntu 178M Sep 28 19:37 root-squash-gzip
-rw-r--r-- 1 ubuntu ubuntu 144M Sep 28 19:36 root-squash-xz

Do note that above the '1.0G' is just the size I made it. The filesystem shows approximately 590M taken on a wily image. the root.img.gz is a simple gzip of that image.

 $ for i in root.img root-squash-gzip root-squash-xz; do
   ../boot-test $i boot-kernel.trusty fixed-initrd > $i.log 2>&1 ; done

 $ for i in *.log; do echo $i; egrep "^(real|user|sys).*s" $i; done
 root.img.log
 real    0m53.957s
 user    0m30.956s
 sys     0m10.744s
 root-squash-gzip.log
 real    0m56.221s
 user    0m34.112s
 sys     0m11.500s
 root-squash-xz.log
 real    1m9.813s
 user    0m51.384s
 sys     0m10.612s

boot-test

```
#!/bin/bash

cleanup() {
	if [ -n "$TEMP_D" -a -d "$TEMP_D" ]; then
		rm -Rf "$TEMP_D"
		TEMP_D=""
	fi
}
error() { echo "$@" 1>&2; }
fail() { [ $# -eq 0 ] || error "$@"; exit 1; }

TEMP_D=$(mktemp -d "${TMPDIR:-/tmp}/${0##*/}.XXXXXX") || exit 1
trap cleanup EXIT

img="$1"
kernel="$2"
initrd="$3"
[ -f "$img" ] || fail "$img: not a file"
seed="${TEMP_D}/seed.img"
target="${TEMP_D}/target.img"
ud="${TEMP_D}/user-data"
md="${TEMP_D}/meta-data"

cat > "$ud" <<"EOF"
#cloud-config
password: passw0rd
chpasswd: { expire: False }
ssh_pwauth: True
power_state:
  delay: now
  mode: poweroff
  message: "=== Good bye ==="
smt:
 - &target_dev "/dev/vdc"
 - &install |
   set -e
   src="$1"
   tdev="$2"
   mp="/mnt"
   mount "$tdev" "$mp"
   #cp --one-file-system --archive "$src/" "$mp"
   rsync -aXHAS --one-file-system "$src/" "$mp"
   umount "$mp"
   echo == took $SECONDS ==
 - &write_launch_info |
   f=/usr/local/bin/launch-info
   cat > "$f" <<"ENDLAUNCH"
   #!/bin/sh
   launch_sec="LAUNCH_SECONDS"
   p=$1; shift;
   if [ -n "$1" ]; then
      launch=$(date -R --date="$1")
      launch_sec=$(date --date="$launch" +%s)
   else
      launch=$(date -R --date="@$launch_sec")
   fi
   ran="$(date -R)"
   ran_sec=$(date --date="$ran" +%s)
   read up idle < /proc/uptime
   up_sec=${up%.*} # drop milliseconds
   kboot=$(date -R --date="$ran - $up_sec seconds")
   kboot_sec=$(date --date="$kboot" +%s)
   echo "${p}uptime: $up seconds"
   echo "${p}you launched me at: $launch"
   echo "${p}it is now      : $ran"
   echo "${p}kernel booted  : $kboot"
   echo "${p}launch to kboot: $((${kboot_sec}-${launch_sec})) seconds"
   echo "${p}launch to now  : $((${ran_sec}-${launch_sec}))   seconds"
   ENDLAUNCH
   chmod 755 "$f"
bootcmd:
 - [sh, '-c', *write_launch_info]
 - "launch-info boot-command: | tee /run/launch-info.txt"
runcmd:
 - "launch-info starting: | tee /run/launch-info.txt"
 - [bash, -c, *install, doinstall, /, *target_dev]
 - "launch-info finished: | tee /run/launch-info.txt"
EOF

cat > "$md" <<EOF
instance-id: $(uuidgen || echo i-abcdefg)
EOF

truncate --size=2G "$target"
out=$(mkfs.ext2 -F "$target" 2>&1) || fail "failed mkfs: $out"

out=$(python3 -c "import yaml; yaml.load(open('$ud'))" 2>&1) ||
    fail "bad yaml in user-data"

sed -i "s,LAUNCH_SECONDS,$(date +%s)," "$ud"
cloud-localds "$seed" "$ud" "$md" || fail "failed cloud-localds"

cmd=(
   qemu-system-x86_64 
   -echr 0x05 -enable-kvm
   -m 1G 
   -nographic
   -kernel "$kernel" -initrd "$initrd"
   -append "root=/dev/vda ro console=ttyS0 overlayroot=tmpfs apparmor=0"
   -device virtio-net-pci,netdev=net00 -netdev type=user,id=net00
   -drive "if=virtio,readonly,file=$img"
   -drive "if=virtio,file=$seed"
   -drive "if=virtio,file=$target"
)

echo "${cmd[@]}"
time "${cmd[@]}"
echo "${SECONDS} seconds"
make-test-image
#!/bin/sh
##
## make-test-image: this makes some test squashfs images
## that have different properties on the files that we'd like
## to make sure are represented.
TEMP_D=""
cleanup() {
	[ -z "$TEMP_D" ] || rm -Rf "$TEMP_D"
}
error() { echo "$@" 1>&2; }
fail() { [ $# -eq 0 ] || error "$@"; exit 1; }

TEMP_D=$(mktemp -d "${TMPDIR:-/tmp}/${0##*/}.XXXXXX")
rdir="${TEMP_D}/root"
psuedo_file="${TEMP_D}/psuedo.txt"
trap cleanup EXIT

out="${1:-my.squashfs}"
start_d="$PWD"

mkdir -p "$rdir"
cd "$rdir"
mkdir -p dev/pts misc home/user1 bin tmp

echo "my xattr file" > misc/attrs
setfattr -n user.comment -v "this is a comment" misc/attrs
setfacl -m u:500:r misc/attrs

ln -s ../etc misc/link-to-dir

echo "foofile" > misc/foofile
ln -s foofile misc/foolink
ln -s deadlink-target misc/deadlink
ln -s recurse-link misc/recurse-link
ln -s /misc/foofile misc/abs-link
truncate --size 100 misc/sparse

printf "%s\n%s\n" '#!/bin/sh' 'echo hello world' > bin/hello
chmod 755 bin/hello

echo "user's my text file" > home/user1/info.txt
ln -s ../../etc home/user1/ulink-to-dir
ln -s ../../dev/sda home/user1/ulink-to-dev
ln -s ../../dev/pts/ptmx home/user1/ulink-to-char

cat > "$psuedo_file" <<EOF
dev                         m  755   0    0
dev/pts                     m  755   0    0
dev/pts/0                   c  640 500  501 136   3
dev/pts/ptmx                c  000   0    0   5   2
dev/sda                     b  660   0  100   8   0
bin                         m  777   0    0
bin/hello                   m  755   0    0
home                        m  755   0    0
home/user1                  m  755 500  500
misc                        m  755   0    0
tmp                         m 4755   0    0
misc/attrs                  m  644   0    0
misc/link-to-dir            m  777   0    0
misc/foofile                m  600   0    0
misc/foolink                m  777   0    0
misc/deadlink               m  777   0    0
misc/recurse-link           m  777   0    0
misc/abs-link               m  777   0    0
misc/sparse                 m  777   0    0
home/user1/ulink-to-dir     m  777 500  500
home/user1/ulink-to-dev     m  777 500  500
home/user1/ulink-to-char    m  777 500  500
home/user1/info.txt         m  644 500  500
EOF

comps="gzip lzo xz"
files=""
for comp in $comps; do
    outf="$TEMP_D/output.$comp"
    logf="$TEMP_D/log.$comp"
    cd "$rdir"
    mksquashfs . "$outf" \
       -pf "$psuedo_file" -xattrs -noappend -comp "$comp" > "$logf" 2>&1 ||
       { cat "$logf"; fail "failed ${out}.$comp"; }
    cd "$start_d"
    mv "$outf" "$out.$comp" &&
       mv "$logf" "$out.$comp.log" || fail "failed move $out.$comp"
    files="$files $out.$comp"
done

unsquashfs -no-progress -d "." -ll "$out.${comps%% *}" 2>/dev/null
for f in $files; do
   echo "wrote $f"
done
prepare-images
#!/bin/sh

maas_mirror="http://maas.ubuntu.com/images/ephemeral-v2/daily/"
rel=${1:-wily}
krel=${2:-$rel}
root_txz_url="http://cloud-images.ubuntu.com/daily/server/$rel/current/$rel-server-cloudimg-amd64-root.tar.xz"

booturl() {
   sstream-query "--output-format=%(item_url)s" \
      --keyring=/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg --max=1 \
      "$1" krel="${5:-$2}" release=$2 arch=$3 kflavor=generic "ftype=boot-$4"
}
error() { echo "$@" 1>&2; }
fail() { [ $# -eq 0 ] || error "$@"; exit 1; }
msg() { echo "$(date -R)" "$@"; }


bk_url=$(booturl $maas_mirror $rel amd64 kernel ${krel}) &&
   bi_url=$(booturl $maas_mirror $rel amd64 initrd ${krel}) || {
   error "failed to get urls for boot-initrd or boot-kernel."
   error "apt-get install simplestreams?"
   fail
}

root_txz=${root_txz_url##*/}
bk_file=boot-kernel
bi_file=boot-initrd
img="root.img"
img_xz="root-squash-xz"
img_gzip="root-squash-gzip"

pairs="$root_txz:$root_txz_url ${bk_file}:${bk_url} $bi_file:$bi_url"
for p in ${pairs}; do
  lfile=${p%%:*}
  url=${p#*:}
  [ -f "$lfile" ] && continue
  msg "getting $url to $lfile"
  wget "$url" -O "$lfile.tmp" && mv "$lfile.tmp" "$lfile"
done

# create images
if ! [ -f "$img" ]; then
   f="$img.tmp"
   truncate --size 1G "$f" || fail "failed truncate $f"
   out=$(mkfs.ext4 -F -L cloudimg-rootfs "$f" 2>&1) ||
      fail "failed mkfs.ext4: $out"
   msg "populating $f from $root_txz"
   time sudo mount-image-callback "$f" -- tar -C _MOUNTPOINT_ \
       -xpSf "$root_txz" --numeric-owner \
        --xattrs "--xattrs-include=*" ||
        fail "failed population of $f"
   # no /lib/modules means copymods wont work
   sudo mount-image-callback "$f" -- \
      sh -c 'cd $MOUNTPOINT && mkdir lib/modules -p'

   # some debug make things fail faster
   sudo mount-image-callback "$f" -- sh -c 'cd $MOUNTPOINT &&
       echo "datasource_list: [ NoCloud ]" > etc/cloud/cloud.cfg.d/90_dpkg.cfg'

   # backdoor it
   if which backdoor-image >/dev/null 2>&1; then
      sudo backdoor-image "$f" --password=backdoor
   fi
   mv "$f" "$img"
   chmod 444 "$img"
fi

## create the squashfs roots
for f in $img_xz $img_gzip; do
   [ -f $f ] && continue
   comp=${f##*-}
   msg "creating squashfs with compression '$comp' in $f"
   time sudo mount-image-callback --read-only "$img" -- \
      mksquashfs _MOUNTPOINT_ "$f" -xattrs -noappend -comp "${f##*-}" ||
      fail "failed mksquashfs"
   sudo chown "$(id -u):$(id -g)" "$f"
done

echo "created ${root_txz} $img $img_xz $img_gzip $bk_file $bi_file"
pysquash.diff
this is diffs against pysquashfsimage
 https://github.com/matteomattei/PySquashfsImage
as of 2015-08-30.

diff --git a/PySquashfsImage/PySquashfsImage.py b/PySquashfsImage/PySquashfsImage.py
index 51597ee..2f42b16 100755
--- a/PySquashfsImage/PySquashfsImage.py
+++ b/PySquashfsImage/PySquashfsImage.py
@@ -125,7 +125,7 @@ SQASHFS_LOOKUP_TYPE= [
 
 
 def str2byt(data):
-	if type( data ) == str:
+	if isinstance(data, str):
 		return data.encode("latin-1")
 	return data
 
@@ -146,12 +146,21 @@ class _ZlibCompressor:
 	def __init__(self):
 		self.supported = ZLIB_COMPRESSION
 		self.name="zlib"
-		
+
 	def uncompress(self, src):
 		import zlib
 		return zlib.decompress(src)
 
-_compressors = ( _Compressor(), _ZlibCompressor() )
+class _XZCompressor:
+	def __init__(self):
+		self.supported = XZ_COMPRESSION
+		self.name="xz"
+
+	def uncompress(self, src):
+		import lzma
+		return lzma.decompress(src)
+
+_compressors = ( _Compressor(), _ZlibCompressor(), _XZCompressor() )
 
 if sys.version_info[0] < 3: pyVersionTwo = True
 else: pyVersionTwo = False
@@ -401,7 +410,9 @@ class _Inode_header(_Squashfs_commons):
 		self.fragment,offset = self.autoMakeBufInteger(buff,offset,4)
 		self.offset,offset = self.autoMakeBufInteger(buff,offset,4)
 		self.xattr,offset = self.autoMakeBufInteger(buff,offset,4)
-		self.block_list[0],offset = self.autoMakeBufInteger(buff,offset,4)
+		print("block_list: %s" % self.block_list)
+		#self.block_list[0],offset = self.autoMakeBufInteger(buff,offset,4)
+		self.block_list=buff[offset:]
 		return offset
 
 	def dir_header (self,buff,offset):
@@ -480,9 +491,9 @@ class _Xattr_id(_Squashfs_commons): # 16
 		self.size = 0
 
 	def fill(self,buffer,ofs):
-		self.xattr,ofs=autoMakeBufInteger(buffer,ofs,8)
-		self.count,ofs=autoMakeBufInteger(buffer,ofs,4)
-		self.size,ofs=autoMakeBufInteger(buffer,ofs,4)
+		self.xattr,ofs=self.autoMakeBufInteger(buffer,ofs,8)
+		self.count,ofs=self.autoMakeBufInteger(buffer,ofs,4)
+		self.size,ofs=self.autoMakeBufInteger(buffer,ofs,4)
 
 class _Xattr_table(_Squashfs_commons):
 	def __init__(self):
@@ -538,6 +549,7 @@ class SquashedFile():
 		return node.children
 
 	def select(self,path):
+		raise Exception("FOO: %s class=%s" % (path, path.__class__))
 		if path == str2byt("/"):
 			path = str2byt("")
 		lpath = path.split(str2byt("/"))
@@ -597,7 +609,7 @@ class SquashFsImage(_Squashfs_commons):
 		self.inode_table = str2byt("")
 		self.id_table = []
 		self.hash_table = {}
-		self.xattrs = ""
+		self.xattrs = b""
 		self.directory_table_hash={}
 		self.created_inode = []
 		self.total_blocks = 0
@@ -632,10 +644,11 @@ class SquashFsImage(_Squashfs_commons):
 		self.comp = self.getCompressor(self.sBlk.compression)
 
 	def getCompressor(self,compression_id):
+		print("compression_id: %s %s" % (compression_id, compression_id.__class__))
 		for c in _compressors :
 			if c.supported == compression_id :
 				return c
-		raise ValueError( "Unknown compression method "+compression_id )
+		raise ValueError( "Unknown compression method %s" % compression_id )
 
 	def initialize(self,myfile):
 		self.__read_super(myfile)
@@ -782,6 +795,7 @@ class SquashFsImage(_Squashfs_commons):
 			#i.block_ptr = block_ptr + 32 #sizeof(*inode)
 			i.xattr = SQUASHFS_INVALID_XATTR
 		elif header.inode_type==SQUASHFS_LREG_TYPE: 
+			print("getting lreg_header")
 			i.block_ptr = header.lreg_header(self.inode_table,block_ptr)
 			i.data = header.file_size
 			if header.fragment == SQUASHFS_INVALID_FRAG:
@@ -860,7 +874,7 @@ class SquashFsImage(_Squashfs_commons):
 				dir_count-=1
 				dire.fill(self.directory_table , bytes )
 				bytes += 8
-				dire.name= self.directory_table[ bytes:bytes+dire.size + 1]
+				dire.name= byt2str(self.directory_table[ bytes:bytes+dire.size + 1])
 				dire.s_file = SquashedFile(dire.name, s_file)
 				s_file.children.append(dire.s_file)
 				dire.parent = mydir
@@ -898,7 +912,7 @@ class SquashFsImage(_Squashfs_commons):
 		indexes = SQUASHFS_XATTR_BLOCKS(ids)
 		index = []
 		for r in range(0,ids):
-			index.append( self.makeInt(myfile,SQUASHFS_XATTR_BLOCK_BYTES(1)) )
+			index.append( self.makeInteger(myfile,SQUASHFS_XATTR_BLOCK_BYTES(1)) )
 		bytes = SQUASHFS_XATTR_BYTES(ids)
 		xattr_ids = {}
 		for i in range(0,indexes):
@@ -919,7 +933,7 @@ class SquashFsImage(_Squashfs_commons):
 			self.hash_table[start]= (i * SQUASHFS_METADATA_SIZE)
 			block,start,byte_count = self.read_block(myfile,start)
 			for i in range(len(block),SQUASHFS_METADATA_SIZE):
-				block+='\x00'
+				block+=b'\x00'
 			self.xattrs += block	
 			i+=1
 		return ids
@@ -934,7 +948,7 @@ class SquashFsImage(_Squashfs_commons):
 			objtype     = dir_entry.type
 			parent      = dir_entry.s_file
 			mydir.cur_entry += 1
-			pathname = str2byt(parent_name + '/') + name
+			#pathname = parent_name + "/" + name
 			if objtype == SQUASHFS_DIR_TYPE :
 				self.pre_scan(parent_name, start_block, offset, parent)
 			else:
@@ -953,9 +967,9 @@ class SquashFsImage(_Squashfs_commons):
 if __name__=="__main__":
 	import sys
 	image = SquashFsImage(sys.argv[1])
-	if len(sys.argv)>1 :
+	if len(sys.argv)>2 :
 		for i in range(2,len(sys.argv)):
-			sqashed_filename = sys.argv[i]
+			sqashed_filename = sys.argv[1]
 			squashed_file = image.root.select(sqashed_filename)
 			print("--------------%-50.50s --------------" % sqashed_filename)
 			if squashed_file==None:
@@ -974,9 +988,12 @@ if __name__=="__main__":
 			nodetype = "FILE  "
 			if i.isFolder():
 				nodetype = "FOLDER"
-			print(nodetype + ' ' + i.getPath() + " inode=" + i.inode.inode_number + " (" + image.read_block_list(i.inode) + " + " + i.inode.offset + ")")
+			print(nodetype + ' ' + i.getPath() + " inode=%d" % i.inode.inode_number + " (%s" % image.read_block_list(i.inode) + " + %d" % i.inode.offset + ")")
 			
 		for i in image.root.findAll() :
+			if isinstance(i.name, bytes):
+				import ipdb; ipdb.set_trace()
+			print("i: %s [%s]" % (i.name, i.name.__class__))
 			if i.name.endswith(".ini") :
 				content = i.getContent()
 				print("==============%-50.50s (%8d)==============" % (i.getPath(), len(content)))
@@ -986,7 +1003,7 @@ if __name__=="__main__":
 				print("++++++++++++++%-50.50s (%8d)++++++++++++++" % (i.getPath(), len(content)))
 				oname = i.name+"_saved_"+str(i.inode.inode_number)
 				print("written %s from %s %d" % (oname, i.name, len(content)))
-				of = file( oname , "wb" )
+				of = open( oname , "wb" )
 				of.write( content )
 				of.close()
 		image.close()
squash2tar.py
#!/usr/bin/python3
##
## Start of a "squashfs to tar" program
## the goal woudl be that it could write to stdout
## and not have to extract the squashfs filesystem
## as you'd have to do with unsquashfs and tar

from PySquashfsImage.PySquashfsImage import SquashFsImage
from PySquashfsImage import PySquashfsImage
import tarfile
import sys

img_f = sys.argv[1]
tar_out = sys.argv[2]

image = SquashFsImage(img_f)
#for i in image.root.findAllPaths():
#    print(i)

#		self.image = owner_image
#		self.blocks = 0
#		self.block_ptr = 0
#		self.data = 0  
#		self.fragment = 0
#		self.frag_bytes = 0
#		self.gid=0
#		self.inode_number = 0
#		self.mode = 0
#		self.offset = 0
#		self.start = 0
#		self.symlink = 0
#		self.time = 0
#		self.type = 0
#		self.uid = 0
#		self.sparse = 0
#		self.xattr = 0

def get_tarinfo(squash_file):
    t = tarfile.TarInfo()
    t.name = squash_file.getPath()
    inode = squash_file.inode

    ftypem = {
        PySquashfsImage.SQUASHFS_DIR_TYPE      : tarfile.DIRTYPE,
        PySquashfsImage.SQUASHFS_FILE_TYPE     : tarfile.REGTYPE,
        PySquashfsImage.SQUASHFS_SYMLINK_TYPE  : tarfile.SYMTYPE,
        PySquashfsImage.SQUASHFS_BLKDEV_TYPE   : tarfile.BLKTYPE,
        PySquashfsImage.SQUASHFS_CHRDEV_TYPE   : tarfile.CHRTYPE,
        PySquashfsImage.SQUASHFS_FIFO_TYPE     : tarfile.FIFOTYPE,
        PySquashfsImage.SQUASHFS_SOCKET_TYPE   : "UNKNOWN_SOCKET_TYPE",
        PySquashfsImage.SQUASHFS_LDIR_TYPE     : tarfile.LNKTYPE,
        PySquashfsImage.SQUASHFS_LREG_TYPE     : tarfile.SYMTYPE,
        PySquashfsImage.SQUASHFS_LSYMLINK_TYPE : tarfile.SYMTYPE,
        PySquashfsImage.SQUASHFS_LBLKDEV_TYPE  : tarfile.SYMTYPE,
        PySquashfsImage.SQUASHFS_LCHRDEV_TYPE  : tarfile.SYMTYPE,
        PySquashfsImage.SQUASHFS_LFIFO_TYPE    : tarfile.SYMTYPE,
        PySquashfsImage.SQUASHFS_LSOCKET_TYPE  : "UNKNOWN_LSOCKET_TYPE",
    }
    #if not hasattr(squash_file, 'size'):
    #    import ipdb; ipdb.set_trace()
    t.size = inode.data
    t.mtime = inode.time
    if squash_file.isFolder():
        t.type = tarfile.DIRTYPE
    else:
        t.type = ftypem[inode.type]
    if inode.symlink:
        raise Exception("%s -> %s" % (t.name, inode.symlink))
        print("%s -> %s" % (t.name, inode.symlink))
    #t.type = UNKNOWN
    #t.linkname = UNKNOWN
    t.uid = inode.uid
    t.gid = inode.gid
    #t.uname = UNKNOWN
    #t.gname = UNKNOWN
    #t.pax_headers = UNKNOWN
    return t
    
    

#tarfile.open(tar_out, mode='w', 
for i in image.root.findAll():
    print(i.getPath())
    tinfo = get_tarinfo(i)

#print("-------- now findAll --------")
#for i in image.root.findAll():
#    print(i.getName())
#image.close()


##
##
##

