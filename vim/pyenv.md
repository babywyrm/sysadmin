
##
#
https://gist.github.com/RichardBronosky/7ccaf9bd614e0fe101859b73252f194d
#
##

A homebrew formula to build vim with support for pyenv version of python
Build

    Patch /usr/local/Homebrew/Library/Taps/homebrew/homebrew-core/Formula/vim.rb
    Build

    brew reinstall --verbose --debug --build-from-source vim

    Locate your dynamic library with find /Users/bronoric/.pyenv/ -name '*libpython3*.dylib'
        It's probably going to contain darwin in the path.
        So, you'll likely be able to use find /Users/bronoric/.pyenv/ -name '*libpython3*.dylib' -path '*darwin*'
        In my case it was /Users/bruno/.pyenv//versions/3.8.6/Python.framework/Versions/3.8/lib/python3.8/config-3.8-darwin/libpython3.8.dylib
            Note: I have ~/.pyenv symlinked to a local git clone of https://github.com/pyenv/pyenv
            Therefore, I have to put a / at the end of the path arg to the find command or else it doesn't follow the symlink.
    In vim before you can use python[3], you must run the [ex (aka :)] command set pythonthreedll=/Users/bronoric/.pyenv//versions/3.8.6/Python.framework/Versions/3.8/lib/python3.8/config-3.8-darwin/libpython3.8.dylib
        I hope to find a build-time solution to this.
        For now, you can add it to your ~/.vim/vimrc by wrapping it in a if !has('nvim') … endif clause if you need it for a plugin that requires Python (like deoplete)
            See: https://vi.stackexchange.com/a/9827/10672
    Recreate symlink if needed

    cd /usr/local/share
    ln -s $(find ../Cellar/vim -name vim -path "*share*" | sort | tail -n1) .

patch.diff
diff --git a/Formula/vim.rb b/Formula/vim.rb
index 9431fecb1e..e7f7cad82d 100644
--- a/Formula/vim.rb
+++ b/Formula/vim.rb
@@ -17,7 +17,6 @@ class Vim < Formula
   depends_on "gettext"
   depends_on "lua"
   depends_on "perl"
-  depends_on "python@3.9"
   depends_on "ruby"
 
   uses_from_macos "ncurses"
@@ -28,17 +27,30 @@ class Vim < Formula
   conflicts_with "macvim",
     because: "vim and macvim both install vi* binaries"
 
+  def python_config_dir
+    `$(pyenv which python2-config) --prefix`.chomp+"/lib/python2.7/config"
+  end
+
+  def python3_config_dir
+    `$(pyenv which python3-config) --configdir`.chomp
+  end
+
+  def add_pyenv_to_path
+    user_home = `echo $(echo ~#{ENV["USER"]})`.chomp
+    dirs = [ "#{user_home}/.pyenv/shims", "#{user_home}/.pyenv/bin" ]
+    dirs.each do |dir|
+      ENV.prepend_path "PATH", dir
+    end
+  end
+
   def install
     # Fix error: '__declspec' attributes are not enabled
     ENV.append_to_cflags "-fdeclspec"
 
-    ENV.prepend_path "PATH", Formula["python@3.9"].opt_libexec/"bin"
-
     # https://github.com/Homebrew/homebrew-core/pull/1046
     ENV.delete("SDKROOT")
 
-    # vim doesn't require any Python package, unset PYTHONPATH.
-    ENV.delete("PYTHONPATH")
+    add_pyenv_to_path
 
     # We specify HOMEBREW_PREFIX as the prefix to make vim look in the
     # the right place (HOMEBREW_PREFIX/share/vim/{vimrc,vimfiles}) for
@@ -55,7 +67,12 @@ class Vim < Formula
                           "--enable-terminal",
                           "--enable-perlinterp",
                           "--enable-rubyinterp",
-                          "--enable-python3interp",
+                          #"--enable-pythoninterp=dynamic",
+                          #"--with-python-command=python2",
+                          #"--with-python-config-dir="+python_config_dir,
+                          "--enable-python3interp=dynamic",
+                          "--with-python3-command=python3",
+                          "--with-python3-config-dir="+python3_config_dir,
                           "--enable-gui=no",
                           "--without-x",
                           "--enable-luainterp",
vim-orig.rb
class Vim < Formula
  desc "Vi 'workalike' with many additional features"
  homepage "https://www.vim.org/"
  # vim should only be updated every 50 releases on multiples of 50
  url "https://github.com/vim/vim/archive/v8.2.2250.tar.gz"
  sha256 "be1de89b4e41d17a4f27bb70210e9e7d334b80a8f488659617d0742e0cd1bbbd"
  license "Vim"
  head "https://github.com/vim/vim.git"

  bottle do
    sha256 "322b126a67ba779a89999b4df91a17ac94e4967e0dad9922866f2f8db8a44256" => :big_sur
    sha256 "a8b7584db1d8a3e77ef9b5a2a7f58754911f847ebd4e688ea387ab0be4234b19" => :arm64_big_sur
    sha256 "6a46c763b64b947a91f16dcffa842616ab54d1eef920fffd9a0fbf9218adf340" => :catalina
    sha256 "643f2072aec4943b4a49bb94354264bc6800b9db313b16b1ac86ed06bf252ba4" => :mojave
  end

  depends_on "gettext"
  depends_on "lua"
  depends_on "perl"
  depends_on "python@3.9"
  depends_on "ruby"

  uses_from_macos "ncurses"

  conflicts_with "ex-vi",
    because: "vim and ex-vi both install bin/ex and bin/view"

  conflicts_with "macvim",
    because: "vim and macvim both install vi* binaries"

  def install
    # Fix error: '__declspec' attributes are not enabled
    ENV.append_to_cflags "-fdeclspec"

    ENV.prepend_path "PATH", Formula["python@3.9"].opt_libexec/"bin"

    # https://github.com/Homebrew/homebrew-core/pull/1046
    ENV.delete("SDKROOT")

    # vim doesn't require any Python package, unset PYTHONPATH.
    ENV.delete("PYTHONPATH")

    # We specify HOMEBREW_PREFIX as the prefix to make vim look in the
    # the right place (HOMEBREW_PREFIX/share/vim/{vimrc,vimfiles}) for
    # system vimscript files. We specify the normal installation prefix
    # when calling "make install".
    # Homebrew will use the first suitable Perl & Ruby in your PATH if you
    # build from source. Please don't attempt to hardcode either.
    system "./configure", "--prefix=#{HOMEBREW_PREFIX}",
                          "--mandir=#{man}",
                          "--enable-multibyte",
                          "--with-tlib=ncurses",
                          "--with-compiledby=Homebrew",
                          "--enable-cscope",
                          "--enable-terminal",
                          "--enable-perlinterp",
                          "--enable-rubyinterp",
                          "--enable-python3interp",
                          "--enable-gui=no",
                          "--without-x",
                          "--enable-luainterp",
                          "--with-lua-prefix=#{Formula["lua"].opt_prefix}"
    system "make"
    # Parallel install could miss some symlinks
    # https://github.com/vim/vim/issues/1031
    ENV.deparallelize
    # If stripping the binaries is enabled, vim will segfault with
    # statically-linked interpreters like ruby
    # https://github.com/vim/vim/issues/114
    system "make", "install", "prefix=#{prefix}", "STRIP=#{which "true"}"
    bin.install_symlink "vim" => "vi"
  end

  test do
    (testpath/"commands.vim").write <<~EOS
      :python3 import vim; vim.current.buffer[0] = 'hello python3'
      :wq
    EOS
    system bin/"vim", "-T", "dumb", "-s", "commands.vim", "test.txt"
    assert_equal "hello python3", File.read("test.txt").chomp
    assert_match "+gettext", shell_output("#{bin}/vim --version")
  end
end
vim.rb
class Vim < Formula
  desc "Vi 'workalike' with many additional features"
  homepage "https://www.vim.org/"
  # vim should only be updated every 50 releases on multiples of 50
  url "https://github.com/vim/vim/archive/v8.2.2250.tar.gz"
  sha256 "be1de89b4e41d17a4f27bb70210e9e7d334b80a8f488659617d0742e0cd1bbbd"
  license "Vim"
  head "https://github.com/vim/vim.git"

  bottle do
    sha256 "322b126a67ba779a89999b4df91a17ac94e4967e0dad9922866f2f8db8a44256" => :big_sur
    sha256 "a8b7584db1d8a3e77ef9b5a2a7f58754911f847ebd4e688ea387ab0be4234b19" => :arm64_big_sur
    sha256 "6a46c763b64b947a91f16dcffa842616ab54d1eef920fffd9a0fbf9218adf340" => :catalina
    sha256 "643f2072aec4943b4a49bb94354264bc6800b9db313b16b1ac86ed06bf252ba4" => :mojave
  end

  depends_on "gettext"
  depends_on "lua"
  depends_on "perl"
  depends_on "ruby"

  uses_from_macos "ncurses"

  conflicts_with "ex-vi",
    because: "vim and ex-vi both install bin/ex and bin/view"

  conflicts_with "macvim",
    because: "vim and macvim both install vi* binaries"

  def python_config_dir
    `$(pyenv which python2-config) --prefix`.chomp+"/lib/python2.7/config"
  end

  def python3_config_dir
    `$(pyenv which python3-config) --configdir`.chomp
  end

  def add_pyenv_to_path
    user_home = `echo $(echo ~#{ENV["USER"]})`.chomp
    dirs = [ "#{user_home}/.pyenv/shims", "#{user_home}/.pyenv/bin" ]
    dirs.each do |dir|
      ENV.prepend_path "PATH", dir
    end
  end

  def install
    # Fix error: '__declspec' attributes are not enabled
    ENV.append_to_cflags "-fdeclspec"

    # https://github.com/Homebrew/homebrew-core/pull/1046
    ENV.delete("SDKROOT")

    add_pyenv_to_path

    # We specify HOMEBREW_PREFIX as the prefix to make vim look in the
    # the right place (HOMEBREW_PREFIX/share/vim/{vimrc,vimfiles}) for
    # system vimscript files. We specify the normal installation prefix
    # when calling "make install".
    # Homebrew will use the first suitable Perl & Ruby in your PATH if you
    # build from source. Please don't attempt to hardcode either.
    system "./configure", "--prefix=#{HOMEBREW_PREFIX}",
                          "--mandir=#{man}",
                          "--enable-multibyte",
                          "--with-tlib=ncurses",
                          "--with-compiledby=Homebrew",
                          "--enable-cscope",
                          "--enable-terminal",
                          "--enable-perlinterp",
                          "--enable-rubyinterp",
                          #"--enable-pythoninterp=dynamic",
                          #"--with-python-command=python2",
                          #"--with-python-config-dir="+python_config_dir,
                          "--enable-python3interp=dynamic",
                          "--with-python3-command=python3",
                          "--with-python3-config-dir="+python3_config_dir,
                          "--enable-gui=no",
                          "--without-x",
                          "--enable-luainterp",
                          "--with-lua-prefix=#{Formula["lua"].opt_prefix}"
    system "make"
    # Parallel install could miss some symlinks
    # https://github.com/vim/vim/issues/1031
    ENV.deparallelize
    # If stripping the binaries is enabled, vim will segfault with
    # statically-linked interpreters like ruby
    # https://github.com/vim/vim/issues/114
    system "make", "install", "prefix=#{prefix}", "STRIP=#{which "true"}"
    bin.install_symlink "vim" => "vi"
  end

  test do
    (testpath/"commands.vim").write <<~EOS
      :python3 import vim; vim.current.buffer[0] = 'hello python3'
      :wq
    EOS
    system bin/"vim", "-T", "dumb", "-s", "commands.vim", "test.txt"
    assert_equal "hello python3", File.read("test.txt").chomp
    assert_match "+gettext", shell_output("#{bin}/vim --version")
  end
end
