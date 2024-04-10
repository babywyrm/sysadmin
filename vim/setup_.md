
##
#
https://github.com/cjadeveloper/pyenv-pipenv-vim-config
#
https://sts10.github.io/docs/initial-setup/dev-env/python-pyenv.html
#
##

How I use Pyenv + Pipenv + Neovim for my daily projects.
Pyenv config

In our project directory, we could make

$ pyenv local 3.7.4

We check with

$ pyenv version
3.7.4 (set by /home/cjadeveloper/.../my-project/.python-version)

Pipenv
Create a new project using Python 3.7.4, specifically

If we open a terminal and write pyenv which python, it will return the full path to the current python executable

$ pyenv which python
/home/cjadeveloper/.pyenv/versions/3.7.4/bin/python

We If we could use this information

In bash or zsh to do:

$ pipenv --python $(pyenv which python)
Creating a virtualenv for this project…
Pipfile: /home/cjadeveloper/.../my-project/Pipfile
Using /home/cjadeveloper/.pyenv/versions/3.7.4/bin/python (3.7.4) to create virtualenv…
...

In fish:

> pipenv --python (pyenv which python)
Creating a virtualenv for this project…
Pipfile: /home/cjadeveloper/.../my-project/Pipfile
Using /home/cjadeveloper/.pyenv/versions/3.7.4/bin/python (3.7.4) to create virtualenv…
...

Install Neovim Python Packages and fancy interactive superpower terms

    You will need NeoVim 0.3 or newer

    Install the required dependencies:

sudo apt install git curl python3-pip exuberant-ctags ack-grep

    Inside the project directory, install dependencies with pipenv

pipenv install --dev neovim flake8 pylint isort msgpack pynvim bpython ipython

    Download the config file and save it as ~/.config/nvim/init.vim (use that exact path and name).

    Open Neovim with pipenv run nvim . and it will it continue the installation by itself. Wait for it finish and done!

    Then, when Neovim already works, we could activate the venv with pipenv shell --fancy inside our projects directory and open it with nvim .

    Note: The --fancy option is necessary in case we use fish together with some oh-my-fish theme and the prompt breaks. Just as pointed out here

Optional: Pipenvwrapper

Pipenvwrapper is a shell functions similar to virtualenvwrapper but using Pipenv as backend.

If we use Pipenvwrapper, we could write workon (or useenv depends on how we configure it) and use a specific virtualenv or list all the available ones if none is provided. With this we can activate the venv and go directly to the project folder from wherever we are.
References

    Vim Cheat Sheet
    pipenv
    pyenv
    fisa vim config
    Creating a new file or directory in Vim using NERDTree


########
########
##
##

    # MacVim with pyenv

[Gist guide for MacVim with Python 2.x and Python 3.x](https://gist.github.com/splhack/4ec93591aec286beac496bbd5cc8d764)

On El Capitan worked version 7.4.1749 from 18.04.2016
```
git clone https://github.com/macvim-dev/macvim.git
```

if used rvm, need use any not system ruby interpretator 

```
brew install gpg2
rvm install 2.3
rvm use 2.3
```  

On El Capitan after install xcode, need run:
```
xcode-select --install
```
without this: ERROR: The Python zlib extension was not compiled. Missing the zlib?

pyenv interpretator must be builded with framework
```
env PYTHON_CONFIGURE_OPTS="--enable-framework CC=clang" pyenv install 2.7.11
env PYTHON_CONFIGURE_OPTS="--enable-framework CC=clang" pyenv install 3.5.1
pyenv global 2.7.11:3.5.1
```

lua from homebrew
```
brew install lua
```

```
export vi_cv_dll_name_python=/Users/svolkov/.pyenv/versions/2.7.11/Python.framework/Versions/2.7/Python
export vi_cv_dll_name_python3=/Users/svolkov/.pyenv/versions/3.5.1/Python.framework/Versions/3.5/Python
export CC=clang 
./configure --with-features=huge \
              --enable-pythoninterp=dynamic \
              --enable-python3interp=dynamic \
              --enable-rubyinterp=dynamic \
              --enable-perlinterp=dynamic \
              --enable-cscope \
              --enable-luainterp=dynamic \
              --with-lua-prefix=/usr/local
time make
```
build time ~2min  

**vi_cv_dll_name_python** - you may set in the .vimrc befor first using python (load YouCompliteMe), after loading change interpretator not available. Build not supprort both python 2 and python 3 loaded simultaniosly:
```
E837: This Vim cannot execute :py3 after using :python
E263: Sorry, this command is disabled, the Python library could not be loaded.
```
Dynamic python interpretator not linked to the bin, for static linked interpretator need change link with otool:
```
# check libs
otool -L src/MacVim/build/Release/MacVim.app/Contents/MacOS/Vim
# replace system python framework
install_name_tool -change \
/System/Library/Frameworks/Python.framework/Versions/2.7/Python \
/Users/svolkov/.pyenv/versions/2.7.10/Python.framework/Versions/2.7/Python \
src/MacVim/build/Release/MacVim.app/Contents/MacOS/Vim
```

test build
```
:python import sys; print(sys.version)
```

```
open src/MacVim/build/Release/MacVim.app
src/MacVim/build/Release/MacVim.app/Contents/MacOS/Vim --version
```

## YouCompleteMe
[YouCompleteMe](https://github.com/Valloric/YouCompleteMe)

```
brew install cmake
cd ~/.vim/bundle/YouCompleteMe
./install.py --clang-completer --gocode-completer
```

If MacVim was not compilled on this machine, in the start .vimrc need insert:
```
set pythondll=/Users/<username>/.pyenv/versions/2.7.11/Python.framework/Versions/2.7/Python
```
