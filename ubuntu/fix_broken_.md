# Fixing a broken package on Ubuntu

Things to try to fix a broken package in Ubuntu Linux.

```sh
sudo apt-get install -f
```

Search for the package name and existence, narrow the proper name down.

```sh
sudo apt-cache search <pkg-name>
```

Remove the old troubling package.

```sh
sudo apt-get autoremove <pkg-name>
sudo apt-get purge <pkg-name>
```

Start a fresh re-install.

```sh
sudo apt-get install <pkg-name>
```

Fix any existing package installation problems.

```sh
sudo apt-get update
sudo apt-get install -f
```

Last resort try again.

```sh
sudo apt-get purge <pkg-name> && sudo apt-get install <pkg-name>
sudo apt-get install --reinstall <pkg-name>
sudo dpkg-reconfigure <pkg-name>
```
