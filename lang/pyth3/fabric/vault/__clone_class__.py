#####
##### https://gist.github.com/Jummit/f1ef6b0a9ec037b0cc4a0a7ea8d799cc
#####

#!/bin/env python3
import os
import subprocess

def replace_in_file(path, replacements):
    with open(path, "r") as original:
        content = original.read()
        for to_replace in replacements:
            content = content.replace(to_replace, replacements[to_replace])
        with open(path, "w") as modified:
            modified.write(content)

settings = {
    "name": "Mod Name",
    "id": "Mod Id",
    "description": "Mod Description",
    "author": "Author",
    "license": "License",
    "website": "Website",
    "package": "Java Package",
}

def get_default_id(info):
    return info["name"].replace(" ", "").lower()

def get_default_package(info):
    return "com." + info["author"].lower() + "." + info["id"]

def get_default_license(info):
    return "CC0-1.0"

defaults = {
    "id": get_default_id,
    "package": get_default_package,
    "license": get_default_license,
}

# Get mod info from the user.
info = {}
print("Enter mod info, ^C to quit.")
for setting in settings:
    description = settings[setting]
    default = ""
    if setting in defaults:
        default = defaults[setting](info)
        description += f" ({default})"
    info[setting] = input(description + ": ") or default

package_path = "src/main/java/" + info["package"].replace(".", "/")
main_class = info["name"].replace(" ", "")
project_folder = info["name"].replace(" ", "_").lower()

# Clone the example mod repo.
subprocess.run(["git", "clone", "git@github.com:FabricMC/fabric-example-mod.git",
        project_folder])
os.chdir(project_folder)

# Replace strings inside example files.
for classfile in ["src/main/java/net/fabricmc/example/ExampleMod.java",
        "src/main/java/net/fabricmc/example/mixin/ExampleMixin.java"]:
    replace_in_file(classfile, {
            "net.fabricmc.example": info["package"],
            "ExampleMod": main_class,})

replace_in_file("src/main/resources/fabric.mod.json", {
    "modid": info["id"],
    "Example Mod": info["name"],
    "Me!": info["author"],
    "This is an example description! Tell everyone what your mod is about!":
            info["description"],
    "https://fabricmc.net/": info["website"],
    "CC0-1.0": info["license"],
    "net.fabricmc.example.ExampleMod": info["package"] + "." + main_class,
    '"suggests": {\n            "another-mod": "*"\n        }': "",
    ',\n    "sources": "https://github.com/FabricMC/fabric-example-mod"': "",
})

replace_in_file("src/main/resources/modid.mixins.json", {
    "net.fabricmc.example.mixin": info["package"] + ".mixin"})
replace_in_file("gradle.properties", {
    "com.example": info["package"][0:info["package"].rfind(".")],
    "fabric-example-mod": info["name"].replace(" ", "-").lower()})

# Rename folders and files.
os.rename("src/main/resources/assets/modid",
        "src/main/resources/assets/" + info["id"])
os.rename("src/main/resources/modid.mixins.json",
        f"src/main/resources/{info['id']}.mixins.json")
os.rename("src/main/java/net/fabricmc/example/ExampleMod.java",
        f"src/main/java/net/fabricmc/example/{main_class}.java")
os.makedirs(package_path)
os.replace("src/main/java/net/fabricmc/example", package_path)
os.rmdir("src/main/java/net/fabricmc")
os.rmdir("src/main/java/net")
