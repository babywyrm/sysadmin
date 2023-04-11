
In Puppet, YAML files are often used as data sources for Hiera, a tool for managing and separating configuration data from Puppet code.

Here's how it works:
```

Hiera is configured to look for data in specific YAML files. For example, you might configure Hiera to look for data in a file called common.yaml or webserver.yaml.

In your Puppet code, you can use Hiera to look up values from those YAML files. For example, you might use the lookup() function to get the value of a variable defined in a YAML file.

When Puppet runs, it checks the YAML files specified by Hiera and pulls in any data that matches the lookup key.

Puppet then uses that data in your code. For example, you might use the data to set the value of a variable or parameter.
```

So, to answer your question, 
a YAML file Puppet module works with Hiera by providing configuration data in the form of YAML files that can be looked up by Hiera and used in Puppet code. 
This allows for easy separation of configuration data from code, making it easier to manage and update your infrastructure.
