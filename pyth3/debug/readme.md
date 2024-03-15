# How to debug Python applications

##
#
https://gist.github.com/barseghyanartur/2387fcd3530a8f48049bcb4eb03a9aba
#
##

[![rp-L4mz-N2-ZJ0-Pnopju2da-1-kguub.jpg](https://i.postimg.cc/rp4SskQv/rp-L4mz-N2-ZJ0-Pnopju2da-1-kguub.jpg)](https://postimg.cc/XZVZ1TM8)

## Introduction

In software development, testing is an essential part of ensuring that code works as intended. One critical aspect of testing is debugging, which involves finding and fixing errors or bugs in a program. In this article, we'll explore how to debug Python applications and highlight some of the most commonly used methods for debugging Python code.

## Debugging options

When it comes to debugging Python, there are multiple options available, and you should consider which one suits your needs best. Two popular options are IDE debugging tools and package debugging tools.

### IDE Debugging Tools

IDEs like PyCharm and VSCode offer debugging tools that allow you to set breakpoints in your code and run it in debug mode. This allows you to step through your code line by line, inspect variables, and evaluate expressions. Here are some resources for learning how to use the debugging tools in PyCharm and VSCode:

- [Debugging Python in PyCharm](https://www.jetbrains.com/help/pycharm/debugging-your-first-python-application.html)
- [Debugging Python in VSCode](https://code.visualstudio.com/docs/python/debugging)

### Package Debugging Tools

Links:

- [pdb](https://docs.python.org/3/library/pdb.html)
- [ipdb](https://pypi.org/project/ipdb/)
- [IPython](https://ipython.readthedocs.io/en/stable/interactive/tutorial.html)

Python also offers built-in debugging tools, such as the `pdb` module, which allow you to set breakpoints and step through your code in a console-based debugger. Additionally, there are alternative packages like `ipdb`, which is based on the `IPython` tool and provides a more powerful debugger. Here is an example of how to use the `pdb` module in your code:

**my_module.py**

```python
def something(val: str) -> int:
    val += " world"
    import pdb; pdb.set_trace()  # set a breakpoint
    # If you want a more powerful debugger, use `ipdb`.
    # Note, that this requires installation of `ipdb`
    #     $ pip install ipdb
    # Then, comment out the `mport pdb; ...` and 
    # uncomment the following line:
    # import ipdb; ipdb.set_trace()

my_str = "Hello"

print(something(my_str))
```

In the example code above, we set a breakpoint in the `something()` function using the `pdb.set_trace()` function. When the code reaches this point, it will pause execution and drop into the debugger, allowing you to inspect variables and step through the code.

**Run it**

```sh
python my_module.py
```

**What would you see**

```sh
$ python my_module.py 
--Return--
> /home/artur.local/repos/tryouts/debug/my_module.py(3)something()->None
-> import pdb; pdb.set_trace()  # set a breakpoint
(Pdb) locals()
{'val': 'Hello world', 'pdb': <module 'pdb' from '/usr/lib64/python3.11/pdb.py'>, '__return__': None}
(Pdb) val
'Hello world'
(Pdb)
```

Study `pdb` documentation for more.

**Good to know**

It works similarly with your web views (like, FastAPI/Flask/Django).

```python

def your_view(request):
   # ...
   import pdb; pdb.set_trace()
```

## Best Practices for Debugging Python

While debugging is an essential part of the development process, there are some best practices to keep in mind to ensure that your code remains clean and maintainable.

### Don't commit your debug code!

Links:

- [precommit](https://pre-commit.com/)
- [ruff](https://github.com/charliermarsh/ruff)

One critical practice is to avoid committing your debug code to your code repository. Debug code can clutter your codebase and make it more challenging to maintain. To avoid committing debug code, use a tool like `pre-commit` and linters like `ruff` to catch and prevent it from being committed.

### Debugging in Docker

If you use Docker for development, you need to configure your `docker-compose.yml` to allow debugging. You can do this by setting the `stdin_open` and `tty` options for your service:

```yaml
version: '3'

services:
  api:
    # Other configuration
    stdin_open: true
    tty: true
```

After configuring your Docker environment, assuming that you have it running already, you can find the container ID (`CONTAINER ID`) for your service (in the example above - `api` service) using `docker ps` and attach to it with the `docker attach` (`docker attach {CONTAINER ID}`) command to start debugging. Note, that you will need to run the `docker attach` command in a separate shell/terminal tab and that's where the debug prompt will appear.

## Conclusion

Debugging Python is an essential skill for any developer, and it's crucial to understand the available options and best practices. In this article, we explored two popular options for debugging Python: IDE debugging tools and package debugging tools. We also highlighted some best practices for debugging in Python, including avoiding committing debug code and configuring Docker for debugging. With this knowledge, you'll be better equipped to debug Python applications and write clean, maintainable code.
