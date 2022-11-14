# Javascript Prototype Pollution

## Javascript prototype specification

```
// Not only Object but also other types. (Function, Array, String, Number, ...)
Object.prototype.prop1 = 1;
Object.prototype.func1 = () => 'Hello!';                                        

const obj1 = {};
console.log(obj1.prop1); // ==> 1
console.log(obj1.func1()); // ==> Hello!
```

In addition,

```
console.log(Object.prototype === {}.__proto__); // ==> true
console.log({}.constructor == Object); // ==> true
```

## Pollution Vulnerability

### Case 1

```
const obj1 = {};
obj1.__proto__.polluted = 1;
const obj2 = {};
console.log(obj2.polluted); // ==> 1
```

### Case 2

```
const obj1 = {};
obj1.constructor.prototype.polluted = 1;
const obj2 = {};
console.log(obj2.polluted); // ==> 1
```

## Possibly Attack 1

```
// A sample library 
function setValue(obj, keyChain, value) {
  setValueRcr(obj, keyChain.split('.'), value);
  return obj;
  
  function setValueRcr(obj, keys, value) {
    const key = keys.shift();
    if (!key) return;
    if (keys.length === 0) {
      obj[key] = value;
      return;
    }
    // Not match for obj.__proto__ or obj.constructor.prototype 
    if (!obj[key] || (typeof obj[key] !== 'object' && typeof obj[key] !== 'function')) {   
      obj[key] = {};
    }
    setValueRcr(obj[key], keys, value);
  }
}
```

### Attack 1.1

```
console.log({}.polluted); // ==> undefined
setValue({}, '__proto__.polluted', 1);
console.log({}.polluted); // ==> 1
```

### Attack 1.2

```
console.log({}.polluted); // ==> undefined
setValue({}, 'constructor.prototype.polluted', 1);
console.log({}.polluted); // ==> 1
```

### Measure

```
// A sample library 
function setValue(obj, keyChain, value) {
  setValueRcr(obj, keyChain.split('.'), value);
  return obj;
  
  function setValueRcr(obj, keys, value) {
    const key = keys.shift();
    if (!key) return;
    if (key === '__proto__' || key === 'constructor') return;  // <== THIS
    if (keys.length === 0) {
      obj[key] = value;
      return;
    }
    // Moreover, it's better to stop using a function or another type property as an object property, because
    //  - `constructor` property is excluded because it is a function
    //  - It prevents to override the intrinsic properties and methods of the other type.
    //if (!obj[key] || (typeof obj[key] !== 'object' && typeof obj[key] !== 'function')) {   
    if (!obj[key] || typeof obj[key] !== 'object') {   
      obj[key] = {};
    }
    setValueRcr(obj, keys, value);
  }
}
```

## Possibly Attack 2

```
// A sample library
function deepCopy(dest, src) {
  for (var key in src) {
    if (!src[key] || typeof src[key] !== 'object') {
      dest[key] = src[key];
      continue;
    }
    if (!dest[key] || (typeof dest[key] !== 'object' && typeof dest[key] !== 'function')) {
      dest[key] = {};
    }
    deepCopy(dest[key], src[key]);
  }
  return dest;
}
```

### Attack 2.1

```
console.log({}.polluted); // ==> undefined
deepCopy({}, {'__proto__':{polluted:1}});  // This is no problem because '__proto__' is not enumerable.
console.log({}.polluted); // ==> undefined

console.log({}.polluted); // ==> undefined
deepCopy({}, JSON.parse('{"__proto__":{"polluted":1}}')); // '__proto__' of A JSON parsed object is enumerable!    
console.log({}.polluted); // ==> 1
```

*NOTE: This pollution does not appeared on Node <=0.10.*

### Attack 2.2

```
console.log({}.polluted); // ==> undefined
deepCopy({}, {constructor:{prototype:{polluted:1}}});
console.log({}.polluted); // ==> 1
```

```
console.log({}.polluted); // ==> undefined
deepCopy({}, JSON.parse('{"constructor":{"prototype":{"polluted":1}}}'));
console.log({}.polluted); // ==> 1
```

### Measure

```
// A sample library
function deepCopy(dest, src) {
  for (var key in src) {
    if (key === '__proto__' || key === 'constructor') continue;  // <== THIS
    if (!dest[key] || typeof dest[key] !== 'object') {
      dest[key] = src[key];
      continue;
    }
    // Moreover, it's better to stop using a function or another type property as an object property, because
    //  - `constructor` property is excluded because it is a function
    //  - It prevents to override the intrinsic properties and methods of the other type.
    //if (!dest[key] || (typeof dest[key] !== 'object' && typeof dest[key] !== 'function')) {
    if (!dest[key] || typeof dest[key] !== 'object') {
      dest[key] = {};
    }
    deepCopy(dest[key], src[key]);
  }
  return dest;
}
```

## Possibly Attack 3

### Attack 3.1

```
console.log({}.polluted); // ==> undefined
eval('Object.prototype.polluted = 1');
console.log({}.polluted); // ==> 1
```

### Attack 3.2

```
console.log({}.polluted); // ==> undefined
eval('const obj={};obj.__proto__.polluted = 1');
console.log({}.polluted); // ==> 1
```

### Attack 3.3

```
console.log({}.polluted); // ==> undefined
eval('const obj={};obj.constructor.prototype.polluted = 1');
console.log({}.polluted); // ==> 1
```

### Measure

Nothing.
