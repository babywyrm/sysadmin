# Validation

We are here interested in handling and reporting errors coming from the user or more generally, data integrity.
This is what we call here *validation*.

The use case is typically to collect as many errors as we could from a given source, in order to expose a report as detailed as possible. Throwing-centric patterns are therefore hard to adapt.

## Illustrative example
This example illustrates a validator and the result of validation, on different email addresses.
The typing and factory methods are explained below.

![validator](https://user-images.githubusercontent.com/44140459/140640811-b171c975-5b27-4881-889d-a1fe2e4b47fb.png)

The email address validator:
```java
final Validator<String, String> validator
    = tree(
        test("Input cannot be null", Objects::nonNull),
          tree(
          chain(
            test("Input does not contain one @ symbol",
                 $ -> $.indexOf('@') > -1),
            test("Input contains too many @ symbols",
                 $ -> $.indexOf('@') == $.lastIndexOf('@'))
          ),
          zoom(
            $ -> $.substring(0, $.indexOf('@')),
            test("Local cannot be blank", 
                 not(String::isBlank)),
            tree(
              zoom(String::length,
                test("Local Length must be 3 chars long at least",
                     i -> i >= 3))
              ),
              test("Local cannot contain a '+' segment",
                   $ -> $.indexOf('+') == -1)
            )
          ),
          zoom(
            $ -> $.substring($.indexOf('@')+1),
            test("Domain cannot be blank", not(String::isBlank)
          )
        )
      );
```
We think examples are better than a long explanations. Details of what the function does are done below.
```
Validating <null> against validator yielded [Input cannot be null]
Validating <hello> against validator yielded [Input does not contain one @ symbol]
Validating <ju@> against validator yielded [Local Length must be 3 chars long at least, Domain cannot be blank]
Validating <@jude> against validator yielded [Local cannot be blank, Local Length must be 3 chars long at least]
Validating <@> against validator yielded [Local cannot be blank, Local Length must be 3 chars long at least, Domain cannot be blank]
Validating <ju@de@keyser> against validator yielded [Input contains too many @ symbols]
Validating <jude+123@keyser> against validator yielded [Local cannot contain a '+' segment]
Validating <jude@keyser> against validator yielded []
```

# Type system

## `Validator` functional type

By *validating a data*, we except to get a list of problems (validation errors) and eventually report them somewhere.
The basic type we suggest is therefore
```
Validator =:= Input -> List<Failure>
```

## Validator encodings

An important question is about how to encode a Validator, as defined previously.
We tackle this question here, from the easier to the more complex structure.

### As a data `Predicate`

A first way to encode a `Validator` could be by pattern-matching on a simple `Predicate`:
```
Validator ~ Failure & Predicate
```
where the morphism is performed by the formula
```
Input -> if Predicate(Input) then emptyList otherwise singletonList(Failure)
```

### As a chain of Validators

Another way to encode a Validator is to combine many of them sequentially, and collect the errors while validating the data:
```
Validator ~ Validator-s
```
where the morphism is performed by the formula
```
Input -> sum of all Validator-s(Input)
```

### As a (chain of) Validator guarded by another one

A third way we propose to encode a Validator is to have a guardian Validator that validates and if the test passes,
delegates on another one (or many of them):
```
Validator ~ Validator(guardian) & Validator-s
```
where the morphism is performed by the formula
```
Input -> guardian(Input) if non empty otherwise Validator-s(Input)
```

# Java approach
(Imports are omitted)

## Validator functional type

```java
@FunctionalInterface
interface Validator <Input, Failure> {
   List<Failure> validationErrors (Input arg);
}
```

## Validator encodings

### As a data `Predicate`

```java
static <Input, Failure> Validator<Input, Failure> test(Failure error, Predicate<Input> p) {
   return x -> p.test(x) ? emptyList(): singletonList(error);
}
```

### As a chain of Validators

```java
static <Input, Failure> Validator<Input, Failure> chain (Validator<Input, Failure>... validators) {
  return x -> stream(validators)
              .map($ -> $.validationErrors(x))
              .<Failure> mapMulti(List::forEach)
              .toList();
}
```

### As a (chain of) Validator guarded by another one

```java
static <Input, Failure> Validator<Input, Failure> tree (
  Validator<Input, Failure> guard,
  Validator<Input, Failure>... children
) {
  return x -> of(guard.validationErrors(x))
              .filter(not(List::isEmpty))
              .orElseGet(() -> chain(children).validationErrors(x));
}
``` 

## Convenient `zoom` method

In order to validate a projection of the input onto a part of the information
(examples: mapping on another type, enriching by fetching informations from the database, performing an operation like substring, ...),
we provide a special `zoom` method that first projects the Input before applying a validator on the projection.

```java
static <ProjectedInput, Input, Failure> Validator<Input, Failure> zoom (
  Function<Input, ProjectedInput> mapper,
  Validator<ProjectedInput, Failure>... validators
) {
  return mapper.andThen(chain(validators)::validationErrors)::apply;
}
```

# Take-Aways

Aside from the result, few take-aways could be given:
- **Write for the functionnality first**: how are we going to use our abstraction? Can the functionnality hold in one method (= functional interface)? *This answer dictates the type*.
- **Define encodings for the functionnality**: use type-theory to design encoding schemes and morphisms to encode the functionnality. *Every encoding is reflected by a factory method*. You do not need classes everytime! 
- **Do not think data, think algebra**: forget about how data are stored, think about how functions and types combine. *This is typed functional programming*.
- **Forget about purity, think Objects**: allow stateful validators to be created on demand. *Objects are meant to have a state*: use it wisely! Enrich the validation functionnality with relevant state (connections to databases, builder binding, event emission, ...).
