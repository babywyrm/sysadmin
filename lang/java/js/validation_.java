/*******************************************************************************
**********  BASIC VALIDATOR ALGEBRA FOR THE JAVA PROGRAMMING LANGUAGE **********
**                                                                            **
** Author: Justin Dekeyser                                                    **
**                                                                            **
** Do not copy. Hire me instead, thank you in advance.                        **
** (with a juicy salary package, home working and days off).                  **
**                                                                            **
*******************************************************************************/

import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Consumer;
import java.util.List;
import java.util.Objects;

import static java.util.Arrays.stream;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.function.Predicate.not;
import static java.util.Optional.of;

public class Validation {


/*******************************************************************************
**********************  VALIDATION ALGEBRA IMPLEMENTATION  *********************
*******************************************************************************/

  @FunctionalInterface
  interface Validator <Input, Failure> {
    List<Failure> validationErrors (Input arg);
  }

  @SuppressWarnings("unchecked")
  static <Input, Failure> Validator<Input, Failure> tree (
    Validator<? super Input, Failure> guard,
    Validator<? super Input, Failure>... children
  ) {
    return x -> of(guard.validationErrors(x))
                .filter(not(List::isEmpty))
                .orElseGet(() -> chain(children).validationErrors(x));
  }

  @SuppressWarnings("unchecked")
  static <ProjectedInput, Input, Failure> Validator<Input, Failure> zoom (
    Function<Input, ProjectedInput> mapper,
    Validator<? super ProjectedInput, Failure>... validators
  ) {
    return mapper.andThen(chain(validators)::validationErrors)::apply;
  }

  static <Input, Failure> Validator<Input, Failure> test(
    Failure error,
    Predicate<? super Input> p
  ) {
     return x -> p.test(x) ? emptyList(): singletonList(error);
  }

  @SuppressWarnings("unchecked")
  static <Input, Failure> Validator<Input, Failure> chain (
    Validator<? super Input, Failure>... validators
  ) {
    return x -> stream(validators)
                .map($ -> $.validationErrors(x))
                .<Failure> mapMulti(List::forEach)
                .toList();
  }


/*******************************************************************************
*************  EXAMPLE CODE - ADDRESS EMAIL SCHEME BASIC VALIDATOR *************
*******************************************************************************/

  @SuppressWarnings("unchecked")
  static Validator<String,String> emailAddressValidator() {
    return tree(
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
  }
  public static void main(String... args) {
    var validator = emailAddressValidator();

    for (var word : new String[]{
      null,
      "hello",
      "ju@",
      "@jude",
      "@",
      "ju@de@keyser",
      "jude+123@keyser",
      "jude@keyser"
    })
      System.out.printf("Validating <%s> against validator yielded %s\n",
                        word, java.util.Arrays.toString(
                              validator.validationErrors(word).toArray()
                              )
                        );

   }
}
