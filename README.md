<a href="https://www.code-intelligence.com/">
<img src="https://www.code-intelligence.com/hubfs/Logos/CI%20Logos/Logo_quer_white.png" alt="Code Intelligence logo" width="450px">
</a>

# Testing C/C++ for Security and Reliability
Building robust C/C++ applications is a highly challenging endeavor that requires thorough testing. While C/C++ enables us to write high-performance code, the memory-unsafety nature of the language brings a broad spectrum of security risks. Memory corruption issues constitute the vast majority of bugs and security vulnerabilities found in C/C++ projects, and their impact is best demonstrated by the [Heartbleed](https://en.wikipedia.org/wiki/Heartbleed) bug on OpenSSL. Regular unit and integration tests are essential to test that our code functions correctly - they are not enough to uncover memory-corruption bugs. (Whitebox and smart) Fuzz testing on the other hand, has established itself as the best practical method to find these issues in large code bases such as Google Chrome.

These examples require libssl-dev and libzstd-dev installed on Ubuntu. To install both dependencies you can run:
```sh
sudo apt install libssl-dev libzstd-dev -y
```
If you do not want to install both packages, you can also comment out the include of the simple_examples folder in the main [CMakeLists.txt](CMakeLists.txt#L23) file.

In this example, we demonstrate how you can use CI Fuzz to integrate fuzz testing into your C/C++ projects. The example project uses [CMake](https://cmake.org/) as the build system and contains the following examples:
* [Simple Checks Example](src/simple_examples/explore_me.cpp#L10):
A simple example that triggers a buffer over when the input parameters satisfy certain criteria.
We show that CI Fuzz can quickly generate a test case that trigger this bug.
Execute with:
```sh
cifuzz run simple_checks_fuzz_test
```
* [Complex Checks Example](src/simple_examples/explore_me.cpp#L22):
A more complex example that triggers a use-after-free bug when the input parameters satisfy certain criteria. In this example, the checks are more complex and involve Base64 encoding and XORing with constant value, making it more challenging to find the correct combination of input parameters that trigger the bug.
Execute with:
```sh
cifuzz run complex_checks_fuzz_test
```
* [Stateful Example](src/state_example):
An example that demonstrates the challenges of creating high-quality fuzz tests for complex projects with a large public API. This fuzz test was created with an early version of Code Intelligence auto-generation features, but it is still an excellent example on how to test a large API that keeps state between the calls.
Execute with:
```sh
cifuzz run state_fuzzer
```
* [Structure Aware Inputs Example](src/advanced_examples/explore_me.cpp#L8):
An example that shows how to fuzz an API that requires structured inputs, with the use of the FuzzedDataProvider helper class.
Execute with:
```sh
cifuzz run structured_input_checks_fuzz_test
```
* [Custom Mutator Example](src/advanced_examples/custom_mutator_example_checks_test.cpp#L37):
An example that shows how to utilize custom mutators to make sure the fuzzer only creates valid inputs.
Execute with:
```sh
cifuzz run custom_mutator_example_checks_fuzz_test
```
* [Slow Input Example](src/advanced_examples/slow_input_checks_test.cpp#L17):
An example that shows how the fuzzer can detect inputs that lead to a slow program execution.
Execute with:
```sh
cifuzz run slow_input_checks_fuzz_test
```


To execute all fuzz tests at the same time, or calculate the code coverage for all, just skip the fuzz target name. Like:
```sh
cifuzz run
```
or:
```sh
cifuzz coverage
```

To use the devcontainer environment you need to export your cifuzz download token to a environment var called "CIFUZZ_CREDENTIALS" like `export CIFUZZ_CREDENTIALS=[my_token]`.
