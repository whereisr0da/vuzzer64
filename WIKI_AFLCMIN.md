# ALF-CMIN Input Reduction Wiki

An input list has a code coverage scope, Vuzzer use a home-made function to take the best inputs with best coverage. The idea is to implement a plugin, AFL-CMIN for another fuzzer called AFL, that handle this function very well to improve the input selection.

AFL-CMIN reduction is a good thing use because it can highly reduce the input count to test, by selecting only relevant inputs. It could make Vuzzer faster on its way of launching test. 

I decided to implement this as an option, and split the reduction in two parts, standard inputs generation reduction (parent input) and child inputs reduction. Note that this reduction is only applied on inputs created from generation (inputs kept from other generation are not reduced).

![http://url/to/img.png](https://i.imgur.com/7sXiVGY.png)

## How to use ?

First you have to set the path of AFL-CMIN in the configuration file (config.py)

```python
ALFCMINEXECUTABLEPATH = '/path/to/afl-cmin/afl/afl-cmin'
```
After you can turn on the input reduction on the normal input generation
```python
ALFINPUTREDUCTION = True
```
Or you can turn on the input reduction on the child input generation
```python
ALFCHILDINPUTREDUCTION = True
```