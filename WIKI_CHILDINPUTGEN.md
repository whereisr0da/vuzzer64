# Conflict Handling Wiki

## What is a conflict ?

To explain what is a conflict and how handle it, I made a short scenario and schemas to represent how mutation works.

Context, here we have an input that will be used to apply 2 mutations.

The gray part represents the input split into parts (bytes) with, for each of them, its position (offset) in the input. The green part is the mutation 1 with a size of 2 bytes, applied on the input at the offset 2. 

![https://i.imgur.com/G95MStJ.png](https://i.imgur.com/G95MStJ.png)

Now come the mutation 2 in amber, with a size of 4 and applied on the offset 3. But there is a problem, the mutation 1 already wrote the part of the input from offset 3 to 4, so here it’s a conflict (marked with red).

![https://i.imgur.com/0PglRYv.png](https://i.imgur.com/0PglRYv.png)

## Child input algorithm 

This is a strategy I created to handle conflicts, it uses the idea of splitting the input into two pieces. By keeping an input without applying the mutation that does the conflict (the parent), and create an input that contains the conflicted mutation (child input).

And each time a mutation is performed on the parent input, each child will try to perform the same mutation. With that, Vuzzer could test a large number of inputs that could cover a lot of mutation possibilities. 

Here is a schema I made to illustrate my strategy :

![https://i.imgur.com/0DpbIjS.png](https://i.imgur.com/0DpbIjS.png)

The schema illustrates the evolution of an input (parent) and, how it handled conflicts during the modifications of 3 mutations.
Like above, grey blocks are inputs, green segments are mutations already applied, yellow one’s are new mutations currently being applied, and the red ones are the conflicts between already applied mutations and currently applied ones.
The orange path represents the parent input during each mutation, and the blue one represents the evolution of each child input.

First in the mutation 1, there is a conflict, so the parent input will not have the conflicted mutation applied on it. And a child input will be created, with the already applied mutations, but without the one that was in conflict with mutation 1. And instead of that one, the mutation 1 is applied.

So now, there is a child input that takes care of this special conflict case and the original input, without overriding any data.
In part 2, the mutation 2 will successfully be applied to the parent input without conflicts. So, no child will be created, but at the same time, the mutation 2 will be tested on the child created in mutation 1. And here there is a conflict, so the child input will create a new child like above with the parent input.

And in part 3, this time the parent input will not receive the mutation 3 because, there is a conflict. So, a new child input will be created, and the mutation 3 will be tested on each children already created. But in this case, the child input created by the parent input already exists in the children list, so it is not added to the list.  

## Issues of this algorithm

This algorithm can create a decent count of child input very quickly, its complexity (if there is conflict and child input created) is about log(x). Without a limit, for 500 input, Vuzzer will generate about ~500 000 child inputs (I stopped before my vm crashes), so I added an option to limit the child input population (CHILDINPUTMAXSIZE).

Theoretically, child input will always be different, but if one day, a parent input has the same comparisons on each knowledge loop. Theoretically the first 500 child inputs will be the same (500 is the limit of child input). Because each comparison leads to a mutation and possibly a conflict. So if the mutation offset is always the same, we create the same child input in the child limit range. To avoid this, I made an option that controls the creation probability of child inputs. If sometimes, a child input is not created due to this random probability, the 500 generated children will not only be the first 500 child possibilities (see complexity above).

## How to use ?

First you have to enable this variable in the configuration file (config.py)

```python
HEAVYCHILDINPUTCREATION = True
```    

Next, you have to set the maximun child input population

```python
# NOTE : lower the POPSIZE is, lower the chance that this number is reached is
# NOTE : tests shows that 500 is the good number

CHILDINPUTMAXSIZE = 500
```  

Finally, you have to set the child input creation randomness (see above)

```python
# NOTE : 1.0 = all inputs are passed
# NOTE : if you use ALFCHILDINPUTREDUCTION, this should be set to 1.0

CHILDINPUTCREATIONRANDOMNESS = 0.7
```
