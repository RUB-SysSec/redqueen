# fastrand
Fast random number generation in Python using PCG

Blog post: [Ranged random-number generation is slow in Python…](https://lemire.me/blog/2016/03/21/ranged-random-number-generation-is-slow-in-python/)


If you have Linux, macOS or Windows (Python 3.6 and 3.7, 64-bit), you should be able to do just pip install...

```
pip install fastrand
```

You may need root access (sudo on macOS and Linux).



Generally, you can build the library as follows (if you have root):


```bash
python setup.py build
python setup.py install 
```

or

```bash
python setup.py build
python setup.py install --home=$HOME
export PYTHONPATH=$PYTHONPATH:~/lib/python
```



Usage... (don't forget to type the above lines in your shell!)

```python
import fastrand

print("generate an integer in [0,1001)")
fastrand.pcg32bounded(1001) 
print("Generate a random 32-bit integer.")
fastrand.pcg32()
```

It is nearly an order of magnitude faster than the alternatives:

```
python -m timeit -s 'import fastrand' 'fastrand.pcg32bounded(1001)'
10000000 loops, best of 3: 0.0602 usec per loop
python -m timeit -s 'import random' 'random.randint(0,1000)'
1000000 loops, best of 3: 0.698 usec per loop
python -m timeit -s 'import numpy' 'numpy.random.randint(0, 1000)'
1000000 loops, best of 3: 0.795 usec per loop
```

## future work

Also look at https://github.com/rkern/line_profiler

## Reference

* http://www.pcg-random.org
* Daniel Lemire, [Fast Random Integer Generation in an Interval](https://arxiv.org/abs/1805.10941), ACM Transactions on Modeling and Computer Simulation (to appear)
