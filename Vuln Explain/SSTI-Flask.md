# SSTI Python Flask Explain 

### I. Python objects

Trong Python, tất cả mọi thứ đều được coi là Object, vì thế chúng sẽ có tính kế thừa, chúng ta sẽ sử dụng tính kế thừa này cho việc build payload, nhưng đầu tiên, chúng ta cần phải tìm hiểu sâu hơn về Object trong Python...

Ta xét các class sau:

```python
class Father:
    pass

class Mother:
    pass

class Son(Father, Mother):
    pass

class StepSon(Mother):
    pass
```

Ta có thể thấy class `Son` có kế thừa từ `Father` và `Mother`, class `StepSon` chỉ kế thừa từ `Mother`
Chúng ta sẽ xem xét một số khái niệm dưới đây:

#### 1. `__mro__`
MRO (Method Resolution Order) là khái niệm chỉ về thứ tự thừa kế của một Object
Ta xét ví dụ trên với đoạn code sau:

```python
print(f'Son: {Son.__mro__}')
print(f'StepSon: {StepSon.__mro__}')

'''
Son: (<class '__main__.Son'>, <class '__main__.Father'>, <class '__main__.Mother'>, <class 'object'>)
StepSon: (<class '__main__.StepSon'>, <class '__main__.Mother'>, <class 'object'>)
'''
```

Như vậy, `__mro__` trả về 1 tupple với thứ tự thừa kế từ con (bản thân Object) đến các cấp thừa kế cao hơn của nó (giống như đi ngược cây gia phả :))) )
Từ kết quả trên, ta sẽ đưa ra được thứ tự thừa kế từ thấp -> cao của `Son` như sau:
```
Son --> Father, Mother --> Object
```

Ngoài ra, `__mro__` cũng có thể gọi thành `mro()` 

#### 2. `__class__`
`__class__` trả về class mà Object thuộc về

```python
s = Son()
ss = StepSon()

print(f'Son: {s.__class__}')
print(f'StepSon: {ss.__class__}')

'''
Son: <class '__main__.Son'>
StepSon: <class '__main__.StepSon'>
'''
```

Thậm chí là cả function:

```python
print(f'Sum: {sum.__class__}')
#Sum: <class 'builtin_function_or_method'>
```

#### 3. `__base__` và `__bases__`
`__base__` trả về 1 class cha mà Object thừa kế, trong khi `__bases__` trả về tất cả:

```python
print(f'Son: {Son.__base__}')
print(f'StepSon: {StepSon.__base__}')

print(f'Son: {Son.__bases__}')
print(f'StepSon: {StepSon.__bases__}')

'''
Son: <class '__main__.Father'>
StepSon: <class '__main__.Mother'>

Son: (<class '__main__.Father'>, <class '__main__.Mother'>)
StepSon: (<class '__main__.Mother'>,)
'''
```

#### 4. `__subclasses__()`
`__subclasses__()` trả về các class con kế thừa từ class:

```python
print(f'Father: {Father.__subclasses__()}')
print(f'Mother: {Mother.__subclasses__()}')

'''
Father: [<class '__main__.Son'>]
Mother: [<class '__main__.Son'>, <class '__main__.StepSon'>]
'''
```

#### 5. `__globals__`
Hơi khó để giải thích nhưng ta có thể hiểu nó bằng đoạn code sau:

```python
from threading import Thread

def func():
	return 100

print(func.__globals__)

'''
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x000002BED8904700>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, '__file__': 'c:\\Users\\test\\TEMP\\oop.py', '__cached__': None, 'Thread': <class 'threading.Thread'>, 'func': <function func at 0x000002BED8843E20>}
'''
```

Có thể thấy, `__globals__` trả về 1 dictionary với key là namespace của object và value là địa chỉ của object tại nơi mà `func` được define (chứ không phải nơi `func` được gọi)

#### 6. `__builtins__`
