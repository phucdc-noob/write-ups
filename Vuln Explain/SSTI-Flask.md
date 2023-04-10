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

#### 6. `__builtins__` (```builtins()```)

Xét đoạn code sau:

```python
import re

print(re.__builtins__)

'''
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x000002BED8904700>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, '__file__': 'c:\\Users\\phucdc1\\Desktop\\TEMP\\oop.py', '__cached__': None, 'Thread': <class 'threading.Thread'>, 'func': <function func at 0x000002BED8843E20>}
PS C:\Users\phucdc1\Desktop\TEMP> & C:/Users/phucdc1/AppData/Local/Programs/Python/Python310/python.exe c:/Users/phucdc1/Desktop/TEMP/oop.py
{'__name__': 'builtins', '__doc__': "Built-in functions, exceptions, and other objects.\n\nNoteworthy: None is the `nil' object; Ellipsis represents `...' in slices.", '__package__': '', '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': ModuleSpec(name='builtins', loader=<class '_frozen_importlib.BuiltinImporter'>, origin='built-in'), '__build_class__': <built-in function __build_class__>, '__import__': <built-in function __import__>, 'abs': <built-in function abs>, 'all': <built-in function all>, 'any': <built-in function any>, 'ascii': <built-in function ascii>, 'bin': <built-in function bin>, 'breakpoint': <built-in function breakpoint>, 'callable': <built-in function callable>, 'chr': <built-in function chr>, 'compile': <built-in function compile>, 'delattr': <built-in function delattr>, 'dir': <built-in function dir>, 'divmod': <built-in function divmod>, 'eval': <built-in function eval>, 'exec': <built-in function 
exec>, 'format': <built-in function format>, 'getattr': <built-in function getattr>, 'globals': <built-in function globals>, 'hasattr': <built-in function hasattr>, 'hash': <built-in function hash>, 'hex': <built-in function hex>, 'id': <built-in function id>, 'input': <built-in function input>, 'isinstance': <built-in function isinstance>, 'issubclass': <built-in function issubclass>, 'iter': <built-in function iter>, 'aiter': <built-in function aiter>, 'len': <built-in function len>, 'locals': <built-in function locals>, 'max': <built-in function max>, 'min': <built-in function min>, 'next': <built-in function next>, 'anext': <built-in function anext>, 'oct': <built-in function oct>, 'ord': <built-in function ord>, 'pow': <built-in function pow>, 'print': <built-in function print>, 'repr': <built-in function repr>, 'round': <built-in function round>, 'setattr': <built-in function setattr>, 'sorted': <built-in function sorted>, 'sum': <built-in function sum>, 'vars': <built-in function vars>, 'None': None, 'Ellipsis': Ellipsis, 'NotImplemented': NotImplemented, 'False': False, 'True': True, 'bool': <class 'bool'>, 'memoryview': <class 'memoryview'>, 'bytearray': <class 'bytearray'>, 'bytes': <class 'bytes'>, 'classmethod': <class 'classmethod'>, 'complex': <class 'complex'>, 'dict': <class 'dict'>, 'enumerate': <class 'enumerate'>, 'filter': <class 'filter'>, 'float': <class 'float'>, 'frozenset': <class 'frozenset'>, 'property': <class 'property'>, 'int': <class 'int'>, 'list': <class 'list'>, 'map': 
<class 'map'>, 'object': <class 'object'>, 'range': <class 'range'>, 'reversed': <class 'reversed'>, 'set': <class 'set'>, 'slice': <class 'slice'>, 'staticmethod': <class 'staticmethod'>, 'str': <class 'str'>, 'super': <class 'super'>, 'tuple': <class 'tuple'>, 'type': <class 'type'>, 'zip': <class 'zip'>, '__debug__': True, 'BaseException': <class 'BaseException'>, 'Exception': <class 'Exception'>, 'TypeError': <class 'TypeError'>, 'StopAsyncIteration': <class 'StopAsyncIteration'>, 'StopIteration': <class 'StopIteration'>, 'GeneratorExit': <class 'GeneratorExit'>, 'SystemExit': <class 'SystemExit'>, 'KeyboardInterrupt': <class 'KeyboardInterrupt'>, 'ImportError': <class 'ImportError'>, 'ModuleNotFoundError': <class 'ModuleNotFoundError'>, 'OSError': <class 'OSError'>, 'EnvironmentError': <class 'OSError'>, 'IOError': <class 'OSError'>, 'WindowsError': <class 'OSError'>, 'EOFError': <class 'EOFError'>, 'RuntimeError': <class 'RuntimeError'>, 'RecursionError': <class 'RecursionError'>, 'NotImplementedError': <class 'NotImplementedError'>, 'NameError': <class 'NameError'>, 'UnboundLocalError': <class 'UnboundLocalError'>, 'AttributeError': <class 'AttributeError'>, 'SyntaxError': <class 'SyntaxError'>, 'IndentationError': <class 'IndentationError'>, 'TabError': <class 'TabError'>, 'LookupError': <class 'LookupError'>, 'IndexError': <class 'IndexError'>, 'KeyError': <class 'KeyError'>, 'ValueError': <class 'ValueError'>, 'UnicodeError': <class 'UnicodeError'>, 'UnicodeEncodeError': <class 'UnicodeEncodeError'>, 'UnicodeDecodeError': <class 'UnicodeDecodeError'>, 'UnicodeTranslateError': <class 'UnicodeTranslateError'>, 'AssertionError': <class 'AssertionError'>, 'ArithmeticError': <class 'ArithmeticError'>, 'FloatingPointError': <class 'FloatingPointError'>, 'OverflowError': <class 'OverflowError'>, 'ZeroDivisionError': <class 'ZeroDivisionError'>, 'SystemError': <class 'SystemError'>, 'ReferenceError': <class 'ReferenceError'>, 'MemoryError': <class 'MemoryError'>, 'BufferError': <class 'BufferError'>, 'Warning': <class 'Warning'>, 'UserWarning': <class 'UserWarning'>, 'EncodingWarning': <class 'EncodingWarning'>, 'DeprecationWarning': <class 'DeprecationWarning'>, 'PendingDeprecationWarning': <class 'PendingDeprecationWarning'>, 'SyntaxWarning': <class 'SyntaxWarning'>, 'RuntimeWarning': <class 'RuntimeWarning'>, 'FutureWarning': <class 'FutureWarning'>, 'ImportWarning': <class 'ImportWarning'>, 'UnicodeWarning': <class 'UnicodeWarning'>, 'BytesWarning': <class 'BytesWarning'>, 'ResourceWarning': <class 'ResourceWarning'>, 'ConnectionError': <class 'ConnectionError'>, 'BlockingIOError': <class 'BlockingIOError'>, 'BrokenPipeError': <class 'BrokenPipeError'>, 'ChildProcessError': <class 'ChildProcessError'>, 'ConnectionAbortedError': <class 'ConnectionAbortedError'>, 'ConnectionRefusedError': <class 'ConnectionRefusedError'>, 'ConnectionResetError': <class 'ConnectionResetError'>, 'FileExistsError': <class 'FileExistsError'>, 'FileNotFoundError': <class 'FileNotFoundError'>, 'IsADirectoryError': <class 'IsADirectoryError'>, 'NotADirectoryError': <class 'NotADirectoryError'>, 'InterruptedError': <class 'InterruptedError'>, 'PermissionError': <class 'PermissionError'>, 'ProcessLookupError': <class 'ProcessLookupError'>, 'TimeoutError': <class 'TimeoutError'>, 'open': <built-in function open>, 'quit': Use quit() or Ctrl-Z plus Return to exit, 'exit': Use exit() or Ctrl-Z plus Return to exit, 'copyright': Copyright (c) 2001-2022 Python Software Foundation.
All Rights Reserved.

Copyright (c) 2000 BeOpen.com.
All Rights Reserved.

Copyright (c) 1995-2001 Corporation for National Research Initiatives.
All Rights Reserved.

Copyright (c) 1991-1995 Stichting Mathematisch Centrum, Amsterdam.
All Rights Reserved., 'credits':     Thanks to CWI, CNRI, BeOpen.com, Zope Corporation and a cast of thousands
    for supporting Python development.  See www.python.org for more information., 'license': Type license() to see the full license text, 'help': Type help() for interactive help, or help(object) for help about object.}
'''
```

`__builtins__` trả về một dictionary với key-value giống `__globals__`, nhưng mà là của các built-in functions như `sum`, `map`, ...

`__builtins__` có thể đi cùng với `__globals__` trong một số trường hợp như dưới đây:

```python
print(globals()['__builtins__'])

'''
<module 'builtins' (built-in)>
'''
```

Như vậy, ta đã tìm hiểu sơ qua về các Object phổ biến trong Python, giờ chúng ta sẽ sử dụng những Object này để thực hiện vấn đề ban đầu

### II. From objects to a freaking hole?

Ta sẽ sử dụng ví dụ sau:

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/")
def home():
    if request.args.get('c'):
        return render_template_string(request.args.get('c'))
    else:
        return "<h3>Param 'c' is required!!!</h3>"

if __name__ == "__main__":
    app.run()
```

Có thể thấy, ta có thể SSTI thông qua param `c`, cùng test thử nhé? Tôi đã viết 1 cái script nho nhỏ để gửi payload cho nhanh :)))

![image](https://user-images.githubusercontent.com/82533607/230844291-c4d5638e-d500-44ff-befc-40048b9a8797.png)

Ta sẽ bắt đầu bằng:

![image](https://user-images.githubusercontent.com/82533607/230846140-81349312-019e-4e16-9fc2-db9278e56d73.png)

Tiếp tục với `__base__`:

