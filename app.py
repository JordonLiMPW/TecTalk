from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# 定义主页路由
@app.route('/')
def home():
    return render_template('index.html')

# 定义登录页面路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # 在这里处理登录逻辑
        username = request.form['username']
        password = request.form['password']
        # 此处可添加用户认证逻辑
        return redirect(url_for('home'))
    return render_template('login.html')

# 定义注册页面路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        if password != confirm_password:
            error_message = "Password does not match"
            return render_template('register.html', error_message=error_message)
        else:
            # 注册成功后重定向到登录页面
            return redirect(url_for('login'))

    return render_template('register.html')


if __name__ == '__main__':
    app.run(debug=True)
